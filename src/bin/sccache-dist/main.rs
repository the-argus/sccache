#[macro_use]
extern crate log;

use anyhow::{Context, Result, bail};
use base64::Engine;
use memory_history::MemoryMeasurements;
use rand::{RngCore, rngs::OsRng};
use sccache::config::{
    INSECURE_DIST_CLIENT_TOKEN, scheduler as scheduler_config, server as server_config,
};
use sccache::dist::{
    self, AllocJobResult, AssignJobResult, BuildResult, BuilderIncoming, BuilderInfo, CommandHash,
    CompileCommand, HeartbeatServerResult, InputsReader, JobAlloc, JobAuthorizer, JobComplete,
    JobId, JobState, RunJobResult, SchedulerIncoming, SchedulerOutgoing, SchedulerStatusResult,
    ServerId, ServerIncoming, ServerNonce, ServerOutgoing, ServerStatus, SubmitToolchainResult,
    TcCache, Toolchain, ToolchainReader, UpdateJobStateResult,
};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use sccache::util::daemonize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, btree_map};
use std::env;
use std::io;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg_attr(target_os = "freebsd", path = "build_freebsd.rs")]
mod build;

mod cmdline;
mod cpu_speed;
mod memory_history;
#[cfg(target_os = "linux")]
mod peak_memory;
mod token_check;

use cmdline::{AuthSubcommand, Command};

pub const INSECURE_DIST_SERVER_TOKEN: &str = "dangerously_insecure_server";

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
)))]
fn main() {
    compile_error!("Distributed compilation is only supported on Linux/x86_64 and FreeBSD!");
}

// Only supported on x86_64 Linux machines and on FreeBSD
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
))]
fn main() {
    init_logging();

    let incr_env_strs = ["CARGO_BUILD_INCREMENTAL", "CARGO_INCREMENTAL"];
    incr_env_strs
        .iter()
        .for_each(|incr_str| match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!(
                    "sccache: incremental compilation is prohibited: Unset {} to continue.",
                    incr_str
                );
                std::process::exit(1);
            }
            _ => (),
        });

    let command = match cmdline::try_parse_from(env::args()) {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache-dist: {some_other_err}");
                for source_err in some_other_err.chain().skip(1) {
                    println!("sccache-dist: caused by: {source_err}");
                }
                std::process::exit(1);
            }
        },
    };

    std::process::exit(match run(command) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sccache-dist: error: {}", e);

            for e in e.chain().skip(1) {
                eprintln!("sccache-dist: caused by: {}", e);
            }
            2
        }
    });
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id.addr(), auth_token)
}
fn check_server_token(server_token: &str, auth_token: &str) -> Option<ServerId> {
    let mut split = server_token.splitn(2, ' ');
    let server_addr = split.next().and_then(|addr| addr.parse().ok())?;
    match split.next() {
        Some(t) if t == auth_token => Some(ServerId::new(server_addr)),
        Some(_) | None => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerJwt {
    exp: u64,
    server_id: ServerId,
}
fn create_jwt_server_token(
    server_id: ServerId,
    header: &jwt::Header,
    key: &[u8],
) -> Result<String> {
    let key = jwt::EncodingKey::from_secret(key);
    jwt::encode(header, &ServerJwt { exp: 0, server_id }, &key).map_err(Into::into)
}
fn dangerous_insecure_extract_jwt_server_token(server_token: &str) -> Result<ServerId> {
    let validation = {
        let mut validation = jwt::Validation::default();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.insecure_disable_signature_validation();
        validation
    };
    let dummy_key = jwt::DecodingKey::from_secret(b"secret");
    jwt::decode::<ServerJwt>(server_token, &dummy_key, &validation)
        .map(|res| res.claims.server_id)
        .map_err(Into::into)
}
fn check_jwt_server_token(
    server_token: &str,
    key: &[u8],
    validation: &jwt::Validation,
) -> Option<ServerId> {
    let key = jwt::DecodingKey::from_secret(key);
    jwt::decode::<ServerJwt>(server_token, &key, validation)
        .map(|res| res.claims.server_id)
        .ok()
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Auth(AuthSubcommand::Base64 { num_bytes }) => {
            let mut bytes = vec![0; num_bytes];
            OsRng.fill_bytes(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", BASE64_URL_SAFE_ENGINE.encode(bytes));
            Ok(0)
        }
        Command::Auth(AuthSubcommand::JwtHS256ServerToken {
            secret_key,
            server_id,
        }) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = BASE64_URL_SAFE_ENGINE.decode(secret_key)?;
            let token = create_jwt_server_token(server_id, &header, &secret_key)
                .context("Failed to create server token")?;
            println!("{}", token);
            Ok(0)
        }

        Command::Scheduler(scheduler_config::Config {
            public_addr,
            client_auth,
            server_auth,
            memory_history_path,
            memory_history_max_entries,
        }) => {
            let check_client_auth: Box<dyn dist::http::ClientAuthCheck> = match client_auth {
                scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
                    INSECURE_DIST_CLIENT_TOKEN.to_owned(),
                )),
                scheduler_config::ClientAuth::Token { token } => {
                    Box::new(token_check::EqCheck::new(token))
                }
                scheduler_config::ClientAuth::JwtValidate {
                    audience,
                    issuer,
                    jwks_url,
                } => Box::new(
                    token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                        .context("Failed to create a checker for valid JWTs")?,
                ),
                scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => Box::new(
                    token_check::ProxyTokenCheck::new(url, cache_secs)
                        .context("failed to create proxy token checker")?,
                ),
            };

            let check_server_auth: dist::http::ServerAuthCheck = match server_auth {
                scheduler_config::ServerAuth::Insecure => {
                    warn!("Scheduler starting with DANGEROUSLY_INSECURE server authentication");
                    let token = INSECURE_DIST_SERVER_TOKEN;
                    Box::new(move |server_token| check_server_token(server_token, token))
                }
                scheduler_config::ServerAuth::Token { token } => {
                    Box::new(move |server_token| check_server_token(server_token, &token))
                }
                scheduler_config::ServerAuth::JwtHS256 { secret_key } => {
                    let secret_key = BASE64_URL_SAFE_ENGINE
                        .decode(secret_key)
                        .context("Secret key base64 invalid")?;
                    if secret_key.len() != 256 / 8 {
                        bail!("Size of secret key incorrect")
                    }
                    let validation = {
                        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
                        validation.leeway = 0;
                        validation.validate_exp = false;
                        validation.validate_nbf = false;
                        validation
                    };
                    Box::new(move |server_token| {
                        check_jwt_server_token(server_token, &secret_key, &validation)
                    })
                }
            };

            let memory_measurements =
                memory_history::load_history(&memory_history_path, memory_history_max_entries);

            daemonize(&[])?;
            let scheduler = Scheduler::new(memory_measurements);
            memory_history::start_saving_history(
                scheduler.memory_measurements.clone(),
                memory_history_path,
            );
            let http_scheduler = dist::http::Scheduler::new(
                public_addr,
                scheduler,
                check_client_auth,
                check_server_auth,
            );
            http_scheduler.start()?;
            unreachable!();
        }

        Command::Server(config) => {
            let server_config::Config {
                builder,
                cache_dir,
                public_addr,
                bind_address,
                scheduler_url,
                scheduler_auth,
                toolchain_cache_size,
                name,
                max_jobs,
                max_memory,
                dist_control_address,
                cpu_speed,
            } = *config;
            let name = match name {
                Some(name) => name,
                None => hostname::get()
                    .context("Failed to get the hostname to use as the server name")?
                    .to_string_lossy()
                    .into_owned(),
            };

            let builder: Box<dyn dist::BuilderIncoming> = match builder {
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Docker => {
                    Box::new(build::DockerBuilder::new().context("Docker builder failed to start")?)
                }
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Overlay {
                    bwrap_path,
                    build_dir,
                } => Box::new(
                    build::OverlayBuilder::new(bwrap_path, build_dir)
                        .context("Overlay builder failed to start")?,
                ),
                #[cfg(target_os = "freebsd")]
                server_config::BuilderType::Pot {
                    pot_fs_root,
                    clone_from,
                    pot_cmd,
                    pot_clone_args,
                } => Box::new(
                    build::PotBuilder::new(pot_fs_root, clone_from, pot_cmd, pot_clone_args)
                        .context("Pot builder failed to start")?,
                ),
                _ => bail!(
                    "Builder type `{}` not supported on this platform",
                    format!("{:?}", builder)
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                ),
            };

            let server_id = ServerId::new(public_addr);
            let scheduler_auth = match scheduler_auth {
                server_config::SchedulerAuth::Insecure => {
                    warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_server_token(server_id, INSECURE_DIST_SERVER_TOKEN)
                }
                server_config::SchedulerAuth::Token { token } => {
                    create_server_token(server_id, &token)
                }
                server_config::SchedulerAuth::JwtToken { token } => {
                    let token_server_id: ServerId =
                        dangerous_insecure_extract_jwt_server_token(&token)
                            .context("Could not decode scheduler auth jwt")?;
                    if token_server_id != server_id {
                        bail!(
                            "JWT server id ({:?}) did not match configured server id ({:?})",
                            token_server_id,
                            server_id
                        )
                    }
                    token
                }
            };

            let server = Server::new(builder, &cache_dir, toolchain_cache_size)
                .context("Failed to create sccache server instance")?;
            let http_server = dist::http::Server::new(
                public_addr,
                bind_address,
                scheduler_url.to_url(),
                scheduler_auth,
                dist::http::BuilderIdentity {
                    name,
                    configured_cpu_speed: cpu_speed.map(NonZeroU32::get),
                },
                max_jobs,
                max_memory,
                dist_control_address,
                server,
            )
            .context("Failed to create sccache HTTP server instance")?;
            http_server.start()?;
            unreachable!();
        }
    }
}

fn init_logging() {
    if env::var(sccache::LOGGING_ENV).is_ok() {
        let mut builder = env_logger::Builder::from_env(sccache::LOGGING_ENV);

        // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set
        if env::var("SCCACHE_LOG_MILLIS").is_ok() {
            builder.format_timestamp_millis();
        }

        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}

const SERVER_REMEMBER_ERROR_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(60);

struct JobDetail {
    server_id: ServerId,
    state: JobState,
    assigned_at: Instant,
    command_hash: CommandHash,
    client_name: String,
}

// To avoid deadlicking, make sure to do all locking at once (i.e. no further locking in a downward scope),
// in alphabetical order
pub struct Scheduler {
    // Build servers may survive a scheduler restart and retain pending job IDs.
    // Start each scheduler instance in a different ID range so a restarted
    // scheduler does not immediately reuse IDs still known to surviving servers.
    job_id_base: u64,
    job_count: AtomicUsize,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,

    // another thread sees job results and saves them here
    memory_measurements: Arc<Mutex<MemoryMeasurements>>,

    servers: Mutex<HashMap<ServerId, ServerDetails>>,
}

struct ServerDetails {
    last_seen: Instant,
    last_error: Option<Instant>,
    info: BuilderInfo,
    server_nonce: ServerNonce,
    job_authorizer: Box<dyn JobAuthorizer>,
}

impl Scheduler {
    pub fn new(memory_measurements: MemoryMeasurements) -> Self {
        Self::with_job_id_base(OsRng.next_u64(), memory_measurements)
    }

    fn with_job_id_base(job_id_base: u64, memory_measurements: MemoryMeasurements) -> Self {
        Scheduler {
            job_id_base,
            job_count: AtomicUsize::new(0),
            jobs: Mutex::new(BTreeMap::new()),
            memory_measurements: Arc::new(Mutex::new(memory_measurements)),
            servers: Mutex::new(HashMap::new()),
        }
    }

    fn next_job_id(&self) -> JobId {
        let job_count = self.job_count.fetch_add(1, Ordering::SeqCst) as u64;
        JobId(self.job_id_base.wrapping_add(job_count))
    }

    fn prune_servers(
        &self,
        servers: &mut MutexGuard<HashMap<ServerId, ServerDetails>>,
        jobs: &mut MutexGuard<BTreeMap<JobId, JobDetail>>,
    ) {
        let now = Instant::now();

        let mut dead_servers = Vec::new();

        for (&server_id, details) in servers.iter_mut() {
            if now.duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                dead_servers.push(server_id);
            }
        }

        for server_id in dead_servers {
            warn!(
                "Server {} appears to be dead, pruning it in the scheduler",
                server_id.addr()
            );
            servers
                .remove(&server_id)
                .expect("server went missing from map");
            jobs.retain(|job_id, job| {
                let on_dead_server = job.server_id == server_id;
                if on_dead_server {
                    warn!(
                        "Non-terminated job {} was cleaned up in server pruning",
                        job_id
                    );
                }
                !on_dead_server
            });
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new(MemoryMeasurements::new(
            scheduler_config::default_memory_history_max_entries(),
        ))
    }
}

fn jobs_on(
    server_id: ServerId,
    jobs: &BTreeMap<JobId, JobDetail>,
) -> impl Iterator<Item = (&JobId, &JobDetail)> {
    jobs.iter()
        .filter(move |(_, job)| job.server_id == server_id)
}

// Note that for this function, the inputs include all jobs, so this estimate
// has to be recomputed for any job any time any other jobs is completed or
// cancelled
fn estimated_memory_of_jobs_on(
    server_id: ServerId,
    jobs: &BTreeMap<JobId, JobDetail>,
    memory_measurements: &MemoryMeasurements,
) -> u64 {
    jobs_on(server_id, jobs)
        .map(|(_, job)| memory_measurements.estimate(&job.command_hash, &job.client_name))
        .fold(0, u64::saturating_add)
}

// ranking for the relative performance of a build server.
// This is ranked by estimated speed * (1 - 0.5 * jobs_assigned / max_jobs),
// which is stolen from icecream
struct Ranking {
    cpu_speed: Option<u32>, // general speed score from database
    jobs_assigned: usize,
    max_jobs: usize,
}

impl Ranking {
    // Mix all values into one score weighted by importance
    fn scaled_score(&self, other_max_jobs: usize) -> u128 {
        let speed = u128::from(self.cpu_speed.unwrap_or(0));
        let free = (2 * self.max_jobs as u128).saturating_sub(self.jobs_assigned as u128);
        speed
            .saturating_mul(free)
            .saturating_mul(other_max_jobs as u128)
    }

    fn is_better_than(&self, other: &Ranking) -> bool {
        let score = self.scaled_score(other.max_jobs);
        let other_score = other.scaled_score(self.max_jobs);
        let load = self.jobs_assigned as u128 * other.max_jobs as u128;
        let other_load = other.jobs_assigned as u128 * self.max_jobs as u128;
        score > other_score || (score == other_score && load < other_load)
    }
}

fn servers_named(servers: &HashMap<ServerId, ServerDetails>, name: &str) -> Vec<ServerId> {
    servers
        .iter()
        .filter(|(_, details)| details.info.name == name)
        .map(|(&server_id, _)| server_id)
        .collect()
}

impl SchedulerIncoming for Scheduler {
    fn handle_alloc_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        tc: Toolchain,
        command_hash: CommandHash,
        client_name: String,
    ) -> Result<AllocJobResult> {
        if client_name.is_empty() {
            bail!("Empty client name specified in job allocation")
        }
        let (job_id, server_id, auth) = {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();
            let memory_measurements = self.memory_measurements.lock().unwrap();
            let mut servers = self.servers.lock().unwrap();

            let estimated_peak_memory = memory_measurements.estimate(&command_hash, &client_name);
            let res = {
                let now = Instant::now();
                let mut best: Option<(ServerId, Ranking)> = None;
                let mut best_err: Option<(ServerId, Instant)> = None;
                for (&server_id, details) in servers.iter_mut() {
                    let num_jobs_assigned = jobs_on(server_id, &jobs).count();
                    let max_jobs = details.info.limits.max_jobs;
                    if num_jobs_assigned >= max_jobs {
                        continue;
                    }
                    if let Some(max_memory) = details.info.limits.max_memory {
                        let estimated_memory_of_assigned_jobs =
                            estimated_memory_of_jobs_on(server_id, &jobs, &memory_measurements);
                        if estimated_memory_of_assigned_jobs.saturating_add(estimated_peak_memory)
                            > max_memory
                        {
                            continue;
                        }
                    }

                    if let Some(last_error) = details.last_error {
                        if now.duration_since(last_error) > SERVER_REMEMBER_ERROR_TIMEOUT {
                            details.last_error = None;
                        }
                        if best_err.is_none_or(|(_, best_last_err)| last_error < best_last_err) {
                            trace!(
                                "Selected {:?}, its most recent error is {:?} ago",
                                server_id,
                                now - last_error
                            );
                            best_err = Some((server_id, last_error));
                        }
                    } else {
                        let ranking = Ranking {
                            cpu_speed: cpu_speed::cpu_speed_of_builder(&details.info).speed(),
                            jobs_assigned: num_jobs_assigned,
                            max_jobs,
                        };
                        if best
                            .as_ref()
                            .is_none_or(|(_, best_ranking)| ranking.is_better_than(best_ranking))
                        {
                            trace!("Selected {:?} as the best ranked server", server_id);
                            best = Some((server_id, ranking));
                        }
                    }
                }

                // Assign the job to our best choice
                if let Some(server_id) = best
                    .map(|(server_id, _)| server_id)
                    .or(best_err.map(|(server_id, _)| server_id))
                {
                    let server_details = servers
                        .get_mut(&server_id)
                        .expect("selected server not found in map");
                    let job_id = self.next_job_id();
                    let auth = server_details
                        .job_authorizer
                        .generate_token(job_id)
                        .context("Could not create an auth token for this job")?;
                    assert!(
                        jobs.insert(
                            job_id,
                            JobDetail {
                                server_id,
                                state: JobState::Pending,
                                assigned_at: Instant::now(),
                                command_hash,
                                client_name,
                            }
                        )
                        .is_none()
                    );

                    info!(
                        "Job {} with an estimated peak memory of {} bytes was created and will be assigned to server {:?} ",
                        job_id, estimated_peak_memory, server_id,
                    );
                    Some((job_id, server_id, auth))
                } else {
                    None
                }
            };

            if let Some(res) = res {
                res
            } else {
                let fits_on_no_server = !servers.is_empty()
                    && servers.values().all(|details| {
                        details
                            .info
                            .limits
                            .max_memory
                            .is_some_and(|max_memory| estimated_peak_memory > max_memory)
                    });
                let message = if fits_on_no_server {
                    let message = format!(
                        "Job needs an estimated {} bytes of memory, which exceeds the max memory of all {} servers",
                        estimated_peak_memory,
                        servers.len()
                    );
                    warn!("{}", message);
                    message
                } else {
                    format!(
                        "Insufficient capacity across {} available servers",
                        servers.len()
                    )
                };
                return Ok(AllocJobResult::Fail { msg: message });
            }
        };
        let AssignJobResult {
            state,
            need_toolchain,
        } = requester
            .do_assign_job(server_id, job_id, tc, auth.clone())
            .with_context(|| {
                // LOCKS
                let mut jobs = self.jobs.lock().unwrap();
                let mut servers = self.servers.lock().unwrap();
                let job_was_known = jobs.remove(&job_id).is_some();
                if let Some(entry) = servers.get_mut(&server_id) {
                    entry.last_error = Some(Instant::now());
                    if !job_was_known {
                        "assign job failed and job not known to the server"
                    } else {
                        "assign job failed, job un-assigned from the server"
                    }
                } else {
                    "assign job failed and server not known"
                }
            })?;
        {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();

            // update job state with the result from our assignment attempt above
            match jobs.get_mut(&job_id) {
                Some(job_detail) => job_detail.state = state,
                None => {
                    let msg = format!(
                        "Job {} assignment was cleaned up before allocation completed",
                        job_id
                    );
                    warn!("{}", msg);
                    return Ok(AllocJobResult::Fail { msg });
                }
            }

            info!(
                "Job {} successfully assigned and saved with state {:?}",
                job_id, state
            );
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            server_id,
        };
        Ok(AllocJobResult::Success {
            job_alloc,
            need_toolchain,
        })
    }

    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        info: BuilderInfo,
        job_authorizer: Box<dyn JobAuthorizer>,
    ) -> Result<HeartbeatServerResult> {
        if info.num_cpus == 0 {
            bail!("Invalid number of CPUs (0) specified in heartbeat")
        }
        if info.name.is_empty() {
            bail!("Empty server name specified in heartbeat")
        }

        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        match servers.get_mut(&server_id) {
            Some(ref mut details) if details.server_nonce == server_nonce => {
                let now = Instant::now();
                details.last_seen = now;
                details.info = info;

                let stale_jobs: Vec<JobId> = jobs_on(server_id, &jobs)
                    .filter(|(_, job)| {
                        let unclaimed_for = now.duration_since(job.assigned_at);
                        match job.state {
                            JobState::Ready => unclaimed_for >= UNCLAIMED_READY_TIMEOUT,
                            JobState::Pending => unclaimed_for > UNCLAIMED_PENDING_TIMEOUT,
                            _ => false,
                        }
                    })
                    .map(|(&job_id, _)| job_id)
                    .collect();

                if !stale_jobs.is_empty() {
                    warn!(
                        "The following stale jobs will be de-allocated: {:?}",
                        stale_jobs
                    );

                    for job_id in stale_jobs {
                        jobs.remove(&job_id);
                    }
                }

                return Ok(HeartbeatServerResult { is_new: false });
            }
            Some(ref mut details) if details.server_nonce != server_nonce => {
                jobs.retain(|_, job| job.server_id != server_id);
            }
            _ => (),
        }
        info!(
            "Registered new server {:?} named {:?}",
            server_id, info.name
        );
        let name = info.name.clone();
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error: None,
                info,
                server_nonce,
                job_authorizer,
            },
        );
        let same_name = servers_named(&servers, &name);
        if same_name.len() > 1 {
            error!(
                "Servers {:?} are registered with the same name {:?}",
                same_name, name
            );
        }
        Ok(HeartbeatServerResult { is_new: true })
    }

    fn handle_update_job_state(
        &self,
        job_id: JobId,
        server_id: ServerId,
        job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            let job_detail = entry.get();
            if job_detail.server_id != server_id {
                bail!(
                    "Job id {} is not registered on server {:?}",
                    job_id,
                    server_id
                )
            }

            let now = Instant::now();
            let mut server_details = servers.get_mut(&server_id);
            if let Some(ref mut details) = server_details {
                details.last_seen = now;
            };

            match (job_detail.state, job_state) {
                (JobState::Pending, JobState::Ready) => entry.get_mut().state = job_state,
                (JobState::Ready, JobState::Started) => {
                    if server_details.is_none() {
                        warn!("Job state updated, but server is not known to scheduler")
                    }
                    entry.get_mut().state = job_state
                }
                (from, to) => bail!("Invalid job state transition from {} to {}", from, to),
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else {
            bail!("Unknown job")
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_complete_job(
        &self,
        job_id: JobId,
        server_id: ServerId,
        peak_memory: Option<u64>,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut memory_measurements = self.memory_measurements.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        let btree_map::Entry::Occupied(entry) = jobs.entry(job_id) else {
            bail!("Unknown job")
        };
        let job_detail = entry.get();
        if job_detail.server_id != server_id {
            bail!(
                "Job id {} is not registered on server {:?}",
                job_id,
                server_id
            )
        }
        if job_detail.state != JobState::Started {
            bail!(
                "Invalid job state transition from {} to complete",
                job_detail.state
            )
        }
        let (job_id, job_detail) = entry.remove_entry();
        if let Some(peak_memory) = peak_memory {
            debug!("Job {} peak memory: {} bytes", job_id, peak_memory);
            memory_measurements.record(
                job_detail.command_hash,
                job_detail.client_name,
                peak_memory,
            );
        }
        if let Some(details) = servers.get_mut(&server_id) {
            details.last_seen = Instant::now();
        } else {
            bail!("Job from an unknown server marked as finished?")
        }
        info!("Job {} completed", job_id);
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        Ok(SchedulerStatusResult {
            num_servers: servers.len(),
            num_cpus: servers.values().map(|v| v.info.num_cpus).sum(),
            in_progress: jobs.len(),
            servers: servers
                .iter()
                .map(|(&server_id, details)| ServerStatus {
                    server_id,
                    info: details.info.clone(),
                    cpu_speed: cpu_speed::cpu_speed_of_builder(&details.info),
                })
                .collect(),
        })
    }
}

pub struct Server {
    builder: Box<dyn BuilderIncoming>,
    cache: Mutex<TcCache>,
    job_toolchains: Mutex<HashMap<JobId, Toolchain>>,
}

impl Server {
    pub fn new(
        builder: Box<dyn BuilderIncoming>,
        cache_dir: &Path,
        toolchain_cache_size: u64,
    ) -> Result<Server> {
        let cache = TcCache::new(&cache_dir.join("tc"), toolchain_cache_size)
            .context("Failed to create toolchain cache")?;
        Ok(Server {
            builder,
            cache: Mutex::new(cache),
            job_toolchains: Mutex::new(HashMap::new()),
        })
    }
}

impl ServerIncoming for Server {
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.cache.lock().unwrap().contains_toolchain(&tc);
        assert!(
            self.job_toolchains
                .lock()
                .unwrap()
                .insert(job_id, tc)
                .is_none()
        );
        let state = if need_toolchain {
            JobState::Pending
        } else {
            // TODO: can start prepping the build environment now
            JobState::Ready
        };
        Ok(AssignJobResult {
            state,
            need_toolchain,
        })
    }
    fn handle_submit_toolchain(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        requester
            .do_update_job_state(job_id, JobState::Ready)
            .context("Updating job state failed")?;
        // TODO: need to lock the toolchain until the container has started
        // TODO: can start prepping container
        let tc = match self.job_toolchains.lock().unwrap().get(&job_id).cloned() {
            Some(tc) => tc,
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        let mut cache = self.cache.lock().unwrap();
        // TODO: this returns before reading all the data, is that valid?
        if cache.contains_toolchain(&tc) {
            return Ok(SubmitToolchainResult::Success);
        }
        Ok(cache
            .insert_with(&tc, |mut file| {
                io::copy(&mut { tc_rdr }, &mut file).map(|_| ())
            })
            .map(|_| SubmitToolchainResult::Success)
            .unwrap_or(SubmitToolchainResult::CannotCache))
    }
    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        requester
            .do_update_job_state(job_id, JobState::Started)
            .context("Updating job state failed")?;
        let tc = self.job_toolchains.lock().unwrap().remove(&job_id);
        let (res, peak_memory) = match tc {
            None => (Ok(RunJobResult::JobNotFound), None),
            Some(tc) => {
                match self
                    .builder
                    .run_build(tc, command, outputs, inputs_rdr, &self.cache)
                {
                    Err(e) => (Err(e.context("run build failed")), None),
                    Ok(BuildResult {
                        output,
                        outputs,
                        peak_memory,
                    }) => {
                        // don't use memory stats from a failed job as that's probably a lot less
                        // memory than if the whole compilation happened
                        let peak_memory = peak_memory.filter(|_| output.code == 0);
                        (
                            Ok(RunJobResult::Complete(JobComplete { output, outputs })),
                            peak_memory,
                        )
                    }
                }
            }
        };
        requester
            .do_complete_job(job_id, peak_memory)
            .context("Updating job state failed")?;
        res
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;
    use sccache::dist::cpu_speed::{REFERENCE_CPU_MODEL, REFERENCE_CPU_SPEED};
    use sccache::dist::{BuilderLimits, CpuSpeed};

    #[test]
    fn scheduler_instances_namespace_job_ids() {
        let scheduler0 = Scheduler::with_job_id_base(0x1000, MemoryMeasurements::new(10));
        let scheduler1 = Scheduler::with_job_id_base(0x2000, MemoryMeasurements::new(10));

        assert_eq!(scheduler0.next_job_id(), JobId(0x1000));
        assert_eq!(scheduler0.next_job_id(), JobId(0x1001));
        assert_eq!(scheduler1.next_job_id(), JobId(0x2000));

        let wrapping = Scheduler::with_job_id_base(u64::MAX - 1, MemoryMeasurements::new(10));
        assert_eq!(wrapping.next_job_id(), JobId(u64::MAX - 1));
        assert_eq!(wrapping.next_job_id(), JobId(u64::MAX));
        assert_eq!(wrapping.next_job_id(), JobId(0));
    }

    struct TestJobAuthorizer;

    impl JobAuthorizer for TestJobAuthorizer {
        fn generate_token(&self, _job_id: JobId) -> Result<String> {
            Ok(String::new())
        }

        fn verify_token(&self, _job_id: JobId, _token: &str) -> Result<()> {
            Ok(())
        }
    }

    fn builder_info(name: &str, num_cpus: usize, max_jobs: usize) -> BuilderInfo {
        BuilderInfo {
            name: name.to_owned(),
            num_cpus,
            cpu_model: None,
            configured_cpu_speed: None,
            limits: BuilderLimits {
                max_jobs,
                max_memory: None,
            },
        }
    }

    // just for shorthand
    fn heartbeat(
        scheduler: &Scheduler,
        server_id: ServerId,
        server_nonce: &ServerNonce,
        info: BuilderInfo,
    ) -> Result<HeartbeatServerResult> {
        scheduler.handle_heartbeat_server(
            server_id,
            server_nonce.clone(),
            info,
            Box::new(TestJobAuthorizer),
        )
    }

    fn get_builder_info_for_server(scheduler: &Scheduler, server_id: ServerId) -> BuilderInfo {
        let servers = scheduler.servers.lock().unwrap();
        servers.get(&server_id).unwrap().info.clone()
    }

    struct DummyAlwaysAcceptStrategy;

    impl SchedulerOutgoing for DummyAlwaysAcceptStrategy {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _toolchain: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            archive_id: "some_toolchain".to_owned(),
        }
    }

    fn command_hash(number: u8) -> CommandHash {
        serde_json::from_value(serde_json::Value::String(format!("{number:064x}"))).unwrap()
    }

    fn client_name(number: u8) -> String {
        format!("client-{number}")
    }

    fn allocate_command(
        scheduler: &Scheduler,
        command_hash: CommandHash,
        client_name: String,
    ) -> AllocJobResult {
        scheduler
            .handle_alloc_job(
                &DummyAlwaysAcceptStrategy,
                toolchain(),
                command_hash,
                client_name,
            )
            .unwrap()
    }

    // returns server that was given the job
    fn allocate(scheduler: &Scheduler) -> Option<ServerId> {
        match allocate_command(scheduler, command_hash(0), client_name(0)) {
            AllocJobResult::Success { job_alloc, .. } => Some(job_alloc.server_id),
            AllocJobResult::Fail { .. } => None,
        }
    }

    #[test]
    fn heartbeat_updates_info_of_known_server() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();

        let result = heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 4, 5),
        )
        .unwrap();
        assert!(result.is_new);
        assert_eq!(
            get_builder_info_for_server(&scheduler, server_id),
            builder_info("a", 4, 5)
        );

        let result = heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 8, 2),
        )
        .unwrap();
        assert!(!result.is_new);
        assert_eq!(
            get_builder_info_for_server(&scheduler, server_id),
            builder_info("a", 8, 2)
        );
        assert_eq!(scheduler.handle_status().unwrap().num_cpus, 8);
    }

    #[test]
    fn zero_max_jobs_effectively_disables_a_server() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info("a", 4, 0),
        )
        .unwrap();

        assert_eq!(allocate(&scheduler), None);
    }

    #[test]
    fn increasing_max_jobs_while_running() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();
        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 4, 2),
        )
        .unwrap();

        assert_eq!(allocate(&scheduler), Some(server_id));
        assert_eq!(allocate(&scheduler), Some(server_id));
        assert_eq!(allocate(&scheduler), None); // reached max jobs

        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 4, 3),
        )
        .unwrap();
        // one more job is now allowed so one more allocation works
        assert_eq!(allocate(&scheduler), Some(server_id));
        assert_eq!(allocate(&scheduler), None); // max again

        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 4, 1),
        )
        .unwrap();
        assert_eq!(allocate(&scheduler), None);
        assert_eq!(scheduler.jobs.lock().unwrap().len(), 3);
    }

    #[test]
    fn basic_load_balancing() {
        let scheduler = Scheduler::default();
        let small: ServerId = "127.0.0.1:10501".parse().unwrap();
        let large: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            small,
            &ServerNonce::new(),
            builder_info("small", 2, 2),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            large,
            &ServerNonce::new(),
            builder_info("large", 8, 8),
        )
        .unwrap();

        let mut selected_server_ids = Vec::new();
        let count_jobs_on_server = |selected_server_ids: &[ServerId], server_id| {
            selected_server_ids
                .iter()
                .filter(|&&id| id == server_id)
                .count()
        };

        // okay, if five jobs are pushed, and we are balancing load, then
        // the 8 job machine should have 4, and the 2 job machine should have 1
        for _ in 0..5 {
            selected_server_ids.push(allocate(&scheduler).unwrap());
        }
        assert_eq!(count_jobs_on_server(&selected_server_ids, small), 1);
        assert_eq!(count_jobs_on_server(&selected_server_ids, large), 4);

        // now just test that things properly fill up without error
        for _ in 0..5 {
            selected_server_ids.push(allocate(&scheduler).unwrap());
        }
        assert_eq!(count_jobs_on_server(&selected_server_ids, small), 2);
        assert_eq!(count_jobs_on_server(&selected_server_ids, large), 8);
        assert_eq!(allocate(&scheduler), None); // max reached
    }

    #[test]
    fn restarting_a_server_clears_anything_having_to_do_with_previous_run() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info("a", 4, 4),
        )
        .unwrap();
        assert_eq!(allocate(&scheduler), Some(server_id));
        {
            let jobs = scheduler.jobs.lock().unwrap();
            assert_eq!(jobs_on(server_id, &jobs).count(), 1);
        }

        let result = heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info("a", 4, 4),
        )
        .unwrap();
        assert!(result.is_new);

        // running jobs are cleared
        assert!(scheduler.jobs.lock().unwrap().is_empty());
    }

    #[test]
    fn duplicate_names_still_work() {
        let scheduler = Scheduler::default();
        let first: ServerId = "127.0.0.1:10501".parse().unwrap();
        let second: ServerId = "127.0.0.2:10501".parse().unwrap();
        let third: ServerId = "127.0.0.3:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            first,
            &ServerNonce::new(),
            builder_info("dup", 4, 4),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            second,
            &ServerNonce::new(),
            builder_info("dup", 4, 4),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            third,
            &ServerNonce::new(),
            builder_info("other", 4, 4),
        )
        .unwrap();

        // make sure that each of the servers still gets registered with us, seems fine
        let servers = scheduler.servers.lock().unwrap();
        let mut duplicates = servers_named(&servers, "dup");
        duplicates.sort_by_key(|server_id| server_id.addr());
        assert_eq!(duplicates, vec![first, second]);
        assert_eq!(servers_named(&servers, "other"), vec![third]);
    }

    fn time_ago(duration: Duration) -> Instant {
        Instant::now().checked_sub(duration).unwrap()
    }

    #[test]
    fn invalid_heartbeat() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();

        assert!(
            heartbeat(
                &scheduler,
                server_id,
                &server_nonce,
                builder_info("a", 0, 1)
            )
            .is_err()
        );
        assert!(heartbeat(&scheduler, server_id, &server_nonce, builder_info("", 4, 1)).is_err());
        assert!(scheduler.servers.lock().unwrap().is_empty());
    }

    fn set_last_error(scheduler: &Scheduler, server_id: ServerId, last_error: Instant) {
        let mut servers = scheduler.servers.lock().unwrap();
        servers.get_mut(&server_id).unwrap().last_error = Some(last_error);
    }

    #[test]
    fn servers_with_error_can_be_picked_if_all_others_are_full() {
        let scheduler = Scheduler::default();
        let healthy: ServerId = "127.0.0.1:10501".parse().unwrap();
        let errored: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            healthy,
            &ServerNonce::new(),
            builder_info("healthy", 4, 2),
        )
        .unwrap();

        heartbeat(
            &scheduler,
            errored,
            &ServerNonce::new(),
            builder_info("errored", 4, 8),
        )
        .unwrap();
        set_last_error(&scheduler, errored, time_ago(Duration::from_secs(1)));

        assert_eq!(allocate(&scheduler), Some(healthy));
        assert_eq!(allocate(&scheduler), Some(healthy));
        for _ in 0..8 {
            assert_eq!(allocate(&scheduler), Some(errored));
        }
        assert_eq!(allocate(&scheduler), None);
    }

    #[test]
    fn of_multiple_servers_with_errors_the_oldest_errored_one_is_higher_priority() {
        let scheduler = Scheduler::default();
        let older_error: ServerId = "127.0.0.1:10501".parse().unwrap();
        let newer_error: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            older_error,
            &ServerNonce::new(),
            builder_info("full", 4, 2),
        )
        .unwrap();
        set_last_error(&scheduler, older_error, time_ago(Duration::from_secs(10)));

        heartbeat(
            &scheduler,
            newer_error,
            &ServerNonce::new(),
            builder_info("errored", 4, 8),
        )
        .unwrap();
        set_last_error(&scheduler, newer_error, time_ago(Duration::from_secs(1)));

        // older error picked first even though it has more load
        assert_eq!(allocate(&scheduler), Some(older_error));
        assert_eq!(allocate(&scheduler), Some(older_error));

        for _ in 0..8 {
            assert_eq!(allocate(&scheduler), Some(newer_error));
        }
        assert_eq!(allocate(&scheduler), None);
    }

    #[test]
    fn old_pending_jobs_timeout() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();
        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 4, 1),
        )
        .unwrap();
        assert_eq!(allocate(&scheduler), Some(server_id));
        assert_eq!(allocate(&scheduler), None); // max capacity

        // force the pending job to be timed out
        for job in scheduler.jobs.lock().unwrap().values_mut() {
            job.assigned_at = time_ago(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1));
        }

        // if the server didn't pick up the job, then it is considered failed and space is open
        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 4, 1),
        )
        .unwrap();
        assert_eq!(allocate(&scheduler), Some(server_id));
    }

    struct ServerThatSendsHeartbeatDuringJobAllocation<'a> {
        scheduler: &'a Scheduler,
        server_nonce: ServerNonce,
        info: BuilderInfo,
    }

    impl SchedulerOutgoing for ServerThatSendsHeartbeatDuringJobAllocation<'_> {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            _job_id: JobId,
            _toolchain: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            heartbeat(
                self.scheduler,
                server_id,
                &self.server_nonce,
                self.info.clone(),
            )?;
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    // try to test some potential weird interleaving of messages
    #[test]
    fn max_jobs_lowered_during_job_allocation() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();
        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 4, 1),
        )
        .unwrap();

        let requester = ServerThatSendsHeartbeatDuringJobAllocation {
            scheduler: &scheduler,
            server_nonce,
            info: builder_info("a", 4, 0),
        };
        let allocation = scheduler
            .handle_alloc_job(&requester, toolchain(), command_hash(0), client_name(0))
            .unwrap();
        // seems fine
        assert!(matches!(allocation, AllocJobResult::Success { .. }));

        let jobs = scheduler.jobs.lock().unwrap();
        let servers = scheduler.servers.lock().unwrap();
        let details = servers.get(&server_id).unwrap();
        assert_eq!(details.info.limits.max_jobs, 0);
        assert_eq!(jobs_on(server_id, &jobs).count(), 1);
    }

    // this one should not work
    #[test]
    fn server_restart_during_job_allocation() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info("a", 4, 1),
        )
        .unwrap();

        let requester = ServerThatSendsHeartbeatDuringJobAllocation {
            scheduler: &scheduler,
            // show the server as having restarted with a new nonce
            server_nonce: ServerNonce::new(),
            info: builder_info("a", 4, 1),
        };
        let allocation = scheduler
            .handle_alloc_job(&requester, toolchain(), command_hash(0), client_name(0))
            .unwrap();

        // this should not work
        match allocation {
            AllocJobResult::Fail { msg: message } => {
                assert!(
                    message.contains("cleaned up before allocation completed"),
                    "{message}"
                );
            }
            AllocJobResult::Success { .. } => panic!("expected job allocation to fail"),
        }
        assert!(scheduler.jobs.lock().unwrap().is_empty());
    }

    struct ReapDuringAssign<'a> {
        scheduler: &'a Scheduler,
        server_id: ServerId,
        server_nonce: ServerNonce,
    }

    impl SchedulerOutgoing for ReapDuringAssign<'_> {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            assert_eq!(server_id, self.server_id);

            {
                let mut jobs = self.scheduler.jobs.lock().unwrap();
                jobs.get_mut(&job_id).unwrap().assigned_at = Instant::now()
                    .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                    .unwrap();
            }

            let heartbeat = heartbeat(
                self.scheduler,
                server_id,
                &self.server_nonce,
                builder_info("a", 1, 2),
            )?;
            assert!(!heartbeat.is_new);

            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn allocation_fails_if_assignment_is_cleaned_up() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();

        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info("a", 1, 2),
        )
        .unwrap();

        let requester = ReapDuringAssign {
            scheduler: &scheduler,
            server_id,
            server_nonce,
        };
        let allocation = scheduler
            .handle_alloc_job(&requester, toolchain(), command_hash(0), client_name(0))
            .unwrap();

        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert!(scheduler.jobs.lock().unwrap().is_empty());
        assert!(scheduler.servers.lock().unwrap().contains_key(&server_id));
    }

    const GIBIBYTE: u64 = 1024 * 1024 * 1024;

    fn builder_info_with_memory_limits(max_jobs: usize, max_memory: Option<u64>) -> BuilderInfo {
        BuilderInfo {
            limits: BuilderLimits {
                max_jobs,
                max_memory,
            },
            ..builder_info("a", 4, max_jobs)
        }
    }

    fn unwrap_job_allocation(result: AllocJobResult) -> JobAlloc {
        match result {
            AllocJobResult::Success { job_alloc, .. } => job_alloc,
            AllocJobResult::Fail { msg } => panic!("allocation failed: {msg}"),
        }
    }

    fn expect_failure(result: AllocJobResult) -> String {
        match result {
            AllocJobResult::Success { .. } => panic!("allocation must fail"),
            AllocJobResult::Fail { msg } => msg,
        }
    }

    fn start(scheduler: &Scheduler, job_alloc: &JobAlloc) {
        for state in [JobState::Ready, JobState::Started] {
            scheduler
                .handle_update_job_state(job_alloc.job_id, job_alloc.server_id, state)
                .unwrap();
        }
    }

    fn complete(scheduler: &Scheduler, job_alloc: &JobAlloc, peak_memory: Option<u64>) {
        start(scheduler, job_alloc);
        scheduler
            .handle_complete_job(job_alloc.job_id, job_alloc.server_id, peak_memory)
            .unwrap();
    }

    #[test]
    fn jobs_getting_assigned_within_memory_limits() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(10, Some(3 * GIBIBYTE)),
        )
        .unwrap();

        // each job estimated at 1GB by default
        for number in 0..3 {
            unwrap_job_allocation(allocate_command(
                &scheduler,
                command_hash(number),
                client_name(number),
            ));
        }
        let message = expect_failure(allocate_command(
            &scheduler,
            command_hash(3),
            client_name(3),
        ));
        assert!(message.contains("Insufficient capacity"), "{message}");
    }

    #[test]
    fn unlimited_memory_if_unspecified() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(5, None),
        )
        .unwrap();

        for _ in 0..5 {
            assert_eq!(allocate(&scheduler), Some(server_id));
        }
        assert_eq!(allocate(&scheduler), None);
    }

    #[test]
    fn recording_job_memory_usage_for_estimation() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(10, Some(3 * GIBIBYTE)),
        )
        .unwrap();

        let job = unwrap_job_allocation(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(1),
        ));
        complete(&scheduler, &job, Some(2 * GIBIBYTE));
        let history = vec![memory_history::HistoryEntry {
            command_hash: command_hash(1),
            peak_memory: 2 * GIBIBYTE,
        }];
        assert_eq!(
            scheduler.memory_measurements.lock().unwrap().history(),
            history
        );

        // same command from a different requester benefits from the estimation
        let first = unwrap_job_allocation(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(2),
        ));
        expect_failure(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(2),
        ));
        // if the requester has a previous completed job and does another unknown command, we assume
        // the new command will use about the same amount of memory
        expect_failure(allocate_command(
            &scheduler,
            command_hash(2),
            client_name(1),
        ));
        // estimate at 1GB if all else fails
        let second = unwrap_job_allocation(allocate_command(
            &scheduler,
            command_hash(2),
            client_name(2),
        ));

        // if memory couldn't be measured then we don't keep up the estimations
        complete(&scheduler, &second, None);
        complete(&scheduler, &first, None);
        assert_eq!(
            scheduler.memory_measurements.lock().unwrap().history(),
            history
        );
        unwrap_job_allocation(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(2),
        ));
        expect_failure(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(2),
        ));
    }

    #[test]
    fn lowering_max_memory_while_running() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();
        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info_with_memory_limits(10, Some(4 * GIBIBYTE)),
        )
        .unwrap();
        let first = unwrap_job_allocation(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(1),
        ));
        let second = unwrap_job_allocation(allocate_command(
            &scheduler,
            command_hash(2),
            client_name(1),
        ));

        // lower memory limits
        heartbeat(
            &scheduler,
            server_id,
            &server_nonce,
            builder_info_with_memory_limits(10, Some(GIBIBYTE)),
        )
        .unwrap();
        // jobs still there
        assert_eq!(allocate(&scheduler), None);
        assert_eq!(scheduler.jobs.lock().unwrap().len(), 2);

        // cant try to start more, though
        complete(&scheduler, &first, None);
        assert_eq!(allocate(&scheduler), None);
        complete(&scheduler, &second, None);
        assert_eq!(allocate(&scheduler), Some(server_id));
    }

    #[test]
    fn server_doesnt_try_to_assign_a_job_if_there_arent_enough_resources() {
        let scheduler = Scheduler::default();
        let small: ServerId = "127.0.0.1:10501".parse().unwrap();
        let busy: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            small,
            &ServerNonce::new(),
            builder_info_with_memory_limits(10, Some(GIBIBYTE / 2)),
        )
        .unwrap();
        let message = expect_failure(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(1),
        ));
        assert!(
            message.contains("exceeds the max memory of all 1 servers"),
            "{message}"
        );
    }

    struct RequesterThatAllocatesDuringJobAssignment<'a> {
        scheduler: &'a Scheduler,
        nested_allocation: Mutex<Option<AllocJobResult>>,
    }

    impl SchedulerOutgoing for RequesterThatAllocatesDuringJobAssignment<'_> {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _toolchain: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            *self.nested_allocation.lock().unwrap() = Some(allocate_command(
                self.scheduler,
                command_hash(2),
                client_name(2),
            ));
            Ok(AssignJobResult {
                state: JobState::Ready,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn job_not_yet_running_is_consider_as_part_of_load() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(10, Some(GIBIBYTE + GIBIBYTE / 2)),
        )
        .unwrap();

        let requester = RequesterThatAllocatesDuringJobAssignment {
            scheduler: &scheduler,
            nested_allocation: Mutex::new(None),
        };
        let job = unwrap_job_allocation(
            scheduler
                .handle_alloc_job(&requester, toolchain(), command_hash(1), client_name(1))
                .unwrap(),
        );
        expect_failure(requester.nested_allocation.lock().unwrap().take().unwrap());

        let jobs = scheduler.jobs.lock().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs.get(&job.job_id).unwrap().state, JobState::Ready);
    }

    struct FailAssign;

    impl SchedulerOutgoing for FailAssign {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _toolchain: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            Err(anyhow::anyhow!("server unreachable"))
        }
    }

    #[test]
    fn job_which_failed_to_be_assigned_is_not_considered_as_part_of_load() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(10, Some(GIBIBYTE)),
        )
        .unwrap();

        assert!(
            scheduler
                .handle_alloc_job(&FailAssign, toolchain(), command_hash(1), client_name(1))
                .is_err()
        );
        assert!(scheduler.jobs.lock().unwrap().is_empty());
        // allocation can work on errored server if it's the only available one
        assert_eq!(allocate(&scheduler), Some(server_id));
    }

    #[test]
    fn all_registered_servers_present_in_status() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(3, Some(GIBIBYTE)),
        )
        .unwrap();

        let status = scheduler.handle_status().unwrap();
        assert_eq!(status.servers.len(), 1);
        assert_eq!(status.servers[0].server_id, server_id);
        assert_eq!(
            status.servers[0].info,
            builder_info_with_memory_limits(3, Some(GIBIBYTE))
        );
    }

    fn speed_builder_info(
        name: &str,
        cpu_model: Option<&str>,
        configured_cpu_speed: Option<u32>,
        max_jobs: usize,
    ) -> BuilderInfo {
        BuilderInfo {
            cpu_model: cpu_model.map(str::to_owned),
            configured_cpu_speed,
            ..builder_info(name, 4, max_jobs)
        }
    }

    const UNKNOWN_CPU: &str = "Epic Computer 3000";

    #[test]
    fn ranking() {
        let scheduler = Scheduler::default();
        let slow: ServerId = "127.0.0.1:10501".parse().unwrap();
        let fast: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            slow,
            &ServerNonce::new(),
            speed_builder_info("slow", Some(REFERENCE_CPU_MODEL), None, 4),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            fast,
            &ServerNonce::new(),
            speed_builder_info("fast", None, Some(REFERENCE_CPU_SPEED + 1), 4),
        )
        .unwrap();
        assert_eq!(allocate(&scheduler), Some(fast));
    }

    #[test]
    fn being_busy_deprioritizes_server_in_ranking() {
        let scheduler = Scheduler::default();
        let slow: ServerId = "127.0.0.1:10501".parse().unwrap();
        let fast: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            slow,
            &ServerNonce::new(),
            speed_builder_info("slow", None, Some(1500), 4),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            fast,
            &ServerNonce::new(),
            speed_builder_info("fast", None, Some(2000), 4),
        )
        .unwrap();

        let alocation_results: Vec<_> = (0..8).map(|_| allocate(&scheduler).unwrap()).collect();
        assert_eq!(
            alocation_results,
            // with the speed being weighted at 2x the business, it should look something like this
            // given the speed of slow is 3/4 the speed of fast
            vec![fast, fast, slow, fast, slow, fast, slow, slow]
        );
        assert_eq!(allocate(&scheduler), None);
    }

    #[test]
    fn ranking_cares_more_about_speed() {
        let ranking = |cpu_speed, jobs_assigned, max_jobs| Ranking {
            cpu_speed,
            jobs_assigned,
            max_jobs,
        };
        struct Case {
            first: Ranking,
            second: Ranking,
            first_is_better: bool,
            second_is_better: bool,
        };

        let cases = [
            Case {
                first: ranking(Some(2000), 0, 4),
                second: ranking(Some(1000), 0, 4),
                first_is_better: true,
                second_is_better: false,
            },
            Case {
                first: ranking(Some(2000), 3, 4),
                second: ranking(Some(1000), 0, 4),
                first_is_better: true,
                second_is_better: false,
            },
            Case {
                first: ranking(Some(1000), 0, 4),
                second: ranking(None, 0, 4),
                first_is_better: true,
                second_is_better: false,
            },
            // Equal scores, lower load.
            Case {
                first: ranking(Some(1000), 1, 2),
                second: ranking(Some(750), 0, 4),
                first_is_better: false,
                second_is_better: true,
            },
            Case {
                first: ranking(Some(150), 2, 3),
                second: ranking(Some(100), 0, 1),
                first_is_better: false,
                second_is_better: true,
            },
            Case {
                first: ranking(None, 1, 2),
                second: ranking(None, 1, 4),
                first_is_better: false,
                second_is_better: true,
            },
            // Fully equal.
            Case {
                first: ranking(Some(1000), 1, 4),
                second: ranking(Some(1000), 2, 8),
                first_is_better: false,
                second_is_better: false,
            },
            Case {
                first: ranking(None, 1, 2),
                second: ranking(None, 2, 4),
                first_is_better: false,
                second_is_better: false,
            },
        ];
        for (
            index,
            Case {
                first,
                second,
                first_is_better,
                second_is_better,
            },
        ) in cases.iter().enumerate()
        {
            assert_eq!(first.is_better_than(second), *first_is_better, "{index}");
            assert_eq!(second.is_better_than(first), *second_is_better, "{index}");
        }
    }

    #[test]
    fn dont_pick_unknown_speed_unless_no_others_are_available() {
        let scheduler = Scheduler::default();
        let known: ServerId = "127.0.0.1:10501".parse().unwrap();
        let unknown: ServerId = "127.0.0.2:10501".parse().unwrap();
        let no_model: ServerId = "127.0.0.3:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            known,
            &ServerNonce::new(),
            speed_builder_info("known", Some(REFERENCE_CPU_MODEL), None, 2),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            unknown,
            &ServerNonce::new(),
            speed_builder_info("unknown", Some(UNKNOWN_CPU), None, 2),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            no_model,
            &ServerNonce::new(),
            speed_builder_info("no-model", None, None, 4),
        )
        .unwrap();

        assert_eq!(allocate(&scheduler), Some(known));
        assert_eq!(allocate(&scheduler), Some(known));
        // pick the one with lower load
        let picked: Vec<_> = (0..6).map(|_| allocate(&scheduler).unwrap()).collect();
        assert_eq!(picked.iter().filter(|&&id| id == unknown).count(), 2);
        assert_eq!(picked.iter().filter(|&&id| id == no_model).count(), 4);
        assert_eq!(allocate(&scheduler), None);
    }

    #[test]
    fn server_is_faster_but_has_error() {
        let scheduler = Scheduler::default();
        let slow: ServerId = "127.0.0.1:10501".parse().unwrap();
        let fast: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            slow,
            &ServerNonce::new(),
            speed_builder_info("slow", Some(UNKNOWN_CPU), None, 1),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            fast,
            &ServerNonce::new(),
            speed_builder_info("fast", None, Some(2000), 4),
        )
        .unwrap();
        set_last_error(&scheduler, fast, time_ago(Duration::from_secs(1)));

        assert_eq!(allocate(&scheduler), Some(slow));
        assert_eq!(allocate(&scheduler), Some(fast));
    }

    #[test]
    fn get_cpu_speeds_with_dist_status() {
        let scheduler = Scheduler::default();
        let configured: ServerId = "127.0.0.1:10501".parse().unwrap();
        let table: ServerId = "127.0.0.2:10501".parse().unwrap();
        let unknown: ServerId = "127.0.0.3:10501".parse().unwrap();
        let configured_nonce = ServerNonce::new();
        heartbeat(
            &scheduler,
            configured,
            &configured_nonce,
            speed_builder_info("configured", Some(REFERENCE_CPU_MODEL), Some(1234), 4),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            table,
            &ServerNonce::new(),
            speed_builder_info("table", Some(REFERENCE_CPU_MODEL), None, 4),
        )
        .unwrap();
        heartbeat(
            &scheduler,
            unknown,
            &ServerNonce::new(),
            speed_builder_info("unknown", Some(UNKNOWN_CPU), None, 4),
        )
        .unwrap();

        let cpu_speeds = |scheduler: &Scheduler| -> HashMap<ServerId, CpuSpeed> {
            let status = scheduler.handle_status().unwrap();
            status
                .servers
                .into_iter()
                .map(|server| (server.server_id, server.cpu_speed))
                .collect()
        };
        assert_eq!(
            cpu_speeds(&scheduler),
            HashMap::from([
                (configured, CpuSpeed::Configured(1234)),
                (table, CpuSpeed::Table(REFERENCE_CPU_SPEED)),
                (unknown, CpuSpeed::Unknown),
            ])
        );

        heartbeat(
            &scheduler,
            configured,
            &configured_nonce,
            speed_builder_info("configured", Some(REFERENCE_CPU_MODEL), None, 4),
        )
        .unwrap();
        assert_eq!(
            cpu_speeds(&scheduler)[&configured],
            CpuSpeed::Table(REFERENCE_CPU_SPEED)
        );
    }

    #[test]
    fn only_a_started_job_can_complete_on_its_own_server() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let other_server_id: ServerId = "127.0.0.2:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(3, None),
        )
        .unwrap();
        let job = unwrap_job_allocation(allocate_command(
            &scheduler,
            command_hash(1),
            client_name(1),
        ));

        assert!(
            scheduler
                .handle_complete_job(job.job_id, server_id, Some(GIBIBYTE))
                .is_err()
        );
        start(&scheduler, &job);
        // handle_complete_job must require both correct job_id and server_id
        assert!(
            scheduler
                .handle_complete_job(job.job_id, other_server_id, Some(GIBIBYTE))
                .is_err()
        );
        assert!(
            scheduler
                .memory_measurements
                .lock()
                .unwrap()
                .history()
                .is_empty()
        );

        // after start the job can be completed
        scheduler
            .handle_complete_job(job.job_id, server_id, Some(GIBIBYTE))
            .unwrap();
        assert!(scheduler.jobs.lock().unwrap().is_empty());
        assert!(
            scheduler
                .handle_complete_job(job.job_id, server_id, Some(GIBIBYTE))
                .is_err()
        );
    }

    #[test]
    fn job_allocation_with_empty_client_name() {
        let scheduler = Scheduler::default();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        heartbeat(
            &scheduler,
            server_id,
            &ServerNonce::new(),
            builder_info_with_memory_limits(3, None),
        )
        .unwrap();
        assert!(
            scheduler
                .handle_alloc_job(
                    &DummyAlwaysAcceptStrategy,
                    toolchain(),
                    command_hash(1),
                    String::new()
                )
                .is_err()
        );
        assert!(scheduler.jobs.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use sccache::dist::ProcessOutput;
    use std::os::unix::process::ExitStatusExt;

    struct FixedBuild {
        exit_code: i32,
        peak_memory: Option<u64>,
    }

    impl BuilderIncoming for FixedBuild {
        fn run_build(
            &self,
            _toolchain: Toolchain,
            _command: CompileCommand,
            _outputs: Vec<String>,
            _inputs_reader: InputsReader,
            _cache: &Mutex<TcCache>,
        ) -> Result<BuildResult> {
            let output = ProcessOutput::try_from(std::process::Output {
                status: std::process::ExitStatus::from_raw(self.exit_code << 8),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })?;
            Ok(BuildResult {
                output,
                outputs: Vec::new(),
                peak_memory: self.peak_memory,
            })
        }
    }

    #[derive(Default)]
    struct RecordingOutgoing {
        state_updates: Mutex<Vec<(JobId, JobState)>>,
        completions: Mutex<Vec<(JobId, Option<u64>)>>,
    }

    impl ServerOutgoing for RecordingOutgoing {
        fn do_update_job_state(
            &self,
            job_id: JobId,
            state: JobState,
        ) -> Result<UpdateJobStateResult> {
            self.state_updates.lock().unwrap().push((job_id, state));
            Ok(UpdateJobStateResult::Success)
        }
        fn do_complete_job(
            &self,
            job_id: JobId,
            peak_memory: Option<u64>,
        ) -> Result<UpdateJobStateResult> {
            self.completions.lock().unwrap().push((job_id, peak_memory));
            Ok(UpdateJobStateResult::Success)
        }
    }

    fn run_fixed_build(exit_code: i32, peak_memory: Option<u64>) -> RecordingOutgoing {
        let cache_directory = tempfile::tempdir().unwrap();
        let server = Server::new(
            Box::new(FixedBuild {
                exit_code,
                peak_memory,
            }),
            cache_directory.path(),
            1024 * 1024,
        )
        .unwrap();
        let job_id = JobId(9);
        server
            .handle_assign_job(
                job_id,
                Toolchain {
                    archive_id: "some_toolchain".to_owned(),
                },
            )
            .unwrap();
        let requester = RecordingOutgoing::default();
        let result = server
            .handle_run_job(
                &requester,
                job_id,
                CompileCommand {
                    executable: "/usr/bin/cc".to_owned(),
                    arguments: Vec::new(),
                    env_vars: Vec::new(),
                    cwd: "/".to_owned(),
                },
                Vec::new(),
                InputsReader::new(io::empty()),
            )
            .unwrap();
        match result {
            RunJobResult::Complete(JobComplete { output, .. }) => {
                assert_eq!(output.code, exit_code)
            }
            RunJobResult::JobNotFound => panic!("job not found"),
        }
        assert_eq!(
            *requester.state_updates.lock().unwrap(),
            vec![(job_id, JobState::Started)]
        );
        requester
    }

    #[test]
    fn get_peak_memory_after_completed_build() {
        let requester = run_fixed_build(0, Some(3 << 30));
        assert_eq!(
            *requester.completions.lock().unwrap(),
            vec![(JobId(9), Some(3 << 30))]
        );
    }

    #[test]
    fn no_peak_memory_for_failed_build() {
        let requester = run_fixed_build(1, Some(50 << 20));
        assert_eq!(
            *requester.completions.lock().unwrap(),
            vec![(JobId(9), None)]
        );
    }
}
