use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Command::output(), except it also returns the peak memory usage of the command and all its
/// children
pub fn output_with_peak_memory(command: &mut Command) -> io::Result<(Output, Option<u64>)> {
    output_with_peak_memory_sampled(command, sample_tree_memory, SAMPLE_INTERVAL)
}

fn output_with_peak_memory_sampled(
    command: &mut Command,
    // called with the process ID of every child process periodically
    // guaranteed to be called at least once
    mut sample: impl FnMut(u32) -> u64,
    interval: Duration,
) -> io::Result<(Output, Option<u64>)> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let process_id = child.id();
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    thread::scope(|scope| {
        let stdout_reader = scope.spawn(move || -> io::Result<Vec<u8>> {
            let mut buffer = Vec::new();
            stdout.read_to_end(&mut buffer)?;
            Ok(buffer)
        });
        let stderr_reader = scope.spawn(move || -> io::Result<Vec<u8>> {
            let mut buffer = Vec::new();
            stderr.read_to_end(&mut buffer)?;
            Ok(buffer)
        });
        // leave child processes as a zombie to prevent the process ID from
        // being reused
        let (exited_sender, exited_receiver) = mpsc::channel();
        scope.spawn(move || {
            let _ = exited_sender.send(wait_for_exit_without_reaping(process_id));
        });

        let mut largest_sample = 0;
        let exited = loop {
            largest_sample = largest_sample.max(sample(process_id));
            match exited_receiver.recv_timeout(interval) {
                Ok(exited) => break exited,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(io::Error::other("the exit waiting thread ended"));
                }
            }
        };

        // now reap the zombie child >:D
        let reaped = reap(process_id);
        exited?;
        let (status, max_resident_set_size) = reaped?;

        let stdout = stdout_reader.join().expect("stdout reader panicked")?;
        let stderr = stderr_reader.join().expect("stderr reader panicked")?;
        let peak_memory = largest_sample.max(max_resident_set_size);
        Ok((
            Output {
                status,
                stdout,
                stderr,
            },
            (peak_memory > 0).then_some(peak_memory),
        ))
    })
}

fn wait_for_exit_without_reaping(process_id: u32) -> io::Result<()> {
    loop {
        // SAFETY: these are just plain structs and immediate function calls, I think it's fine to
        // zero initialize and do things like C. waitid doesn't store the pointer to siginfo
        let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                process_id as libc::id_t,
                &mut siginfo,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

// Returns exit status and max memory usage of this process and all children
fn reap(process_id: u32) -> io::Result<(ExitStatus, u64)> {
    loop {
        let mut status = 0;
        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: wait4 blocks and doesnt store away either of these pointers
        let result = unsafe { libc::wait4(process_id as libc::pid_t, &mut status, 0, &mut rusage) };
        if result == process_id as libc::pid_t {
            // ru_maxrss is in kilobytes on linux
            let max_resident_set_size = u64::try_from(rusage.ru_maxrss).unwrap_or(0) * 1024;
            return Ok((ExitStatus::from_raw(status), max_resident_set_size));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

// get the sum of all max memory usage below a root process
fn sample_tree_memory(root: u32) -> u64 {
    process_tree(root, &process_parents())
        .into_iter()
        .filter_map(|process_id| {
            // if process exits then filter it out, perhaps unfortunately
            let status = fs::read_to_string(format!("/proc/{process_id}/status")).ok()?;
            parse_peak_resident_set_size(&status)
        })
        .fold(0, u64::saturating_add)
}

fn process_parents() -> HashMap<u32, u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return HashMap::new();
    };
    entries
        .filter_map(|entry| {
            let process_id = entry.ok()?.file_name().to_str()?.parse::<u32>().ok()?;
            let stat = fs::read_to_string(format!("/proc/{process_id}/stat")).ok()?;
            Some((process_id, parse_stat_parent(&stat)?))
        })
        .collect()
}

fn process_tree(root: u32, parents: &HashMap<u32, u32>) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&process_id, &parent) in parents {
        children.entry(parent).or_default().push(process_id);
    }
    let mut tree = vec![root];
    let mut index = 0;
    while let Some(&process_id) = tree.get(index) {
        tree.extend(children.get(&process_id).into_iter().flatten());
        index += 1;
    }
    tree
}

// uses /proc/N/stat to get the parent process
fn parse_stat_parent(stat: &str) -> Option<u32> {
    let (_, after_name) = stat.rsplit_once(')')?;
    let mut fields = after_name.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

// uses /proc/N/status to get the peak memory usage in bytes
fn parse_peak_resident_set_size(status: &str) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?;
    let kibibytes = value
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const GIBIBYTE: u64 = 1024 * 1024 * 1024;

    fn wait_until_file_exists(marker: &Path) -> Command {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(r#"while [ ! -e "$1" ]; do sleep 0.01; done"#)
            .arg("sh")
            .arg(marker);
        command
    }

    #[test]
    fn parse_stat_parent_special_characters() {
        assert_eq!(
            parse_stat_parent("1234 (cc1plus) R 1200 1234 1200 0 -1 4194304 100 0 0 0"),
            Some(1200)
        );
        assert_eq!(
            parse_stat_parent("77 (a) b (c) S 42 77 77 0 -1 4194560 0 0 0 0"),
            Some(42)
        );
        assert_eq!(parse_stat_parent("77 (unterminated S 42"), None);
        assert_eq!(parse_stat_parent("77 (a) S"), None);
    }

    #[test]
    fn parse_peak_resident_set_size_reads_kibibytes() {
        let status =
            "Name:\tcc1plus\nVmPeak:\t  900000 kB\nVmHWM:\t  524288 kB\nVmRSS:\t  1000 kB\n";
        assert_eq!(
            parse_peak_resident_set_size(status),
            Some(512 * 1024 * 1024)
        );
        assert_eq!(
            parse_peak_resident_set_size("Name:\tkthreadd\nThreads:\t1\n"),
            None
        );
        assert_eq!(parse_peak_resident_set_size("VmHWM:\t  lots kB\n"), None);
    }

    #[test]
    fn process_tree_has_all_processes() {
        let parents = HashMap::from([(2, 1), (3, 2), (4, 2), (5, 4), (6, 1), (7, 99)]);
        let mut tree = process_tree(2, &parents);
        tree.sort();
        assert_eq!(tree, vec![2, 3, 4, 5]);
        assert_eq!(process_tree(7, &parents), vec![7]);
    }

    #[test]
    fn sample_has_child_processes() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        let tree = process_tree(std::process::id(), &process_parents());
        assert!(tree.contains(&child.id()));
        let own = parse_peak_resident_set_size(&fs::read_to_string("/proc/self/status").unwrap())
            .unwrap();
        assert!(sample_tree_memory(std::process::id()) > own);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn largest_sample_reported() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("marker");
        let fake_memory_peak_samples = [5 * GIBIBYTE, 7 * GIBIBYTE, 6 * GIBIBYTE];
        let mut calls = 0;
        let (output, peak_memory) = output_with_peak_memory_sampled(
            &mut wait_until_file_exists(&marker),
            |_| {
                let sample = fake_memory_peak_samples.get(calls).copied().unwrap_or(0);
                calls += 1;
                if calls == fake_memory_peak_samples.len() {
                    fs::write(&marker, "").unwrap();
                }
                sample
            },
            Duration::from_millis(1),
        )
        .unwrap();
        assert!(output.status.success());
        assert!(calls >= fake_memory_peak_samples.len());
        assert_eq!(peak_memory, Some(7 * GIBIBYTE));
    }

    #[test]
    fn samples_or_else_max_rss() {
        let (output, peak_memory) =
            output_with_peak_memory_sampled(Command::new("true").arg("x"), |_| 0, SAMPLE_INTERVAL)
                .unwrap();
        assert!(output.status.success());
        assert!(peak_memory.is_some_and(|peak_memory| peak_memory > 0));
    }

    #[test]
    fn test_sample_tree_memory() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("marker");
        let mut first_sample = None;
        let (output, peak_memory) = output_with_peak_memory_sampled(
            &mut wait_until_file_exists(&marker),
            |process_id| {
                let sample = sample_tree_memory(process_id);
                if first_sample.is_none() {
                    first_sample = Some(sample);
                    fs::write(&marker, "").unwrap();
                }
                sample
            },
            Duration::from_millis(1),
        )
        .unwrap();
        assert!(output.status.success());
        let first_sample = first_sample.unwrap();
        assert!(first_sample > 0);
        assert!(peak_memory.unwrap() >= first_sample);
    }

    #[test]
    fn test_command_output() {
        let (output, peak_memory) = output_with_peak_memory(
            Command::new("sh")
                .arg("-c")
                .arg("echo out; echo err >&2; head -c 1000000 /dev/zero; exit 3"),
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout.len(), "out\n".len() + 1000000);
        assert!(output.stdout.starts_with(b"out\n"));
        assert_eq!(output.stderr, b"err\n");
        assert!(peak_memory.is_some_and(|peak_memory| peak_memory > 0));
    }

    #[test]
    fn test_grandchild_process() {
        const BUFFER: u64 = 64 * 1024 * 1024;
        let (output, peak_memory) = output_with_peak_memory(Command::new("sh").arg("-c").arg(
            // use dd bs= because it must allocate a buffer that big, so we can assume that is a
            // minimum memory usage
            format!("sh -c 'dd if=/dev/zero of=/dev/null bs={BUFFER} count=1 2>/dev/null'; true"),
        ))
        .unwrap();
        assert!(output.status.success());
        let peak_memory = peak_memory.unwrap();
        assert!(peak_memory >= BUFFER, "{peak_memory}");
    }
}
