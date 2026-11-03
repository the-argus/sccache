use anyhow::{Context, Result};
use fs_err as fs;
use sccache::dist::CommandHash;
use sccache::lru_disk_cache::lru_cache::LruCache;
use serde::{Deserialize, Serialize};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SAVE_INTERVAL: Duration = Duration::from_secs(30);
const RECENT_COMPLETION_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Used to predict how much memory a new job will take, based on its command
pub struct MemoryMeasurements {
    last_peak_by_command: LruCache<CommandHash, Measurement>,
}

struct Measurement {
    peak_memory: u64,
    completed_at: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub command_hash: CommandHash,
    pub peak_memory: u64,
    #[serde(skip)] // only for jobs that are completed during this run of the scheduler
    pub completed_at: Option<Instant>,
}

impl MemoryMeasurements {
    pub fn new(max_entries: usize) -> Self {
        Self::from_history(Vec::new(), max_entries)
    }

    fn from_history(
        entries_least_recently_used_first: Vec<HistoryEntry>,
        max_entries: usize,
    ) -> Self {
        let mut last_peak_by_command = LruCache::new(max_entries as u64);
        for HistoryEntry {
            command_hash,
            peak_memory,
            completed_at,
        } in entries_least_recently_used_first
        {
            last_peak_by_command.insert(
                command_hash,
                Measurement {
                    peak_memory,
                    completed_at,
                },
            );
        }
        Self {
            last_peak_by_command,
        }
    }

    pub fn estimate(&self, command_hash: &CommandHash, worst_case: u64) -> u64 {
        self.last_peak_by_command
            .peek(command_hash)
            .map_or(worst_case, |measurement| measurement.peak_memory)
    }

    pub fn record(&mut self, command_hash: CommandHash, peak_memory: u64, completed_at: Instant) {
        self.last_peak_by_command.insert(
            command_hash,
            Measurement {
                peak_memory,
                completed_at: Some(completed_at),
            },
        );
    }

    pub fn largest_recent_memory_peak(&self, now: Instant) -> u64 {
        self.last_peak_by_command
            .iter()
            .filter(|(_, measurement)| {
                measurement.completed_at.is_some_and(|completed_at| {
                    now.saturating_duration_since(completed_at) <= RECENT_COMPLETION_WINDOW
                })
            })
            .map(|(_, measurement)| measurement.peak_memory)
            .max()
            .unwrap_or(0)
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        self.last_peak_by_command
            .iter()
            .map(|(command_hash, measurement)| HistoryEntry {
                command_hash: command_hash.clone(),
                peak_memory: measurement.peak_memory,
                completed_at: measurement.completed_at,
            })
            .collect()
    }
}

pub fn load_history(path: &Path, max_entries: usize) -> MemoryMeasurements {
    let entries = match fs::File::open(path) {
        Ok(file) => match serde_json::from_reader(BufReader::new(file)) {
            Ok(entries) => entries,
            Err(error) => {
                warn!(
                    "Ignoring memory usage history file {}, parse error: {}",
                    path.display(),
                    error
                );
                Vec::new()
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            info!(
                "No memory usage history at {}, using an empty history",
                path.display()
            );
            Vec::new()
        }
        Err(error) => {
            warn!("Ignoring the memory usage history: {}", error);
            Vec::new()
        }
    };
    MemoryMeasurements::from_history(entries, max_entries)
}

pub fn save_history(path: &Path, entries: &[HistoryEntry]) -> Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(directory)?;
    // writing to tempfile + moving is atomic, so we dont have corruption if we
    // shut down during this process
    let file = tempfile::NamedTempFile::new_in(directory).with_context(|| {
        format!(
            "Failed to create a temporary file in {}",
            directory.display()
        )
    })?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, entries)?;
    writer.flush()?;
    let file = writer.into_inner().map_err(|error| error.into_error())?;
    file.persist(path)
        .with_context(|| format!("Failed to replace {}", path.display()))?;
    Ok(())
}

fn save_current_history(measurements: &Mutex<MemoryMeasurements>, path: &Path) -> Result<()> {
    // LOCKS
    let entries = measurements.lock().unwrap().history();
    save_history(path, &entries)?;
    trace!(
        "Saved {} memory usage history entries to {}",
        entries.len(),
        path.display()
    );
    Ok(())
}

pub fn start_saving_history(measurements: Arc<Mutex<MemoryMeasurements>>, path: PathBuf) {
    thread::spawn(move || {
        loop {
            thread::sleep(SAVE_INTERVAL);
            if let Err(error) = save_current_history(&measurements, &path) {
                error!(
                    "Failed to save the memory history to {}: {:#}",
                    path.display(),
                    error
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_hash(number: u8) -> CommandHash {
        serde_json::from_value(serde_json::Value::String(format!("{number:064x}"))).unwrap()
    }

    const WORST_CASE: u64 = 8000;

    fn entry(number: u8, peak_memory: u64) -> HistoryEntry {
        HistoryEntry {
            command_hash: command_hash(number),
            peak_memory,
            completed_at: None,
        }
    }

    fn make_history_entry(number: u8, peak_memory: u64, completed_at: Instant) -> HistoryEntry {
        HistoryEntry {
            completed_at: Some(completed_at),
            ..entry(number, peak_memory)
        }
    }

    #[test]
    fn unknown_command_is_assumed_worst_case() {
        let mut measurements = MemoryMeasurements::new(10);
        let now = Instant::now();
        assert_eq!(
            measurements.estimate(&command_hash(1), WORST_CASE),
            WORST_CASE
        );

        measurements.record(command_hash(1), 100, now);
        assert_eq!(measurements.estimate(&command_hash(1), WORST_CASE), 100);
        assert_eq!(
            measurements.estimate(&command_hash(2), WORST_CASE),
            WORST_CASE
        );
        assert_eq!(measurements.estimate(&command_hash(2), 50), 50);

        measurements.record(command_hash(1), 150, now);
        assert_eq!(measurements.estimate(&command_hash(1), WORST_CASE), 150);
    }

    #[test]
    fn test_largest_recent_memory_peak() {
        let mut measurements = MemoryMeasurements::new(10);
        let start = Instant::now();
        let after = |duration: Duration| start + duration;
        assert_eq!(measurements.largest_recent_memory_peak(start), 0);

        measurements.record(command_hash(1), 300, start);
        measurements.record(command_hash(2), 200, after(Duration::from_secs(60)));
        assert_eq!(
            measurements.largest_recent_memory_peak(after(Duration::from_secs(60))),
            300
        );
        assert_eq!(
            measurements.largest_recent_memory_peak(after(RECENT_COMPLETION_WINDOW)),
            300
        );
        assert_eq!(
            measurements.largest_recent_memory_peak(after(
                RECENT_COMPLETION_WINDOW + Duration::from_secs(1)
            )),
            200
        );
        assert_eq!(
            measurements.largest_recent_memory_peak(after(
                RECENT_COMPLETION_WINDOW + Duration::from_secs(61)
            )),
            0
        );

        // if the same command uses a different amount of memory on another run, it modifies the
        // peak recorded for it
        measurements.record(command_hash(1), 100, after(Duration::from_secs(120)));
        assert_eq!(
            measurements.largest_recent_memory_peak(after(Duration::from_secs(120))),
            200
        );
        assert_eq!(
            measurements.largest_recent_memory_peak(after(
                RECENT_COMPLETION_WINDOW + Duration::from_secs(61)
            )),
            100
        );
    }

    #[test]
    fn loaded_history_not_considered_in_recent_peaks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");
        let mut measurements = MemoryMeasurements::new(10);
        let now = Instant::now();
        measurements.record(command_hash(1), 100, now);
        save_history(&path, &measurements.history()).unwrap();

        let loaded = load_history(&path, 10);
        assert_eq!(loaded.history(), vec![entry(1, 100)]);
        assert_eq!(loaded.estimate(&command_hash(1), WORST_CASE), 100);
        assert_eq!(loaded.largest_recent_memory_peak(now), 0);
    }

    #[test]
    fn history_prefers_more_recent_entries() {
        let mut measurements = MemoryMeasurements::new(2);
        let now = Instant::now();
        measurements.record(command_hash(1), 100, now);
        measurements.record(command_hash(2), 200, now);
        // Estimating does not update usage time
        assert_eq!(measurements.estimate(&command_hash(1), WORST_CASE), 100);
        measurements.record(command_hash(3), 300, now);

        assert_eq!(
            measurements.history(),
            vec![
                make_history_entry(2, 200, now),
                make_history_entry(3, 300, now)
            ]
        );
        assert_eq!(
            measurements.estimate(&command_hash(1), WORST_CASE),
            WORST_CASE
        );

        // Recording a known command again replaces the old recorded value
        measurements.record(command_hash(2), 210, now);
        assert_eq!(
            measurements.history(),
            vec![
                make_history_entry(3, 300, now),
                make_history_entry(2, 210, now)
            ]
        );
    }

    #[test]
    fn saving_and_loading_give_the_same_result() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("history.json");
        let entries = vec![entry(1, 100), entry(2, 200), entry(3, 300)];
        save_history(&path, &entries).unwrap();

        let loaded = load_history(&path, 10);
        assert_eq!(loaded.history(), entries);

        // a history file can be too long but still valid with the most recent items intact
        let truncated = load_history(&path, 2);
        assert_eq!(truncated.history(), vec![entry(2, 200), entry(3, 300)]);

        let mut measurements = MemoryMeasurements::new(10);
        measurements.record(command_hash(4), 400, Instant::now());
        save_history(&path, &measurements.history()).unwrap();
        let reloaded = load_history(&path, 10);
        assert_eq!(reloaded.history(), vec![entry(4, 400)]);
        assert_eq!(reloaded.estimate(&command_hash(9), WORST_CASE), WORST_CASE);
    }

    #[test]
    fn missing_or_corrupt_memoyr_usage_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");

        assert_eq!(load_history(&path, 10).history(), vec![]);

        let not_a_directory = directory.path().join("file");
        fs::write(&not_a_directory, "").unwrap();
        assert_eq!(
            load_history(&not_a_directory.join("history.json"), 10).history(),
            vec![]
        );

        for contents in [
            "",
            "{not json",
            r#"[{"command_hash": "not a hash", "peak_memory": 1}]"#,
            r#"[{"command_hash": 1, "peak_memory": 1}]"#,
        ] {
            fs::write(&path, contents).unwrap();
            assert_eq!(load_history(&path, 10).history(), vec![], "{contents}");
        }
    }

    // test that a failed save doesn't leave things in a bad state
    #[test]
    fn failed_save_followed_by_successful_save() {
        let directory = tempfile::tempdir().unwrap();
        let mut measurements = MemoryMeasurements::new(10);
        measurements.record(command_hash(1), 100, Instant::now());
        let measurements = Mutex::new(measurements);

        // A file where the directory of the history should be
        let blocker = directory.path().join("blocker");
        fs::write(&blocker, "").unwrap();
        let path = blocker.join("history.json");
        assert!(save_current_history(&measurements, &path).is_err());

        fs::remove_file(&blocker).unwrap();
        save_current_history(&measurements, &path).unwrap();
        assert_eq!(load_history(&path, 10).history(), vec![entry(1, 100)]);
    }
}
