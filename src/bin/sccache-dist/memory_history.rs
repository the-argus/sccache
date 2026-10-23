use anyhow::{Context, Result};
use fs_err as fs;
use sccache::dist::CommandHash;
use sccache::lru_disk_cache::lru_cache::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const DEFAULT_PEAK_MEMORY_ESTIMATE: u64 = 1024 * 1024 * 1024;
const SAVE_INTERVAL: Duration = Duration::from_secs(30);

/// Used to predict how much memory a new job will take, based on its command
pub struct MemoryMeasurements {
    last_peak_by_command: LruCache<CommandHash, u64>,
    last_peak_by_client: HashMap<String, u64>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub command_hash: CommandHash,
    pub peak_memory: u64,
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
        } in entries_least_recently_used_first
        {
            last_peak_by_command.insert(command_hash, peak_memory);
        }
        Self {
            last_peak_by_command,
            last_peak_by_client: HashMap::new(),
        }
    }

    pub fn estimate(&self, command_hash: &CommandHash, client_name: &str) -> u64 {
        if let Some(&peak_memory) = self.last_peak_by_command.peek(command_hash) {
            return peak_memory;
        }
        if let Some(&peak_memory) = self.last_peak_by_client.get(client_name) {
            return peak_memory;
        }
        DEFAULT_PEAK_MEMORY_ESTIMATE
    }

    pub fn record(&mut self, command_hash: CommandHash, client_name: String, peak_memory: u64) {
        self.last_peak_by_command.insert(command_hash, peak_memory);
        self.last_peak_by_client.insert(client_name, peak_memory);
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        self.last_peak_by_command
            .iter()
            .map(|(command_hash, &peak_memory)| HistoryEntry {
                command_hash: command_hash.clone(),
                peak_memory,
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

    fn client(number: u8) -> String {
        format!("client-{number}")
    }

    fn entry(number: u8, peak_memory: u64) -> HistoryEntry {
        HistoryEntry {
            command_hash: command_hash(number),
            peak_memory,
        }
    }

    #[test]
    fn estimate_fallback() {
        let mut measurements = MemoryMeasurements::new(10);
        assert_eq!(
            measurements.estimate(&command_hash(1), &client(1)),
            DEFAULT_PEAK_MEMORY_ESTIMATE
        );

        measurements.record(command_hash(1), client(1), 100);
        assert_eq!(measurements.estimate(&command_hash(1), &client(1)), 100);
        // Same command from another client
        assert_eq!(measurements.estimate(&command_hash(1), &client(2)), 100);
        // Another command from the same client
        assert_eq!(measurements.estimate(&command_hash(2), &client(1)), 100);
        assert_eq!(
            measurements.estimate(&command_hash(2), &client(2)),
            DEFAULT_PEAK_MEMORY_ESTIMATE
        );

        measurements.record(command_hash(3), client(1), 300);
        assert_eq!(measurements.estimate(&command_hash(1), &client(1)), 100);
        assert_eq!(measurements.estimate(&command_hash(2), &client(1)), 300);

        measurements.record(command_hash(1), client(2), 150);
        assert_eq!(measurements.estimate(&command_hash(1), &client(1)), 150);
        assert_eq!(measurements.estimate(&command_hash(2), &client(2)), 150);
    }

    #[test]
    fn history_prefers_more_recent_entries() {
        let mut measurements = MemoryMeasurements::new(2);
        measurements.record(command_hash(1), client(1), 100);
        measurements.record(command_hash(2), client(1), 200);
        // Estimating does not update usage time
        assert_eq!(measurements.estimate(&command_hash(1), &client(9)), 100);
        measurements.record(command_hash(3), client(1), 300);

        assert_eq!(measurements.history(), vec![entry(2, 200), entry(3, 300)]);
        assert_eq!(
            measurements.estimate(&command_hash(1), &client(9)),
            DEFAULT_PEAK_MEMORY_ESTIMATE
        );

        // Recording a known command again replaces the old recorded value
        measurements.record(command_hash(2), client(1), 210);
        assert_eq!(measurements.history(), vec![entry(3, 300), entry(2, 210)]);
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
        measurements.record(command_hash(4), client(1), 400);
        save_history(&path, &measurements.history()).unwrap();
        let reloaded = load_history(&path, 10);
        assert_eq!(reloaded.history(), vec![entry(4, 400)]);
        assert_eq!(
            reloaded.estimate(&command_hash(9), &client(1)),
            DEFAULT_PEAK_MEMORY_ESTIMATE
        );
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
        measurements.record(command_hash(1), client(1), 100);
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
