// Generates a file with a table of relative CPU speeds based on model name
// from Blender Open Data https://opendata.blender.org
//
// Processors are judged by speed when all cores are occupied

use anyhow::{Context, Result, bail};
use sccache::dist::cpu_speed::{REFERENCE_CPU_MODEL, REFERENCE_CPU_SPEED, normalize_cpu_model};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

const SCENES_PER_BENCHMARK_RUN: usize = 3;
// ignore CPUs that don't have many samples
const MIN_RECORDS_PER_CPU: usize = 2 * SCENES_PER_BENCHMARK_RUN;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Metric {
    RenderTime,
    SamplesPerMinute,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MeasurementGroup {
    blender_version: String,
    scene: String,
    metric: Metric,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CpuTableEntry {
    cpu_model: String,
    group: MeasurementGroup,
}

#[derive(Debug, PartialEq)]
struct Measurement {
    cell: CpuTableEntry,
    log_speed_per_core: f64,
}

fn is_generic_cpu_model(cpu_model: &str) -> bool {
    [
        "AMD EPYC",
        "Apple processor",
        "Apple Silicon",
        "Apple silicon",
    ]
    .contains(&cpu_model)
}

fn is_virtual_machine_cpu_model(cpu_model: &str) -> bool {
    let lowercase = cpu_model.to_ascii_lowercase();
    let has_digit_wildcard = cpu_model
        .as_bytes()
        .windows(3)
        .any(|window| window[0].is_ascii_digit() && &window[1..] == b"xx");
    ["virtual", "qemu", "kvm"]
        .iter()
        .any(|word| lowercase.contains(word))
        || [
            "Intel Core Processor (",
            "Intel Xeon Processor (",
            "Intel Atom Processor (",
            "AMD EPYC Processor",
            "AMD EPYC-",
            "Hygon Dhyana Processor",
        ]
        .iter()
        .any(|prefix| cpu_model.starts_with(prefix))
        || has_digit_wildcard
}

fn try_get_u64(value: Option<&Value>) -> Option<u64> {
    value?.as_u64().filter(|&value| value > 0)
}

fn try_get_positive_f64(value: Option<&Value>) -> Option<f64> {
    value?.as_f64().filter(|&value| value > 0.0)
}

fn parse_measurement_from_json(record: &Value) -> Option<Measurement> {
    let device_info = record.get("device_info")?.as_object()?;
    let system_info = record.get("system_info")?.as_object()?;
    let stats = record.get("stats")?.as_object()?;
    let blender_version = record.get("blender_version")?.as_object()?;
    let scene = record.get("scene")?.as_object()?;
    if device_info.get("device_type")?.as_str()? != "CPU" {
        return None;
    }
    let first_device = device_info.get("compute_devices")?.as_array()?.first()?;
    let cpu_model = match first_device {
        Value::Object(device) => device.get("name")?,
        device => device,
    }
    .as_str()?;
    if !cpu_model.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
        return None;
    }
    let cpu_model = normalize_cpu_model(cpu_model);
    if cpu_model.is_empty()
        || is_generic_cpu_model(&cpu_model)
        || is_virtual_machine_cpu_model(&cpu_model)
    {
        return None;
    }

    let cores = try_get_u64(system_info.get("num_cpu_cores"))?;
    let threads = try_get_u64(system_info.get("num_cpu_threads"))?;
    if device_info.get("num_cpu_threads")?.as_f64()? != threads as f64 {
        // render didnt use all threads so the benchmark is inconclusive
        return None;
    }
    if !(cores <= threads && threads <= 2 * cores) {
        return None;
    }

    let blender_version = blender_version.get("version")?.as_str()?;
    let scene = scene.get("label")?.as_str()?;
    let (measure, log_speed) = match try_get_positive_f64(stats.get("samples_per_minute")) {
        Some(samples_per_minute) => (Metric::SamplesPerMinute, samples_per_minute.ln()),
        None => {
            let render_time = try_get_positive_f64(stats.get("render_time_no_sync"))
                .or_else(|| try_get_positive_f64(stats.get("total_render_time")))?;
            (Metric::RenderTime, -render_time.ln())
        }
    };
    Some(Measurement {
        cell: CpuTableEntry {
            cpu_model,
            group: MeasurementGroup {
                blender_version: blender_version.to_owned(),
                scene: scene.to_owned(),
                metric: measure,
            },
        },
        log_speed_per_core: log_speed - (cores as f64).ln(),
    })
}

fn ascii_contains_cpu(line: &[u8]) -> bool {
    line.windows(5).any(|window| window == b"\"CPU\"")
}

fn parse_measurements_from_line(line: &[u8]) -> Vec<Measurement> {
    let Ok(document) = serde_json::from_slice::<Value>(line) else {
        return vec![];
    };
    match document.get("data") {
        Some(Value::Array(records)) => records
            .iter()
            .filter_map(parse_measurement_from_json)
            .collect(),
        Some(record @ Value::Object(_)) => {
            parse_measurement_from_json(record).into_iter().collect()
        }
        _ => vec![],
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        values[middle]
    } else {
        (values[middle - 1] + values[middle]) / 2.0
    }
}

// for each cpu table entry, for each of its measured speeds, find the median
// returns (mostly) the same datastructure but with the Vec<f64> flattened into
// single f64 median.
// This also filters out CPUs that have fewer than MIN_RECORDS_PER_CPU samples,
// which is why the data structure is not exactly the same
fn find_measurement_medians_per_cpu(
    measurements_per_cpu: BTreeMap<CpuTableEntry, Vec<f64>>,
) -> BTreeMap<CpuTableEntry, f64> {
    let mut num_measurements_per_cpu = BTreeMap::<String, usize>::new();
    for (cell, values) in &measurements_per_cpu {
        *num_measurements_per_cpu
            .entry(cell.cpu_model.clone())
            .or_default() += values.len();
    }
    measurements_per_cpu
        .into_iter()
        .filter(|(cell, _)| num_measurements_per_cpu[&cell.cpu_model] >= MIN_RECORDS_PER_CPU)
        .map(|(cell, values)| (cell, median(values)))
        .collect()
}

// returns each cpu and its median measured speed
fn try_parse_measurements_jsonfile(jsonl: impl BufRead) -> Result<BTreeMap<CpuTableEntry, f64>> {
    let mut measurements_per_cpu = BTreeMap::<CpuTableEntry, Vec<f64>>::new();
    for line in jsonl.split(b'\n') {
        let line = line.context("Failed to read the snapshot")?;
        if !ascii_contains_cpu(&line) {
            continue;
        }
        for measurement in parse_measurements_from_line(&line) {
            measurements_per_cpu
                .entry(measurement.cell)
                .or_default()
                .push(measurement.log_speed_per_core);
        }
    }
    Ok(find_measurement_medians_per_cpu(measurements_per_cpu))
}

// given the result of try_parse_measurements_jsonfile (CPU entry and its median measured speed),
// take all the ones that are in the same group as the (a) reference CPU, with the same CPU model
// name as each other, and tae all of their relative speeds and create a score value which describes
// the relative speed of the given CPU model.
// returns a map of cpu model names to the relative speed score.
fn relative_speeds(cells: &BTreeMap<CpuTableEntry, f64>) -> BTreeMap<String, u32> {
    let mut cpu_model_name_to_relative_speeds = BTreeMap::<&String, Vec<f64>>::new();
    for (cell, log_speed_per_core) in cells {
        let reference_cell = CpuTableEntry {
            cpu_model: REFERENCE_CPU_MODEL.to_owned(),
            group: cell.group.clone(),
        };
        if let Some(reference_cpu_median_speed) = cells.get(&reference_cell) {
            cpu_model_name_to_relative_speeds
                .entry(&cell.cpu_model)
                .or_default()
                .push(log_speed_per_core - reference_cpu_median_speed);
        }
    }
    cpu_model_name_to_relative_speeds
        .into_iter()
        .map(|(cpu_model, relative_speeds)| {
            let speed =
                (f64::from(REFERENCE_CPU_SPEED) * median(relative_speeds).exp()).round_ties_even();
            (cpu_model.clone(), speed as u32)
        })
        .collect()
}

// Also see: sccache::dist::cpu_speed::parse_cpu_speed_table() in cpu_speed.rs
fn format_cpu_speed_table(header: &[String], speeds: &BTreeMap<String, u32>) -> String {
    let mut table = String::new();
    for line in header {
        table.push_str(&format!("# {line}\n"));
    }
    for (cpu_model, speed) in speeds {
        table.push_str(&format!("{speed}\t{cpu_model}\n"));
    }
    table
}

fn format_cpu_speed_table_with_header(
    jsonl_name: &str,
    cells: &BTreeMap<CpuTableEntry, f64>,
) -> String {
    let header = [
        "Relative speed per core of CPUs by model name, generated by ".to_owned(),
        "examples/cpu-speeds.rs from Blender Open Data (https://opendata.blender.org), ".to_owned(),
        format!("specifically from {jsonl_name}. To regenerate this file run the following:"),
        "  curl -LO https://opendata.blender.org/snapshots/opendata-latest.zip".to_owned(),
        "  unzip opendata-latest.zip".to_owned(),
        "  cargo run --locked --release --features dist-server --example cpu-speeds -- \\"
            .to_owned(),
        "      opendata-*.jsonl > src/bin/sccache-dist/cpu-speeds.tsv".to_owned(),
        format!(
            "We use {REFERENCE_CPU_MODEL} as a reference, it always gets a score of {REFERENCE_CPU_SPEED}"
        ),
    ];
    format_cpu_speed_table(&header, &relative_speeds(cells))
}

fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [jsonl_path] = &arguments[..] else {
        bail!("Usage: cpu-speeds <blender opendata .jsonl file>")
    };
    let jsonl = File::open(jsonl_path).with_context(|| format!("Failed to open {jsonl_path}"))?;
    let jsonl_name = Path::new(jsonl_path)
        .file_name()
        .context("The snapshot path has no file name")?
        .to_string_lossy();
    let cells = try_parse_measurements_jsonfile(BufReader::new(jsonl))?;
    io::stdout().write_all(format_cpu_speed_table_with_header(&jsonl_name, &cells).as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use sccache::dist::cpu_speed::parse_cpu_speed_table;
    use serde_json::json;
    use std::collections::HashMap;

    fn dummy_json() -> Value {
        json!({
            "blender_version": {"version": "4.5.0"},
            "device_info": {
                "device_type": "CPU",
                "num_cpu_threads": 16,
                "compute_devices": [{"name": "AMD Ryzen 7 5800X 8-Core Processor ", "type": "CPU"}],
            },
            "scene": {"label": "monster"},
            "stats": {"samples_per_minute": 200.0, "total_render_time": 31.0},
            "system_info": {"num_cpu_cores": 8, "num_cpu_threads": 16, "num_cpu_sockets": 1},
        })
    }

    fn dummy_cpu_table_entry() -> CpuTableEntry {
        CpuTableEntry {
            cpu_model: "AMD Ryzen 7 5800X 8-Core Processor".to_owned(),
            group: MeasurementGroup {
                blender_version: "4.5.0".to_owned(),
                scene: "monster".to_owned(),
                metric: Metric::SamplesPerMinute,
            },
        }
    }

    fn make_cpu_table_entry(cpu_model: &str, group_name: &str) -> CpuTableEntry {
        CpuTableEntry {
            cpu_model: cpu_model.to_owned(),
            group: MeasurementGroup {
                blender_version: group_name.to_owned(),
                scene: "scene".to_owned(),
                metric: Metric::RenderTime,
            },
        }
    }

    #[test]
    fn speed_appears_to_be_measured_per_core() {
        let measurement = parse_measurement_from_json(&dummy_json()).unwrap();
        assert_eq!(measurement.cell, dummy_cpu_table_entry());
        assert!((measurement.log_speed_per_core - (200.0f64 / 8.0).ln()).abs() < 1e-12);

        let mut json = dummy_json();
        json["stats"] = json!({"render_time_no_sync": 100.0, "total_render_time": 101.0});
        json["device_info"]["compute_devices"] =
            json!(["Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"]);
        json["system_info"] =
            json!({"num_cpu_cores": 28, "num_cpu_threads": 28, "num_cpu_sockets": 2});
        json["device_info"]["num_cpu_threads"] = json!(28);
        let measurement = parse_measurement_from_json(&json).unwrap();
        assert_eq!(
            measurement.cell.cpu_model,
            "Intel Xeon CPU E5-2680 v4 @ 2.40GHz"
        );
        assert_eq!(measurement.cell.group.metric, Metric::RenderTime);
        assert!((measurement.log_speed_per_core - (-(100.0f64 * 28.0).ln())).abs() < 1e-12);
    }

    // just test that bad data seems to be skipped, maybe the user will try to
    // use this one something other than blender opendata
    #[test]
    fn invalid_weird_cpunames() {
        let changes: [(&str, Value); 7] = [
            ("/device_info/device_type", json!("OPTIX")),
            ("/device_info/num_cpu_threads", json!(8)),
            (
                "/device_info/compute_devices/0/name",
                json!("QEMU Virtual CPU version 2.5+"),
            ),
            (
                "/device_info/compute_devices/0/name",
                json!("AMD Ryzen\u{7f}"),
            ),
            ("/system_info/num_cpu_cores", json!(4)),
            ("/system_info/num_cpu_cores", json!(8.0)),
            (
                "/stats",
                json!({"samples_per_minute": 0, "total_render_time": -1}),
            ),
        ];
        for (pointer, value) in changes {
            let mut json = dummy_json();
            *json.pointer_mut(pointer).unwrap() = value;
            assert_eq!(parse_measurement_from_json(&json), None, "{pointer}");
        }
        assert_eq!(parse_measurement_from_json(&json!("not a record")), None);
    }

    #[test]
    fn virtual_machine_and_generic_cpumodels() {
        for virtual_machine in [
            "QEMU Virtual CPU version 2.5+",
            "Common KVM processor",
            "Virtual CPU @ 3.41GHz",
            "VirtualApple @ 2.50GHz",
            "Intel Core Processor (Haswell, no TSX)",
            "Intel Core Processor (Broadwell, no TSX, IBRS)",
            "Intel Xeon Processor (Cascadelake)",
            "Intel Xeon Processor (Icelake)",
            "Intel Xeon Processor (Skylake, IBRS)",
            "Intel Atom Processor (Denverton)",
            "Intel Xeon E312xx (Sandy Bridge)",
            "Intel Xeon E3-12xx v2 (Ivy Bridge, IBRS)",
            "Intel Core 2 Duo P9xxx (Penryn Class Core 2)",
            "Intel Core i7 9xx (Nehalem Class Core i7)",
            "Westmere E56xx/L56xx/X56xx (Nehalem-C)",
            "AMD Opteron 63xx class CPU",
            "AMD EPYC Processor",
            "AMD EPYC Processor (with IBPB)",
            "AMD EPYC-Rome Processor",
            "AMD EPYC-Rome-v4 Processor (no XSAVES)",
            "AMD EPYC-Milan Processor",
            "AMD EPYC-Genoa Processor",
            "Hygon Dhyana Processor",
        ] {
            assert!(
                is_virtual_machine_cpu_model(virtual_machine),
                "{virtual_machine}"
            );
        }
        for generic in ["AMD EPYC", "Apple processor", "Apple Silicon"] {
            assert!(is_generic_cpu_model(generic), "{generic}");
        }
        for hardware in [
            "Intel Core i7-8700K CPU @ 3.70GHz",
            "Intel Xeon Gold 6342 CPU @ 2.80GHz",
            "INTEL XEON GOLD 6542Y",
            "Intel Core Ultra 9 285K",
            "Intel Xeon CPU X5690 @ 3.47GHz",
            "AMD EPYC 7763 64-Core Processor",
            "AMD EPYC 7R13 Processor",
            "AMD Opteron Processor 6272",
            "AMD Ryzen 9 9950X3D 16-Core Processor",
            "Hygon C86-4G (OPN:3490)",
            "Apple M1",
            "Snapdragon X Plus (8-core) @ 3.30 GHz",
        ] {
            assert!(
                !is_virtual_machine_cpu_model(hardware) && !is_generic_cpu_model(hardware),
                "{hardware}"
            );
        }
    }

    #[test]
    fn line_items_get_read_smoketest() {
        let line =
            serde_json::to_vec(&json!({"data": [dummy_json(), dummy_json(), "text"]})).unwrap();
        assert!(ascii_contains_cpu(&line));
        assert_eq!(parse_measurements_from_line(&line).len(), 2);
        let line = serde_json::to_vec(&json!({"data": dummy_json()})).unwrap();
        assert_eq!(parse_measurements_from_line(&line).len(), 1);
        assert!(parse_measurements_from_line(b"{not json").is_empty());
    }

    #[test]
    fn medians_skips_cpus_with_very_few_measurements() {
        let cpu_table = BTreeMap::from([
            (make_cpu_table_entry("few", "a"), vec![1.0, 2.0]),
            (make_cpu_table_entry("few", "b"), vec![1.0, 2.0, 3.0]),
            (make_cpu_table_entry("many", "a"), vec![1.0, 5.0, 2.0, 4.0]),
            (make_cpu_table_entry("many", "b"), vec![3.0, 1.0, 2.0]),
        ]);
        assert_eq!(
            find_measurement_medians_per_cpu(cpu_table),
            BTreeMap::from([
                (make_cpu_table_entry("many", "a"), 3.0),
                (make_cpu_table_entry("many", "b"), 2.0)
            ])
        );
    }

    #[test]
    fn parse_json_to_line_items_to_cpu_table_smoketest() {
        let mut jsonl = vec![];
        for _ in 0..MIN_RECORDS_PER_CPU {
            jsonl.extend(serde_json::to_vec(&json!({"data": [dummy_json()]})).unwrap());
            jsonl.push(b'\n');
        }
        jsonl.extend(b"{\"data\": \"no CPU here\"}\n");
        let cells = try_parse_measurements_jsonfile(&jsonl[..]).unwrap();
        assert_eq!(cells.len(), 1);
        assert!((cells[&dummy_cpu_table_entry()] - (200.0f64 / 8.0).ln()).abs() < 1e-12);
    }

    #[test]
    fn speeds_are_relative_to_cpu_reference_model() {
        let cells = BTreeMap::from([
            (make_cpu_table_entry(REFERENCE_CPU_MODEL, "a"), 1.0),
            (make_cpu_table_entry(REFERENCE_CPU_MODEL, "b"), -2.0),
            (make_cpu_table_entry(REFERENCE_CPU_MODEL, "c"), 5.0),
            (make_cpu_table_entry("Fast", "a"), 1.5),
            (make_cpu_table_entry("Fast", "b"), -1.5),
            // test outliers in the groups
            (make_cpu_table_entry("Fast", "c"), 0.0),
            (make_cpu_table_entry("Slow", "b"), -2.3),
            // test not having a reference cpu
            (make_cpu_table_entry("Slow", "d"), 9.0),
            (make_cpu_table_entry("Alone", "d"), 1.0),
        ]);
        let table = format_cpu_speed_table_with_header("snapshot.jsonl", &cells);
        let speeds = parse_cpu_speed_table(&table).unwrap();
        assert_eq!(
            speeds,
            HashMap::from([
                (REFERENCE_CPU_MODEL.to_owned(), REFERENCE_CPU_SPEED),
                ("Fast".to_owned(), 1649),
                ("Slow".to_owned(), 741),
            ])
        );
    }

    #[test]
    fn table_save_and_load() {
        let speeds = BTreeMap::from([
            (REFERENCE_CPU_MODEL.to_owned(), REFERENCE_CPU_SPEED),
            ("AMD Ryzen 9 5950X 16-Core Processor".to_owned(), 1224),
        ]);
        let table = format_cpu_speed_table(&["first".to_owned(), "second".to_owned()], &speeds);
        assert_eq!(
            table,
            "# first\n# second\n1224\tAMD Ryzen 9 5950X 16-Core Processor\n1000\tIntel Core i7-8700K CPU @ 3.70GHz\n"
        );
        assert_eq!(
            parse_cpu_speed_table(&table).unwrap(),
            speeds.into_iter().collect::<HashMap<_, _>>()
        );
    }
}
