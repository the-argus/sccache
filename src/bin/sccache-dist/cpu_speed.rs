use sccache::dist::cpu_speed::{normalize_cpu_model, parse_cpu_speed_table};
use sccache::dist::{BuilderInfo, CpuSpeed};
use std::collections::HashMap;
use std::sync::LazyLock;

// generated table of relative CPU speeds
static CPU_SPEED_TABLE: LazyLock<HashMap<String, u32>> = LazyLock::new(|| {
    parse_cpu_speed_table(include_str!("cpu-speeds.tsv")).expect("Invalid CPU speed table")
});

pub fn cpu_speed_from_table(cpu_model: &str) -> Option<u32> {
    CPU_SPEED_TABLE
        .get(&normalize_cpu_model(cpu_model))
        .copied()
}

pub fn cpu_speed_of_builder(info: &BuilderInfo) -> CpuSpeed {
    match (info.configured_cpu_speed, &info.cpu_model) {
        (Some(speed), _) => CpuSpeed::Configured(speed),
        (None, Some(cpu_model)) => {
            cpu_speed_from_table(cpu_model).map_or(CpuSpeed::Unknown, CpuSpeed::Table)
        }
        (None, None) => CpuSpeed::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccache::dist::BuilderLimits;
    use sccache::dist::cpu_speed::{REFERENCE_CPU_MODEL, REFERENCE_CPU_SPEED};

    #[test]
    fn generated_table_file() {
        assert!(!CPU_SPEED_TABLE.is_empty());
    }

    #[test]
    fn model_name_matches_exactly() {
        let speed = cpu_speed_from_table(REFERENCE_CPU_MODEL);
        assert_eq!(speed, Some(REFERENCE_CPU_SPEED));
        for same in [
            "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz",
            "  Intel(R)  Core(TM) i7-8700K CPU @ 3.70GHz   ",
        ] {
            assert_eq!(cpu_speed_from_table(same), speed, "{same}");
        }

        for unknown in [
            "",
            "Epic Computer 3000",
            "Intel(R) Core(TM) i7-8700K",
            "Intel(R) Core(TM) i7-8700K CPU @ 3.80GHz",
            "intel(r) core(tm) i7-8700k cpu @ 3.70ghz",
        ] {
            assert_eq!(cpu_speed_from_table(unknown), None, "{unknown}");
        }
    }

    fn builder_info_with_cpu(
        cpu_model: Option<&str>,
        configured_cpu_speed: Option<u32>,
    ) -> BuilderInfo {
        BuilderInfo {
            name: "builder".to_owned(),
            num_cpus: 4,
            cpu_model: cpu_model.map(str::to_owned),
            configured_cpu_speed,
            limits: BuilderLimits {
                max_jobs: 4,
                max_memory: None,
            },
        }
    }

    #[test]
    fn explicitly_configured_speed_versus_estimated() {
        const KNOWN: &str = "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz";
        assert_eq!(
            cpu_speed_of_builder(&builder_info_with_cpu(Some(KNOWN), None)),
            CpuSpeed::Table(REFERENCE_CPU_SPEED)
        );
        // the estimated speed is ignored if an explicit one is provided
        assert_eq!(
            cpu_speed_of_builder(&builder_info_with_cpu(Some(KNOWN), Some(1500))),
            CpuSpeed::Configured(1500)
        );
        assert_eq!(
            cpu_speed_of_builder(&builder_info_with_cpu(
                Some("Epic Computer 3000"),
                Some(700)
            )),
            CpuSpeed::Configured(700)
        );
        assert_eq!(
            cpu_speed_of_builder(&builder_info_with_cpu(None, Some(700))),
            CpuSpeed::Configured(700)
        );
        assert_eq!(
            cpu_speed_of_builder(&builder_info_with_cpu(Some("Epic Computer 3000"), None)),
            CpuSpeed::Unknown
        );
        assert_eq!(
            cpu_speed_of_builder(&builder_info_with_cpu(None, None)),
            CpuSpeed::Unknown
        );
    }
}
