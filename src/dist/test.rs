use crate::dist::{ProcessOutput, Toolchain};
use crate::util::Digest;

fn roundtrip(archive_id: &str) -> bincode::Result<Toolchain> {
    let tc = Toolchain {
        archive_id: archive_id.to_owned(),
    };
    bincode::deserialize(&bincode::serialize(&tc).unwrap())
}

#[test]
fn test_toolchain_archive_id_digest_accepted() {
    let archive_id = Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    assert_eq!(roundtrip(&archive_id).unwrap().archive_id, archive_id);
    assert_eq!(
        roundtrip(&archive_id.to_uppercase()).unwrap().archive_id,
        archive_id
    );
}

#[test]
fn test_toolchain_archive_id_non_digest_rejected() {
    let digest = Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    for archive_id in [
        "",
        "a",
        "/tmp/toolchain",
        "../toolchain",
        &digest[1..],
        &format!("{digest}0"),
        &format!("/{}", &digest[1..]),
    ] {
        assert!(roundtrip(archive_id).is_err(), "accepted {archive_id:?}");
    }
}

#[test]
fn test_process_output_exit_code_is_kept() {
    let output: std::process::Output =
        ProcessOutput::fake_output(1, b"out".to_vec(), b"err".to_vec()).into();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(output.status.signal(), None);
    }
}

// A remote compile that fails with an exit code reached the client as "killed by signal <code>".
#[cfg(unix)]
#[test]
fn test_process_output_roundtrip_is_not_a_signal() {
    use std::os::unix::process::ExitStatusExt;
    for code in [0, 1, 2, 127] {
        let compiled = std::process::Output {
            status: crate::util::exit_status_from_code(code),
            stdout: vec![],
            stderr: vec![],
        };
        let received: std::process::Output = ProcessOutput::try_from(compiled).unwrap().into();
        assert_eq!(received.status.code(), Some(code), "exit code {code}");
        assert_eq!(received.status.signal(), None, "exit code {code}");
    }
}

#[cfg(feature = "dist-client")]
#[test]
fn command_hash_for_memory_prediction_depends_on_the_command_but_not_environment_variable() {
    use crate::dist::{CommandHash, CompileCommand};

    let command = CompileCommand {
        executable: "/usr/bin/gcc".to_owned(),
        arguments: vec!["-c".to_owned(), "/src/a.c".to_owned()],
        env_vars: vec![("LANG".to_owned(), "C".to_owned())],
        cwd: "/build".to_owned(),
    };
    let toolchain = Toolchain {
        archive_id: Digest::reader_sync(&b"toolchain archive"[..]).unwrap(),
    };
    let hash = CommandHash::new(&command, &toolchain).unwrap();
    assert_eq!(
        CommandHash::new(&command.clone(), &toolchain).unwrap(),
        hash
    );

    let mut changed = vec![command.clone(); 3];
    changed[0].executable = "/usr/bin/cc".to_owned();
    changed[1].arguments.push("-O2".to_owned());
    changed[2].cwd = "/build2".to_owned();
    for changed in changed {
        assert_ne!(CommandHash::new(&changed, &toolchain).unwrap(), hash);
    }
    // The environment is not part of the hash.
    let mut other_environment = command.clone();
    other_environment.env_vars[0].1 = "en_US.UTF-8".to_owned();
    other_environment
        .env_vars
        .push(("MAKEFLAGS".to_owned(), "-j8".to_owned()));
    assert_eq!(
        CommandHash::new(&other_environment, &toolchain).unwrap(),
        hash
    );

    // different arguments give a differnet hash
    let mut shifted = command.clone();
    shifted.executable = "/usr/bin/gcc-c".to_owned();
    shifted.arguments.remove(0);
    assert_ne!(CommandHash::new(&shifted, &toolchain).unwrap(), hash);

    let other_toolchain = Toolchain {
        archive_id: Digest::reader_sync(&b"other archive"[..]).unwrap(),
    };
    assert_ne!(CommandHash::new(&command, &other_toolchain).unwrap(), hash);

    let roundtrip: CommandHash =
        serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
    assert_eq!(roundtrip, hash);
    assert!(serde_json::from_str::<CommandHash>(r#""not a hash""#).is_err());
}
