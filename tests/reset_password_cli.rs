//! End-to-end coverage of `reset-password`'s PIN rotation and its scripting flags
//! (`--new-pin`, `--quiet`, `--env-file`), run against the real built binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qiui-server")
}

/// A fresh data directory under the OS temp dir, unique per test run.
fn temp_data_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qiui-cli-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(data_dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.arg("--data-dir").arg(data_dir).args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run qiui-server binary")
}

fn init(data_dir: &Path, password: &str, pin: &str) {
    let out = run(data_dir, &["init"], &[("QIUI_KEYHOLDER_PASSWORD", password), ("QIUI_RECOVERY_PIN", pin)]);
    assert!(out.status.success(), "init failed: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn quiet_reset_prints_only_the_new_pin_and_retires_the_old_one() {
    let dir = temp_data_dir("quiet-generated");
    init(&dir, "a very long demo passphrase", "123456");

    let out = run(
        &dir,
        &["reset-password", "--quiet"],
        &[("QIUI_RECOVERY_PIN", "123456"), ("QIUI_NEW_PASSWORD", "a second long passphrase")],
    );
    assert!(out.status.success(), "reset failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stderr.is_empty(), "stderr should be silent on success: {:?}", String::from_utf8_lossy(&out.stderr));

    let new_pin = String::from_utf8(out.stdout).unwrap();
    let new_pin = new_pin.trim();
    assert_eq!(new_pin.len(), 10, "generated PIN should be 10 digits, got {new_pin:?}");
    assert!(new_pin.bytes().all(|b| b.is_ascii_digit()), "generated PIN should be all digits, got {new_pin:?}");

    // The retired PIN can no longer authorise a reset.
    let reuse = run(
        &dir,
        &["reset-password", "--quiet"],
        &[("QIUI_RECOVERY_PIN", "123456"), ("QIUI_NEW_PASSWORD", "a third long passphrase!!")],
    );
    assert!(!reuse.status.success(), "the retired PIN should not work a second time");
    assert!(String::from_utf8_lossy(&reuse.stderr).contains("not correct"));

    // The freshly generated PIN does work.
    let follow_up = run(
        &dir,
        &["reset-password", "--quiet"],
        &[("QIUI_RECOVERY_PIN", new_pin), ("QIUI_NEW_PASSWORD", "a fourth long passphrase!!"), ("QIUI_NEW_PIN", "999888777")],
    );
    assert!(follow_up.status.success(), "reset with the generated PIN failed: {}", String::from_utf8_lossy(&follow_up.stderr));
    assert!(follow_up.stdout.is_empty(), "--quiet with --new-pin should print nothing on success");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn quiet_reset_with_explicit_new_pin_prints_nothing() {
    let dir = temp_data_dir("quiet-explicit");
    init(&dir, "a very long demo passphrase", "654321");

    let out = run(
        &dir,
        &["reset-password", "--quiet"],
        &[("QIUI_RECOVERY_PIN", "654321"), ("QIUI_NEW_PASSWORD", "another long passphrase"), ("QIUI_NEW_PIN", "111222333")],
    );
    assert!(out.status.success(), "reset failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "nothing new to report when the PIN was chosen explicitly");
    assert!(out.stderr.is_empty());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_file_gets_the_new_credentials_with_restrictive_permissions() {
    let dir = temp_data_dir("env-file");
    init(&dir, "a very long demo passphrase", "424242");
    let env_path = dir.join("new_creds.env");

    let out = run(
        &dir,
        &["reset-password", "--quiet", "--env-file", env_path.to_str().unwrap()],
        &[("QIUI_RECOVERY_PIN", "424242"), ("QIUI_NEW_PASSWORD", "the new keyholder passphrase")],
    );
    assert!(out.status.success(), "reset failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "--quiet with --env-file should print nothing on success");

    let contents = std::fs::read_to_string(&env_path).unwrap();
    assert!(contents.contains("QIUI_KEYHOLDER_PASSWORD=the new keyholder passphrase"), "{contents}");
    let pin_line = contents.lines().find(|l| l.starts_with("QIUI_RECOVERY_PIN=")).unwrap_or_else(|| panic!("{contents}"));
    let written_pin = pin_line.trim_start_matches("QIUI_RECOVERY_PIN=");
    assert_eq!(written_pin.len(), 10);
    assert!(written_pin.bytes().all(|b| b.is_ascii_digit()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credentials file should not be group/world readable");
    }

    // The env file's PIN actually works for the next reset (round-trip check).
    let follow_up = run(
        &dir,
        &["reset-password", "--quiet"],
        &[("QIUI_RECOVERY_PIN", written_pin), ("QIUI_NEW_PASSWORD", "yet another long passphrase!!")],
    );
    assert!(follow_up.status.success(), "the env-file PIN should work: {}", String::from_utf8_lossy(&follow_up.stderr));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_file_without_quiet_still_prints_the_status_lines() {
    let dir = temp_data_dir("env-file-verbose");
    init(&dir, "a very long demo passphrase", "808080");
    let env_path = dir.join("new_creds.env");

    let out = run(
        &dir,
        &["reset-password", "--env-file", env_path.to_str().unwrap()],
        &[("QIUI_RECOVERY_PIN", "808080"), ("QIUI_NEW_PASSWORD", "a fresh long passphrase here")],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Password reset."));
    assert!(stdout.contains(&format!("Wrote the new password and recovery PIN to {}", env_path.display())));
    // The PIN itself must not leak to stdout when it's going to the file.
    assert!(!stdout.contains("New recovery PIN:"));

    std::fs::remove_dir_all(&dir).ok();
}

/// A basic sanity check that a bogus file handle doesn't silently succeed (e.g. an unwritable path).
#[test]
fn env_file_write_failure_is_reported() {
    let dir = temp_data_dir("env-file-bad-path");
    init(&dir, "a very long demo passphrase", "112233");
    let bad_path = dir.join("no-such-directory").join("creds.env");

    let out = run(
        &dir,
        &["reset-password", "--env-file", bad_path.to_str().unwrap()],
        &[("QIUI_RECOVERY_PIN", "112233"), ("QIUI_NEW_PASSWORD", "a long enough passphrase!!")],
    );
    assert!(!out.status.success(), "writing to a nonexistent directory should fail, not succeed silently");

    std::fs::remove_dir_all(&dir).ok();
}
