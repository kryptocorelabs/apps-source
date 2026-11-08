use crate::{Error, Result};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub const MAX_TOTAL_BYTES: u64 = 400 * 1024 * 1024;

fn enforce_size_limit(root: &Path) -> Result<()> {
    fn walk(path: &Path, depth: usize, entries: &mut usize, bytes: &mut u64) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if crate::is_link(&metadata) || (!metadata.is_file() && !metadata.is_dir()) || depth > 64 {
            return Err(Error::Format(
                "Scan refused: unsupported file, link or depth.",
            ));
        }
        *entries += 1;
        if *entries > 10_001 {
            return Err(Error::Format("Scan refused: too many entries."));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                walk(&entry?.path(), depth + 1, entries, bytes)?;
            }
        } else {
            *bytes = bytes
                .checked_add(metadata.len())
                .ok_or(Error::ScanRejected)?;
            if metadata.len() > 100 * 1024 * 1024 || *bytes > MAX_TOTAL_BYTES {
                return Err(Error::Format(
                    "Scan refused: 100 MiB per file / 400 MiB total scan limit exceeded.",
                ));
            }
        }
        Ok(())
    }
    walk(root, 0, &mut 0, &mut 0)
}

/// Inspect authenticated plaintext staging with an explicitly trusted local ClamAV binary.
pub fn inspect(root: &Path, scanner: Option<&Path>) -> Result<()> {
    inspect_with_timeout(root, scanner, Duration::from_secs(300))
}

fn inspect_with_timeout(root: &Path, scanner: Option<&Path>, timeout: Duration) -> Result<()> {
    let Some(scanner) = scanner else {
        return Ok(());
    };
    if !scanner.is_absolute() {
        return Err(Error::Format(
            "Provide the absolute path to a trusted scanner.",
        ));
    }
    enforce_size_limit(root).map_err(|error| match error {
        Error::Io(_) => Error::ScanRejected,
        other => other,
    })?;
    let mut command = Command::new(scanner);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut process = command
        .args([
            "--recursive=yes",
            "--alert-exceeds-max=yes",
            "--alert-encrypted=yes",
            "--max-filesize=100M",
            "--max-scansize=400M",
            "--max-dir-recursion=64",
            "--follow-dir-symlinks=0",
            "--follow-file-symlinks=0",
        ])
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::ScanRejected)?;
    let deadline = Instant::now() + timeout;
    loop {
        match process.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(Error::ScanRejected),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = process.kill();
                let _ = process.wait();
                return Err(Error::ScanRejected);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scanner_policy_bounds_files_and_refuses_missing_or_relative_tools() {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let file = root.join("test");
        fs::write(&file, b"synthetic").unwrap();
        assert!(inspect(&file, None).is_ok());
        assert!(inspect(&file, Some(Path::new("relative-tool"))).is_err());
        assert!(inspect(&file, Some(&root.join("missing-scanner"))).is_err());
        let large = fs::File::create(root.join("large")).unwrap();
        large.set_len(100 * 1024 * 1024 + 1).unwrap();
        assert!(enforce_size_limit(&root).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn scanner_process_detection_errors_timeout_and_links_fail_closed() {
        use std::os::unix::{fs::symlink, fs::PermissionsExt};
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let data = root.join("plain");
        fs::write(&data, b"synthetic").unwrap();
        for (status, ok) in [(0, true), (1, false), (2, false)] {
            let tool = root.join(format!("scanner-{status}"));
            fs::write(&tool, format!("#!/bin/sh\nexit {status}\n")).unwrap();
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(inspect(&data, Some(&tool)).is_ok(), ok);
        }
        let hang = root.join("scanner-timeout");
        fs::write(&hang, b"#!/bin/sh\nwhile :; do :; done\n").unwrap();
        fs::set_permissions(&hang, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(inspect_with_timeout(&data, Some(&hang), Duration::from_millis(20)).is_err());
        let link = root.join("linked");
        symlink(&data, &link).unwrap();
        assert!(enforce_size_limit(&link).is_err());
    }
}
