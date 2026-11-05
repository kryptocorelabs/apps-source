use crate::{Error, Result};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn enforce_size_limit(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            enforce_size_limit(&entry.path())?;
        } else if metadata.len() > 100 * 1024 * 1024 {
            return Err(Error::Format(
                "Scan refused: a file exceeds the 100 MiB scan limit.",
            ));
        }
    }
    Ok(())
}

/// Inspect an authenticated extraction staging directory with a trusted ClamAV binary.
pub fn inspect(root: &Path, scanner: Option<&Path>) -> Result<()> {
    let Some(scanner) = scanner else {
        return Ok(());
    };
    if !scanner.is_absolute() {
        return Err(Error::Format(
            "Provide the absolute path to a trusted scanner.",
        ));
    }
    enforce_size_limit(root)?;
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
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(300);
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
