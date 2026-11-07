use crate::{inspect, CredentialRoute, Format};
use serde::Serialize;
use std::{fs, io::Write, path::Path};
use tempfile::NamedTempFile;

#[derive(Debug, Eq, PartialEq)]
pub enum RecoveryError {
    Unsupported,
    Credential,
    InvalidSource,
    InvalidDestination,
    AuthenticationOrData,
    WriteFailed,
    PlaintextNotConfirmed,
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "Recovery for this format is not implemented.",
            Self::Credential => "Select a supported credential and enter 1 to 1024 UTF-8 bytes.",
            Self::InvalidSource => "The source is not a supported regular file.",
            Self::InvalidDestination => {
                "Choose a new destination in an existing trusted folder without links."
            }
            Self::AuthenticationOrData => {
                "Wrong credential, damaged data, or invalid contents. No output was published."
            }
            Self::WriteFailed => {
                "Output could not be completed. Check the destination and free space."
            }
            Self::PlaintextNotConfirmed => "Explicit confirmation of plaintext output is required.",
        })
    }
}
impl std::error::Error for RecoveryError {}

#[derive(Debug, Serialize)]
pub struct RecoverySummary {
    pub schema_version: u8,
    pub format: Format,
    pub content_authenticated: bool,
    pub entries: usize,
    pub bytes: u64,
}

/// Authenticate with the original format reader, then publish a fresh plaintext
/// destination. The source is never reset, migrated or written. No secret or
/// record contents are returned in the summary. The parent must be trusted.
pub fn recover(
    input: &Path,
    output: &Path,
    route: CredentialRoute,
    secret: &[u8],
    confirm_plaintext: bool,
) -> Result<RecoverySummary, RecoveryError> {
    if !confirm_plaintext {
        return Err(RecoveryError::PlaintextNotConfirmed);
    }
    if secret.is_empty() || secret.len() > 1024 {
        return Err(RecoveryError::Credential);
    }
    let source = inspect(input).map_err(|_| RecoveryError::InvalidSource)?;
    if !source.credential_routes.contains(&route) {
        return Err(RecoveryError::Credential);
    }
    if !matches!(
        source.format,
        Format::VaultV1 | Format::VaultV2 | Format::ContainerV1 | Format::EmbeddedContainerV1
    ) {
        return Err(RecoveryError::Unsupported);
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Reject linked/reparse ancestors for output. No overwrite, including dangling links.
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| RecoveryError::InvalidDestination)?;
        if !metadata.is_dir() || crate::is_link(&metadata) {
            return Err(RecoveryError::InvalidDestination);
        }
    }
    if output.file_name().is_none() || fs::symlink_metadata(output).is_ok() {
        return Err(RecoveryError::InvalidDestination);
    }
    let (entries, bytes) = match source.format {
        Format::VaultV1 | Format::VaultV2 => {
            let plaintext = match route {
                CredentialRoute::Password => kryptocore_vault_format::open(input, secret),
                CredentialRoute::RecoveryKey => {
                    kryptocore_vault_format::open_with_recovery(input, secret)
                }
                _ => return Err(RecoveryError::Credential),
            }
            .map_err(|_| RecoveryError::AuthenticationOrData)?;
            let records: Vec<kryptocore_vault_format::Login> =
                serde_json::from_slice(&plaintext)
                    .map_err(|_| RecoveryError::AuthenticationOrData)?;
            let mut temporary =
                NamedTempFile::new_in(parent).map_err(|_| RecoveryError::WriteFailed)?;
            temporary
                .write_all(&plaintext)
                .map_err(|_| RecoveryError::WriteFailed)?;
            temporary
                .as_file()
                .sync_all()
                .map_err(|_| RecoveryError::WriteFailed)?;
            temporary
                .persist_noclobber(output)
                .map_err(|_| RecoveryError::WriteFailed)?;
            (records.len(), plaintext.len() as u64)
        }
        Format::ContainerV1 | Format::EmbeddedContainerV1 => {
            let result = if source.format == Format::ContainerV1 {
                kryptocore_container::unpack(input, output, secret)
            } else {
                kryptocore_container::unpack_executable_with_inspection(
                    input,
                    output,
                    secret,
                    |_| Ok(()),
                )
            }
            .map_err(|error| match error {
                kryptocore_container::Error::Io(_) => RecoveryError::WriteFailed,
                _ => RecoveryError::AuthenticationOrData,
            })?;
            (result.entries, result.bytes)
        }
        _ => return Err(RecoveryError::Unsupported),
    };
    Ok(RecoverySummary {
        schema_version: 1,
        format: source.format,
        content_authenticated: true,
        entries,
        bytes,
    })
}

#[cfg(test)]
mod tests;
