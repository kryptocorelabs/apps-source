#![forbid(unsafe_code)]

//! Offline inspection and authenticated exports. Recognition alone is not authentication.
mod formats;
pub use formats::{CredentialRoute, Format};
mod recovery;
pub use recovery::{
    recover, recover_with_options, RecoveryError, RecoveryOptions, RecoverySummary,
};

use serde::Serialize;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const FOOTER: &[u8; 16] = b"KCC-WIN64-EXE-v1";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    ReadFailed,
    NotRegularFile,
    UnknownFormat,
    UnsupportedVersion,
    Truncated,
    InvalidSize,
    InvalidWrapper,
    ChangedDuringInspection,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReadFailed => "The selected file could not be read.",
            Self::NotRegularFile => "Select a regular file without links or reparse points.",
            Self::UnknownFormat => "The file does not have a supported KryptoCore format marker.",
            Self::UnsupportedVersion => "This format version or header layout is not supported.",
            Self::Truncated => "The file is shorter than the minimum structure for this format.",
            Self::InvalidSize => "The file size is outside this reader's supported limits.",
            Self::InvalidWrapper => "The embedded container length or marker is invalid.",
            Self::ChangedDuringInspection => {
                "The file changed during inspection. Use a stable copy."
            }
        })
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub schema_version: u8,
    pub format: Format,
    pub label: &'static str,
    pub file_bytes: u64,
    pub payload_offset: u64,
    pub payload_bytes: u64,
    pub credential_routes: &'static [CredentialRoute],
    pub authenticity: &'static str,
    pub data_access_available: bool,
}

/// Read only bounded markers and sizes. Does not authenticate or decrypt.
pub fn inspect(path: &Path) -> Result<Inspection, Error> {
    let original = fs::symlink_metadata(path).map_err(|_| Error::ReadFailed)?;
    if !original.is_file() || is_link(&original) {
        return Err(Error::NotRegularFile);
    }
    let mut file = File::open(path).map_err(|_| Error::ReadFailed)?;
    let before = file.metadata().map_err(|_| Error::ReadFailed)?;
    if !before.is_file() || is_link(&before) {
        return Err(Error::NotRegularFile);
    }
    let result = inspect_reader(&mut file, before.len())?;
    let after = file.metadata().map_err(|_| Error::ReadFailed)?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(Error::ChangedDuringInspection);
    }
    Ok(result)
}

fn is_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes() & 0x400 != 0;
    }
    #[cfg(not(windows))]
    false
}

fn inspect_reader(reader: &mut (impl Read + Seek), size: u64) -> Result<Inspection, Error> {
    if size < 5 {
        return Err(Error::Truncated);
    }
    let mut header = [0; 8];
    let count = size.min(8) as usize;
    reader
        .read_exact(&mut header[..count])
        .map_err(|_| Error::Truncated)?;
    if let Some(descriptor) = formats::identify(&header[..count]) {
        return describe(descriptor, size, 0, size);
    }
    if formats::has_known_family(&header[..count]) {
        return Err(Error::UnsupportedVersion);
    }
    if size < 24 {
        return Err(Error::UnknownFormat);
    }
    reader
        .seek(SeekFrom::End(-24))
        .map_err(|_| Error::ReadFailed)?;
    let mut footer = [0; 24];
    reader
        .read_exact(&mut footer)
        .map_err(|_| Error::Truncated)?;
    if &footer[8..] != FOOTER {
        return Err(Error::UnknownFormat);
    }
    let payload = u64::from_le_bytes(footer[..8].try_into().expect("fixed length field"));
    let end = size.checked_sub(24).ok_or(Error::InvalidWrapper)?;
    if payload == 0 || payload >= end {
        return Err(Error::InvalidWrapper);
    }
    let offset = end - payload;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|_| Error::ReadFailed)?;
    reader
        .read_exact(&mut header)
        .map_err(|_| Error::InvalidWrapper)?;
    let mut descriptor = formats::identify(&header).ok_or_else(|| {
        if formats::has_known_family(&header) {
            Error::UnsupportedVersion
        } else {
            Error::InvalidWrapper
        }
    })?;
    if descriptor.format != Format::ContainerV1 {
        return Err(Error::InvalidWrapper);
    }
    descriptor.format = Format::EmbeddedContainerV1;
    descriptor.label = "Embedded container / KCC v1";
    describe(descriptor, size, offset, payload)
}

fn describe(
    descriptor: formats::Descriptor,
    file: u64,
    offset: u64,
    payload: u64,
) -> Result<Inspection, Error> {
    if payload < descriptor.minimum {
        return Err(Error::Truncated);
    }
    if payload > descriptor.maximum {
        return Err(Error::InvalidSize);
    }
    Ok(Inspection {
        schema_version: 1,
        format: descriptor.format,
        label: descriptor.label,
        file_bytes: file,
        payload_offset: offset,
        payload_bytes: payload,
        credential_routes: descriptor.credentials,
        authenticity: "not_verified",
        data_access_available: false,
    })
}

#[cfg(test)]
mod tests;
