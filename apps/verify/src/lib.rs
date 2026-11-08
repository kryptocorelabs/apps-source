//! Offline release verification. Trust is an explicit caller input, never a
//! public key accepted from the download being checked. No downloads/execution.
#![forbid(unsafe_code)]

pub mod keys;
use kryptocore_signatures::{verify, Purpose, Signature, SigningKey, VerificationKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub type Result<T> = std::result::Result<T, &'static str>;
pub const MAX_MANIFEST: u64 = 128 * 1024;
pub const MAX_ARTIFACT: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema: String,
    pub product: String,
    pub version: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub source_commit: String,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub file: String,
    pub target: String,
    pub length: u64,
    pub sha256: String,
}

pub struct Expected<'a> {
    pub product: &'a str,
    pub version: &'a str,
    pub target: &'a str,
    pub min_sequence: u64,
    pub now: u64,
}

fn label(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
}

fn hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ReleaseManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "kryptocore-release/v1"
            || !label(&self.product, 64)
            || !label(&self.version, 64)
            || self.sequence == 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 366 * 86400
            || !(hex(&self.source_commit, 40) || hex(&self.source_commit, 64))
            || self.artifacts.is_empty()
            || self.artifacts.len() > 64
        {
            return Err("Unsupported or invalid release manifest");
        }
        let mut names = std::collections::HashSet::new();
        for item in &self.artifacts {
            if !label(&item.file, 180)
                || matches!(item.file.as_str(), "." | "..")
                || !label(&item.target, 64)
                || !hex(&item.sha256, 64)
                || item.length == 0
                || item.length > MAX_ARTIFACT
                || !names.insert(&item.file)
            {
                return Err("Invalid or duplicate release artifact");
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "Manifest encoding failed")?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err("Manifest exceeds size limit");
        }
        Ok(bytes)
    }
}

pub fn public_code(key: VerificationKey) -> String {
    format!("KCP1:{}", hex_bytes(&key.to_bytes()))
}

pub fn parse_public(code: &str) -> Result<VerificationKey> {
    let text = code
        .strip_prefix("KCP1:")
        .ok_or("Expected an independently trusted KCP1 public key")?;
    if !hex(text, 64) {
        return Err("Invalid public key encoding");
    }
    let mut bytes = [0; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "Invalid key")?, 16)
            .map_err(|_| "Invalid key")?;
    }
    VerificationKey::from_bytes(&bytes).map_err(|_| "Invalid public key")
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(text, "{b:02x}").expect("String write");
    }
    text
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = regular_file(path)?;
    if file.metadata().map_err(|_| "File metadata failed")?.len() > limit {
        return Err("Input exceeds size limit");
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "File read failed")?;
    if bytes.len() as u64 > limit {
        return Err("Input exceeds size limit");
    }
    Ok(bytes)
}

fn regular_file(path: &Path) -> Result<File> {
    if !std::fs::symlink_metadata(path)
        .map_err(|_| "Input unavailable")?
        .is_file()
    {
        return Err("Expected a regular file, not a link or directory");
    }
    let file = File::open(path).map_err(|_| "Input unavailable")?;
    if !file
        .metadata()
        .map_err(|_| "File metadata failed")?
        .is_file()
    {
        return Err("Expected a regular file");
    }
    Ok(file)
}

pub fn describe(path: &Path, target: &str) -> Result<Artifact> {
    let file = regular_file(path)?;
    let before = file.metadata().map_err(|_| "File metadata failed")?;
    if before.len() == 0 || before.len() > MAX_ARTIFACT {
        return Err("Invalid artifact size");
    }
    let mut digest = Sha256::new();
    let mut reader = file.take(before.len() + 1);
    let mut block = [0u8; 128 * 1024];
    let mut length = 0;
    loop {
        let count = reader
            .read(&mut block)
            .map_err(|_| "Artifact read failed")?;
        if count == 0 {
            break;
        }
        length += count as u64;
        digest.update(&block[..count]);
    }
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| "File metadata failed")?;
    if length != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err("Artifact changed during verification");
    }
    let file = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Artifact filename must be UTF-8")?
        .to_owned();
    Ok(Artifact {
        file,
        target: target.to_owned(),
        length,
        sha256: hex_bytes(&digest.finalize()),
    })
}

pub fn sign(manifest: &ReleaseManifest, key: &SigningKey) -> Result<(Vec<u8>, [u8; 64])> {
    let bytes = manifest.encode()?;
    let signature = key
        .sign(Purpose::ReleaseManifest, &bytes)
        .map_err(|_| "Release signing failed")?;
    Ok((bytes, signature.to_bytes()))
}

pub fn check(
    bytes: &[u8],
    signature: &[u8],
    key: &VerificationKey,
    expected: &Expected<'_>,
    artifact: &Path,
) -> Result<ReleaseManifest> {
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err("Manifest exceeds size limit");
    }
    let signature = Signature::from_bytes(signature).map_err(|_| "Invalid signature length")?;
    verify(key, Purpose::ReleaseManifest, bytes, &signature)
        .map_err(|_| "Release signature rejected")?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(bytes).map_err(|_| "Invalid manifest JSON")?;
    manifest.validate()?;
    if manifest.product != expected.product
        || manifest.version != expected.version
        || manifest.sequence < expected.min_sequence
        || expected.now < manifest.issued_at
        || expected.now >= manifest.expires_at
    {
        return Err("Release identity, sequence or validity period rejected");
    }
    let name = artifact
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid artifact filename")?;
    let item = manifest
        .artifacts
        .iter()
        .find(|a| a.file == name && a.target == expected.target)
        .ok_or("Artifact or platform not authorized by manifest")?;
    // Reject unexpected length before hashing the untrusted download.
    if regular_file(artifact)?
        .metadata()
        .map_err(|_| "File metadata failed")?
        .len()
        != item.length
    {
        return Err("Artifact size mismatch");
    }
    let actual = describe(artifact, expected.target)?;
    if actual.length != item.length || actual.sha256 != item.sha256 {
        return Err("Artifact digest mismatch");
    }
    Ok(manifest)
}

pub fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|_| "Cannot stage output")?;
    file.write_all(bytes).map_err(|_| "Cannot write output")?;
    file.as_file()
        .sync_all()
        .map_err(|_| "Cannot sync output")?;
    file.persist_noclobber(path)
        .map_err(|_| "Output exists or cannot be published")?;
    Ok(())
}
