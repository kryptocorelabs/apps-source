//! Optional, detached KCC sender signatures. Existing KCC/OpenSSH formats are unchanged.
use crate::{invalid, open_container, output_location, Error, Result, Summary};
use kryptocore_signatures::{verify, Purpose, Signature, SigningKey, VerificationKey};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const KEY_MAGIC: &[u8; 8] = b"KCSK\0\0\0\x01";
const SIGN_MAGIC: &[u8; 8] = b"KCCS\0\0\0\x01";
const MAX_FILE: u64 = 2 * 1024_u64.pow(4);
const MANIFEST: usize = 8 + 1 + 8 + 32;

fn exact<const N: usize>(path: &Path) -> Result<[u8; N]> {
    let mut file = open_container(path)?;
    if file.metadata()?.len() != N as u64 {
        return Err(Error::SignatureRejected);
    }
    let mut bytes = [0; N];
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0])? != 0 {
        return Err(Error::SignatureRejected);
    }
    Ok(bytes)
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let (parent, output) = output_location(path)?;
    let mut staged = NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    Ok(())
}

/// Create one password-encrypted signing-key file. The returned public code is
/// safe to share; its authenticity must be established through a trusted route.
pub fn generate_key(output: &Path, password: &[u8]) -> Result<String> {
    if password.len() > 1024
        || !std::str::from_utf8(password).is_ok_and(|s| s.chars().count() >= 15)
    {
        return Err(invalid(
            "Signing-key password requires at least 15 characters and at most 1024 UTF-8 bytes.",
        ));
    }
    let key = SigningKey::generate().map_err(|_| Error::Crypto)?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| Error::Crypto)?;
    let mut aad = KEY_MAGIC.to_vec();
    aad.extend_from_slice(&salt);
    let wrapping = kryptocore::derive_key(password, &salt).map_err(|_| Error::Crypto)?;
    let seed = key.export_seed();
    let (nonce, ciphertext) =
        kryptocore::encrypt(&wrapping, &seed[..], &aad).map_err(|_| Error::Crypto)?;
    let mut file = aad;
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);
    publish(output, &file)?;
    Ok(public_code(key.verification_key()))
}

fn open_key(path: &Path, password: &[u8]) -> Result<SigningKey> {
    if password.is_empty() || password.len() > 1024 {
        return Err(invalid("Invalid signing-key password length."));
    }
    let file = exact::<96>(path)?;
    if !file.starts_with(KEY_MAGIC) {
        return Err(invalid("Unsupported signing-key format."));
    }
    let salt = file[8..24].try_into().expect("fixed salt");
    let nonce = file[24..48].try_into().expect("fixed nonce");
    let wrapping = kryptocore::derive_key(password, &salt).map_err(|_| Error::Crypto)?;
    let seed = kryptocore::decrypt(&wrapping, &nonce, &file[48..], &file[..24])
        .map_err(|_| invalid("Wrong signing-key password or damaged signing key."))?;
    if seed.len() != 32 {
        return Err(invalid("Invalid signing-key contents."));
    }
    let mut owned = Zeroizing::new([0; 32]);
    owned.copy_from_slice(&seed);
    Ok(SigningKey::from_seed(owned))
}

pub fn export_public(path: &Path, password: &[u8]) -> Result<String> {
    Ok(public_code(open_key(path, password)?.verification_key()))
}

fn public_code(key: VerificationKey) -> String {
    use std::fmt::Write;
    let mut text = String::from("KCP1:");
    for byte in key.to_bytes() {
        write!(text, "{byte:02x}").expect("String write");
    }
    text
}

pub fn parse_public(code: &str) -> Result<VerificationKey> {
    let hex = code
        .trim()
        .strip_prefix("KCP1:")
        .filter(|s| s.len() == 64 && s.is_ascii())
        .ok_or_else(|| invalid("Expected an independently trusted KCP1 public code."))?;
    let mut bytes = [0; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16)
            .map_err(|_| Error::SignatureRejected)?;
    }
    VerificationKey::from_bytes(&bytes).map_err(|_| Error::SignatureRejected)
}

// Classify the existing file from one handle, then rewind before hashing.
fn layout(file: &mut File) -> Result<(u8, u64, u64, u64)> {
    let size = file.metadata()?.len();
    if !(136..=MAX_FILE).contains(&size) {
        return Err(invalid("Invalid signed container size."));
    }
    let mut header = [0; 8];
    file.read_exact(&mut header)?;
    if &header == crate::MAGIC {
        file.rewind()?;
        return Ok((1, size, 0, size));
    }
    file.seek(SeekFrom::End(-24))?;
    let mut footer = [0; 24];
    file.read_exact(&mut footer)?;
    let length = u64::from_le_bytes(footer[..8].try_into().expect("fixed footer"));
    let end = size - 24;
    if &footer[8..] != crate::EXE_FOOTER || length < 136 || length >= end {
        return Err(invalid("Unsupported signed container wrapper."));
    }
    let offset = end - length;
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut header)?;
    if &header != crate::MAGIC {
        return Err(invalid("Invalid embedded KCC marker."));
    }
    file.rewind()?;
    Ok((2, size, offset, length))
}

struct HashReader<R> {
    reader: R,
    hash: Sha256,
    bytes: u64,
}
impl<R> HashReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            hash: Sha256::new(),
            bytes: 0,
        }
    }
    fn finish(self) -> ([u8; 32], u64) {
        (self.hash.finalize().into(), self.bytes)
    }
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(output)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("Signed file too large"))?;
        if self.bytes > MAX_FILE {
            return Err(io::Error::other("Signed file too large"));
        }
        self.hash.update(&output[..count]);
        Ok(count)
    }
}

fn message(kind: u8, size: u64, digest: &[u8; 32]) -> [u8; MANIFEST] {
    let mut data = [0; MANIFEST];
    data[..8].copy_from_slice(SIGN_MAGIC);
    data[8] = kind;
    data[9..17].copy_from_slice(&size.to_be_bytes());
    data[17..].copy_from_slice(digest);
    data
}

pub fn sign(input: &Path, key_file: &Path, password: &[u8], output: &Path) -> Result<()> {
    let key = open_key(key_file, password)?;
    let mut file = open_container(input)?;
    let (kind, size, _, _) = layout(&mut file)?;
    let mut reader = HashReader::new(BufReader::new(file));
    io::copy(&mut reader, &mut io::sink())?;
    let (digest, count) = reader.finish();
    if count != size {
        return Err(Error::SignatureRejected);
    }
    let data = message(kind, size, &digest);
    let signature = key
        .sign(Purpose::ContainerManifest, &data)
        .map_err(|_| Error::Crypto)?;
    let mut detached = data.to_vec();
    detached.extend_from_slice(&signature.to_bytes());
    publish(output, &detached)
}

/// Expected signer is supplied separately; the signature contains no trusted key.
pub struct Verification {
    expected: VerificationKey,
    manifest: [u8; MANIFEST],
    signature: Signature,
}
impl Verification {
    pub fn from_file(signature: &Path, expected_public: &str) -> Result<Self> {
        let expected = parse_public(expected_public)?;
        let detached = exact::<113>(signature)?;
        if !detached.starts_with(SIGN_MAGIC) || !matches!(detached[8], 1 | 2) {
            return Err(Error::SignatureRejected);
        }
        let manifest: [u8; MANIFEST] = detached[..MANIFEST].try_into().expect("fixed manifest");
        let signature =
            Signature::from_bytes(&detached[MANIFEST..]).map_err(|_| Error::SignatureRejected)?;
        // Reject unauthenticated metadata before expensive decryption/scanning.
        verify(&expected, Purpose::ContainerManifest, &manifest, &signature)
            .map_err(|_| Error::SignatureRejected)?;
        Ok(Self {
            expected,
            manifest,
            signature,
        })
    }
    fn verify_digest(&self, kind: u8, size: u64, digest: &[u8; 32]) -> Result<()> {
        let actual = message(kind, size, digest);
        if actual != self.manifest {
            return Err(Error::SignatureRejected);
        }
        verify(
            &self.expected,
            Purpose::ContainerManifest,
            &actual,
            &self.signature,
        )
        .map_err(|_| Error::SignatureRejected)
    }
    pub fn verify(&self, input: &Path) -> Result<()> {
        let mut file = open_container(input)?;
        let (kind, _, _, _) = layout(&mut file)?;
        let mut reader = HashReader::new(BufReader::new(file));
        io::copy(&mut reader, &mut io::sink())?;
        let (digest, size) = reader.finish();
        self.verify_digest(kind, size, &digest)
    }
}

pub(crate) fn read_authenticated(
    input: &Path,
    password: &[u8],
    stage: &Path,
    verifier: &Verification,
) -> Result<Summary> {
    read_authenticated_limited(input, password, stage, verifier, crate::MAX_BYTES)
}

pub(crate) fn read_authenticated_limited(
    input: &Path,
    password: &[u8],
    stage: &Path,
    verifier: &Verification,
    limit: u64,
) -> Result<Summary> {
    let mut file = open_container(input)?;
    let (kind, size, offset, length) = layout(&mut file)?;
    let mut reader = HashReader::new(BufReader::new(file));
    io::copy(&mut (&mut reader).take(offset), &mut io::sink())?;
    let result = crate::read_payload_limited(
        &mut (&mut reader).take(length),
        password,
        Some(stage),
        limit,
    )?;
    if kind == 2 {
        // Validate the footer bytes that were actually hashed, rather than
        // trusting an earlier seek/read if the source changes concurrently.
        let mut footer = [0; 24];
        reader.read_exact(&mut footer)?;
        if &footer[8..] != crate::EXE_FOOTER
            || u64::from_le_bytes(footer[..8].try_into().expect("fixed footer")) != length
            || offset.checked_add(length).and_then(|n| n.checked_add(24)) != Some(size)
        {
            return Err(Error::SignatureRejected);
        }
    }
    if reader.read(&mut [0])? != 0 {
        return Err(Error::SignatureRejected);
    }
    let (digest, count) = reader.finish();
    if count != size {
        return Err(Error::SignatureRejected);
    }
    verifier.verify_digest(kind, count, &digest)?;
    Ok(result)
}

#[cfg(test)]
mod tests;
