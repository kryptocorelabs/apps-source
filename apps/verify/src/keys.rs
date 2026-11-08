//! Existing KCSK v1 envelope; use a dedicated release key, never a container key.
use crate::{publish, read_bounded, Result};
use kryptocore_signatures::SigningKey;
use std::path::Path;
use zeroize::Zeroizing;
const MAGIC: &[u8] = b"KCSK\0\0\0\x01";

pub fn generate(path: &Path, password: &[u8]) -> Result<SigningKey> {
    if password.len() > 1024
        || !std::str::from_utf8(password).is_ok_and(|s| s.chars().count() >= 15)
    {
        return Err("Use at least 15 characters and at most 1024 UTF-8 bytes");
    }
    let signer = SigningKey::generate().map_err(|_| "Signing key generation failed")?;
    let mut salt = [0; 16];
    getrandom::fill(&mut salt).map_err(|_| "OS randomness unavailable")?;
    let mut aad = MAGIC.to_vec();
    aad.extend_from_slice(&salt);
    let key = kryptocore::derive_key(password, &salt).map_err(|_| "Key derivation failed")?;
    let (nonce, ciphertext) = kryptocore::encrypt(&key, &signer.export_seed()[..], &aad)
        .map_err(|_| "Key encryption failed")?;
    let mut bytes = aad;
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    publish(path, &bytes)?;
    Ok(signer)
}

pub fn open(path: &Path, password: &[u8]) -> Result<SigningKey> {
    if password.is_empty() || password.len() > 1024 {
        return Err("Invalid key password length");
    }
    let bytes = read_bounded(path, 96)?;
    if bytes.len() != 96 || !bytes.starts_with(MAGIC) {
        return Err("Invalid KCSK v1 key file");
    }
    let salt = bytes[8..24].try_into().map_err(|_| "Invalid salt")?;
    let nonce = bytes[24..48].try_into().map_err(|_| "Invalid nonce")?;
    let key = kryptocore::derive_key(password, &salt).map_err(|_| "Key derivation failed")?;
    let seed = kryptocore::decrypt(&key, &nonce, &bytes[48..], &bytes[..24])
        .map_err(|_| "Wrong password or damaged signing key")?;
    let mut owned = Zeroizing::new([0; 32]);
    if seed.len() != owned.len() {
        return Err("Invalid signing seed");
    }
    owned.copy_from_slice(&seed);
    Ok(SigningKey::from_seed(owned))
}
