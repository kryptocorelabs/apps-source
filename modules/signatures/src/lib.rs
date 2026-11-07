//! Optional, purpose-bound signatures. This crate is independent of the encryption core.
//!
//! A successful check authenticates bytes under the **expected** public key. It
//! does not establish trust in a person, confidentiality, freshness, or file safety.
//! See the crate README for the exact signed representation and compatibility scope.
//!
//! ```
//! use kryptocore_signatures::{SigningKey, Purpose, verify};
//! let signer = SigningKey::generate()?;
//! let expected_key = signer.verification_key(); // obtain through a trusted route
//! let signature = signer.sign(Purpose::ContainerManifest, b"canonical manifest")?;
//! verify(&expected_key, Purpose::ContainerManifest, b"canonical manifest", &signature)?;
//! # Ok::<(), kryptocore_signatures::Error>(())
//! ```

#![forbid(unsafe_code)]

use ed25519_dalek::Signer;
use zeroize::Zeroizing;

pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const DOMAIN: &[u8] = b"KryptoCore/signatures\0\x01";

/// Protocol purposes are explicit and versioned. These labels are part of the wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Purpose {
    ContainerManifest,
    ReleaseManifest,
    ContactBinding,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::ContainerManifest => b"container-manifest/v1",
            Self::ReleaseManifest => b"release-manifest/v1",
            Self::ContactBinding => b"contact-binding/v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RandomnessUnavailable,
    InvalidPublicKey,
    InvalidSignatureLength,
    MessageTooLarge,
    AllocationFailed,
    VerificationFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RandomnessUnavailable => "Operating system randomness unavailable",
            Self::InvalidPublicKey => "Invalid signing public key",
            Self::InvalidSignatureLength => "Signature must contain exactly 64 bytes",
            Self::MessageTooLarge => "Signed message exceeds the size limit",
            Self::AllocationFailed => "Unable to allocate signature message buffer",
            Self::VerificationFailed => "Signature verification failed",
        })
    }
}

impl std::error::Error for Error {}

/// Dedicated signing key. No Debug, Clone, or implicit encryption-key conversion.
/// The upstream key uses its zeroize-on-drop implementation.
///
/// ```compile_fail
/// let key = kryptocore_signatures::SigningKey::generate().unwrap();
/// println!("{key:?}");
/// ```
/// ```compile_fail
/// let key = kryptocore_signatures::SigningKey::generate().unwrap();
/// let duplicate = key.clone();
/// ```
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self::from_seed(seed))
    }

    /// Import a dedicated Ed25519 seed. Never supply a password, an encryption
    /// key, or an MSG X25519 identity. Caller-owned copies remain the caller's responsibility.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// Explicit secret export for an application's encrypted key storage.
    /// No persistence or recovery policy is implemented by this crate.
    pub fn export_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey(self.0.verifying_key())
    }

    pub fn sign(&self, purpose: Purpose, message: &[u8]) -> Result<Signature, Error> {
        let framed = frame(purpose, message)?;
        Ok(Signature(self.0.sign(&framed)))
    }
}

/// A structurally validated key, not an automatically trusted signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationKey(ed25519_dalek::VerifyingKey);

impl VerificationKey {
    /// Require a canonical, non-identity point in the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let encoded: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(encoded)
            .map_err(|_| Error::InvalidPublicKey)?;
        let point = key.to_edwards();
        if key.is_weak() || !point.is_torsion_free() || point.compress().as_bytes() != encoded {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Detached 64-byte Ed25519 signature. Parsing checks length; verification
/// checks scalar/point encodings and the signature equation using verify_strict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let encoded = bytes
            .try_into()
            .map_err(|_| Error::InvalidSignatureLength)?;
        Ok(Self(ed25519_dalek::Signature::from_bytes(encoded)))
    }

    pub fn to_bytes(self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

/// Verify against an expected key chosen by the caller. Never derive trust
/// from a public key supplied alongside an untrusted message.
pub fn verify(
    expected_key: &VerificationKey,
    purpose: Purpose,
    message: &[u8],
    signature: &Signature,
) -> Result<(), Error> {
    let framed = frame(purpose, message)?;
    expected_key
        .0
        .verify_strict(&framed, &signature.0)
        .map_err(|_| Error::VerificationFailed)
}

fn frame(purpose: Purpose, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge);
    }
    let label = purpose.label();
    let mut framed = Zeroizing::new(Vec::new());
    framed
        .try_reserve_exact(DOMAIN.len() + 2 + label.len() + 8 + message.len())
        .map_err(|_| Error::AllocationFailed)?;
    framed.extend_from_slice(DOMAIN);
    framed.extend_from_slice(&(label.len() as u16).to_be_bytes());
    framed.extend_from_slice(label);
    framed.extend_from_slice(&(message.len() as u64).to_be_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}

#[cfg(test)]
mod tests;
