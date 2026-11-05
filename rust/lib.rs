#![forbid(unsafe_code)]
//! Local authenticated encryption and password-based key derivation.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use zeroize::Zeroizing;

/// A secret key whose backing bytes are overwritten on drop.
pub struct Key(Zeroizing<[u8; 32]>);

impl Key {
    /// Generate a new key using the operating system's random source.
    pub fn generate() -> Result<Self, Error> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut key[..]).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self(key))
    }
}
/// A public, random salt for the password derivation profile.
pub type Salt = [u8; 16];
/// A public XChaCha20-Poly1305 nonce.
pub type Nonce = [u8; 24];

/// Failure of a cryptographic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPassword,
    DerivationFailed,
    RandomnessUnavailable,
    EncryptionFailed,
    AuthenticationFailed,
}

/// Derive a key using Argon2id v19 with 256 MiB, three passes and one lane.
/// The caller supplies a fresh random salt for each new derivation context
/// and bounds the number of concurrent derivations.
/// Returns an error if the allocator rejects the work buffer reservation.
pub fn derive_key(password: &[u8], salt: &Salt) -> Result<Key, Error> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let params = Params::new(256 * 1024, 3, 1, Some(32)).map_err(|_| Error::DerivationFailed)?;
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(params.block_count())
        .map_err(|_| Error::DerivationFailed)?;
    memory.resize(params.block_count(), Block::default());
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, &mut key[..], &mut memory[..])
        .map_err(|_| Error::DerivationFailed)?;
    Ok(Key(key))
}

/// Encrypt a message and return a fresh nonce and the ciphertext with its tag.
/// Associated data is authenticated and remains public.
pub fn encrypt(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<(Nonce, Vec<u8>), Error> {
    let mut nonce = Nonce::default();
    getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
    let ciphertext = XChaCha20Poly1305::new((&*key.0).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;
    Ok((nonce, ciphertext))
}

/// Authenticate the ciphertext and associated data before returning plaintext.
pub fn decrypt(
    key: &Key,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    XChaCha20Poly1305::new((&*key.0).into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn decrypts_published_xchacha20_poly1305_vector() {
        // draft-irtf-cfrg-xchacha-03, Appendix A.1
        let key = Key(Zeroizing::new(hex!(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )));
        let nonce = hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let ciphertext = hex!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"
        );
        let plaintext = decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(
            &plaintext[..],
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        );
    }

    #[test]
    fn rejects_wrong_key_nonce_aad_and_modified_or_truncated_ciphertext() {
        let key = Key(Zeroizing::new([1; 32]));
        let wrong_key = Key(Zeroizing::new([2; 32]));
        let (nonce, ciphertext) = encrypt(&key, b"secret", b"vault/v1").unwrap();
        assert_eq!(
            &decrypt(&key, &nonce, &ciphertext, b"vault/v1").unwrap()[..],
            b"secret"
        );

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        let mut modified = ciphertext.clone();
        modified[0] ^= 1;
        for (key, nonce, data, aad) in [
            (&wrong_key, &nonce, ciphertext.as_slice(), &b"vault/v1"[..]),
            (&key, &wrong_nonce, &ciphertext, &b"vault/v1"[..]),
            (&key, &nonce, &ciphertext, &b"vault/v2"[..]),
            (&key, &nonce, &modified, &b"vault/v1"[..]),
            (&key, &nonce, &ciphertext[..15], &b"vault/v1"[..]),
        ] {
            assert!(matches!(
                decrypt(key, nonce, data, aad),
                Err(Error::AuthenticationFailed)
            ));
        }
    }

    #[test]
    fn generated_key_round_trips_an_empty_message() {
        let key = Key::generate().unwrap();
        let (nonce, ciphertext) = encrypt(&key, b"", b"").unwrap();
        assert_eq!(ciphertext.len(), 16);
        assert!(decrypt(&key, &nonce, &ciphertext, b"").unwrap().is_empty());
    }

    #[test]
    fn argon2id_matches_python_and_libsodium_reference() {
        let salt = hex!("000102030405060708090a0b0c0d0e0f");
        let key = derive_key(b"password used only in tests", &salt).unwrap();
        assert_eq!(
            *key.0,
            hex!("d2250c8b3ccc488a296fc8d6875c6a9a2cf6e838c79c14b714e3945ba46f8e3c")
        );
        assert!(matches!(derive_key(b"", &salt), Err(Error::EmptyPassword)));
    }
}
