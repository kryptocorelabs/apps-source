use super::*;
use hex_literal::hex;

// RFC 8032 section 7.1, TEST 1. Public test material only, never production keys.
const SEED: [u8; 32] = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const PUBLIC: [u8; 32] = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

fn signer() -> SigningKey {
    SigningKey::from_seed(Zeroizing::new(SEED))
}

#[test]
fn published_rfc8032_vectors() {
    let vectors: [([u8; 32], [u8; 32], &[u8], [u8; 64]); 2] = [
        (
            SEED,
            PUBLIC,
            b"",
            hex!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        ),
        (
            hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            &[0x72],
            hex!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        ),
    ];
    for (seed, public, message, expected) in vectors {
        // Test the pinned primitive directly: the public wrapper always frames.
        let key = SigningKey::from_seed(Zeroizing::new(seed));
        assert_eq!(key.verification_key().to_bytes(), public);
        let signature = key.0.sign(message);
        assert_eq!(signature.to_bytes(), expected);
        key.0
            .verifying_key()
            .verify_strict(message, &signature)
            .unwrap();
        VerificationKey::from_bytes(&public).unwrap();
    }
}

#[test]
fn exact_versioned_framing() {
    let framed = frame(Purpose::ContainerManifest, b"abc").unwrap();
    assert_eq!(
        framed.as_slice(),
        b"KryptoCore/signatures\0\x01\0\x15container-manifest/v1\0\0\0\0\0\0\0\x03abc"
    );
    assert_ne!(
        frame(Purpose::ContainerManifest, b"").unwrap(),
        frame(Purpose::ReleaseManifest, b"").unwrap()
    );
}

#[test]
fn roundtrip_all_purposes_and_binary_messages() {
    let key = signer();
    let public = VerificationKey::from_bytes(&key.verification_key().to_bytes()).unwrap();
    for purpose in [
        Purpose::ContainerManifest,
        Purpose::ReleaseManifest,
        Purpose::ContactBinding,
    ] {
        for data in [b"".as_slice(), b"\0\xff\nhello".as_slice()] {
            let signature = key.sign(purpose, data).unwrap();
            let parsed = Signature::from_bytes(&signature.to_bytes()).unwrap();
            verify(&public, purpose, data, &parsed).unwrap();
        }
    }
}

#[test]
fn modified_data_signature_key_and_purpose_are_rejected() {
    let key = signer();
    let purpose = Purpose::ContactBinding;
    let message = b"identity=synthetic;revision=1";
    let signature = key.sign(purpose, message).unwrap();
    let public = key.verification_key();
    for index in 0..message.len() {
        let mut altered = message.to_vec();
        altered[index] ^= 1;
        assert_eq!(
            verify(&public, purpose, &altered, &signature),
            Err(Error::VerificationFailed)
        );
    }
    for index in 0..64 {
        let mut altered = signature.to_bytes();
        altered[index] ^= 1;
        assert_eq!(
            verify(
                &public,
                purpose,
                message,
                &Signature::from_bytes(&altered).unwrap()
            ),
            Err(Error::VerificationFailed)
        );
    }
    assert_eq!(
        verify(&public, Purpose::ReleaseManifest, message, &signature),
        Err(Error::VerificationFailed)
    );
    let other = SigningKey::from_seed(Zeroizing::new([42; 32]));
    assert_eq!(
        verify(&other.verification_key(), purpose, message, &signature),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        verify(&public, purpose, &message[..message.len() - 1], &signature),
        Err(Error::VerificationFailed)
    );
    let mut appended = message.to_vec();
    appended.push(0);
    assert_eq!(
        verify(&public, purpose, &appended, &signature),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn public_keys_require_canonical_prime_order_encoding() {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    for point in EIGHT_TORSION {
        assert_eq!(
            VerificationKey::from_bytes(point.compress().as_bytes()),
            Err(Error::InvalidPublicKey)
        );
    }
    let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
    assert_eq!(
        VerificationKey::from_bytes(mixed.compress().as_bytes()),
        Err(Error::InvalidPublicKey)
    );
    // Noncanonical y = p + 1, and x = 0 with an unnecessary sign bit.
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    assert_eq!(
        VerificationKey::from_bytes(&noncanonical),
        Err(Error::InvalidPublicKey)
    );
    let mut negative_zero = [0u8; 32];
    negative_zero[0] = 1;
    negative_zero[31] = 0x80;
    assert_eq!(
        VerificationKey::from_bytes(&negative_zero),
        Err(Error::InvalidPublicKey)
    );
}

#[test]
fn malformed_lengths_are_rejected_without_panics() {
    for length in 0..=128 {
        let bytes = vec![0u8; length];
        if length != 32 {
            assert_eq!(
                VerificationKey::from_bytes(&bytes),
                Err(Error::InvalidPublicKey)
            );
        }
        if length != 64 {
            assert_eq!(
                Signature::from_bytes(&bytes),
                Err(Error::InvalidSignatureLength)
            );
        }
    }
}

#[test]
fn noncanonical_scalar_and_low_order_r_are_rejected() {
    let key = signer();
    let purpose = Purpose::ContainerManifest;
    let signature = key.sign(purpose, b"manifest").unwrap();
    let mut altered = signature.to_bytes();
    // Add group order L to S: an equivalent residue must not be accepted.
    let order = hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = altered[32 + index] as u16 + order[index] as u16 + carry;
        altered[32 + index] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(
        verify(
            &key.verification_key(),
            purpose,
            b"manifest",
            &Signature::from_bytes(&altered).unwrap()
        ),
        Err(Error::VerificationFailed)
    );
    for r in [[0u8; 32], {
        let mut id = [0; 32];
        id[0] = 1;
        id
    }] {
        let mut altered = signature.to_bytes();
        altered[..32].copy_from_slice(&r);
        assert_eq!(
            verify(
                &key.verification_key(),
                purpose,
                b"manifest",
                &Signature::from_bytes(&altered).unwrap()
            ),
            Err(Error::VerificationFailed)
        );
    }
}

#[test]
fn raw_and_other_version_signatures_are_not_accepted() {
    let key = signer();
    let purpose = Purpose::ReleaseManifest;
    let data = b"manifest";
    let raw = Signature(key.0.sign(data));
    assert_eq!(
        verify(&key.verification_key(), purpose, data, &raw),
        Err(Error::VerificationFailed)
    );
    let mut other_version = frame(purpose, data).unwrap();
    other_version[DOMAIN.len() - 1] = 2;
    let wrong = Signature(key.0.sign(&other_version));
    assert_eq!(
        verify(&key.verification_key(), purpose, data, &wrong),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn bounded_messages_and_explicit_seed_roundtrip() {
    fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    let key = signer();
    let restored = SigningKey::from_seed(key.export_seed());
    assert_eq!(restored.verification_key(), key.verification_key());
    let data = vec![0; MAX_MESSAGE_BYTES];
    let signature = key.sign(Purpose::ContainerManifest, &data).unwrap();
    verify(
        &key.verification_key(),
        Purpose::ContainerManifest,
        &data,
        &signature,
    )
    .unwrap();
    let oversized = vec![0; MAX_MESSAGE_BYTES + 1];
    assert_eq!(
        key.sign(Purpose::ContainerManifest, &oversized),
        Err(Error::MessageTooLarge)
    );
    assert_eq!(
        verify(
            &key.verification_key(),
            Purpose::ContainerManifest,
            &oversized,
            &signature
        ),
        Err(Error::MessageTooLarge)
    );
}

#[test]
fn os_random_keys_are_distinct_and_sign() {
    let first = SigningKey::generate().unwrap();
    let second = SigningKey::generate().unwrap();
    assert_ne!(first.verification_key(), second.verification_key());
    let signature = first.sign(Purpose::ContactBinding, b"test").unwrap();
    verify(
        &first.verification_key(),
        Purpose::ContactBinding,
        b"test",
        &signature,
    )
    .unwrap();
}
