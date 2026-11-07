use hex_literal::hex;
use kryptocore_signatures::{verify, Purpose, Signature, SigningKey, VerificationKey};
use std::process::Command;
use zeroize::Zeroizing;

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "requires Python and PyNaCl; run explicitly in the Python CI jobs"]
fn pynacl_signs_rust_verifies_and_rust_signs_pynacl_verifies() {
    // Public RFC 8032 TEST 1 seed, not production material.
    let key = SigningKey::from_seed(Zeroizing::new(hex!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )));
    let message = b"manifest\0\xff\nsynthetic data";
    let public = key.verification_key();
    let python = std::env::var_os("PYTHON").unwrap_or_else(|| "python".into());
    for (purpose, label) in [
        (Purpose::ContainerManifest, "container-manifest/v1"),
        (Purpose::ReleaseManifest, "release-manifest/v1"),
        (Purpose::ContactBinding, "contact-binding/v1"),
    ] {
        let signature = key.sign(purpose, message).unwrap();
        let output = Command::new(&python)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/pynacl_interop.py"
            ))
            .arg(encode(&public.to_bytes()))
            .arg(encode(&signature.to_bytes()))
            .arg(encode(message))
            .arg(label)
            .output()
            .expect("start Python reference");
        assert!(
            output.status.success(),
            "Python reference failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let bytes: Vec<u8> = text
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(bytes.len(), 96);
        let python_key = VerificationKey::from_bytes(&bytes[..32]).unwrap();
        let python_sig = Signature::from_bytes(&bytes[32..]).unwrap();
        verify(&python_key, purpose, message, &python_sig).unwrap();
        assert_ne!(python_key, public);
    }
}
