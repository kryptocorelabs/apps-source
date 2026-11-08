use super::*;
use std::fs;

const PASSWORD: &[u8] = b"synthetic signing password only";
const ARCHIVE_PASSWORD: &[u8] = b"synthetic archive password only";

fn root() -> (tempfile::TempDir, std::path::PathBuf) {
    let owner = tempfile::tempdir().unwrap();
    let path = owner.path().canonicalize().unwrap();
    (owner, path)
}

#[test]
fn shared_signature_and_encrypted_key_roundtrip_and_negative_cases() {
    let (_owner, root) = root();
    let key = root.join("sender.kcsk");
    let public = generate_key(&key, PASSWORD).unwrap();
    assert_eq!(export_public(&key, PASSWORD).unwrap(), public);
    assert!(export_public(&key, b"wrong").is_err());
    assert_eq!(fs::metadata(&key).unwrap().len(), 96);
    assert!(generate_key(&key, PASSWORD).is_err());
    let other = generate_key(&root.join("other.kcsk"), PASSWORD).unwrap();
    let file = root.join("data.txt");
    fs::write(&file, b"synthetic contents").unwrap();
    let archive = root.join("data.kcc");
    crate::pack(&archive, &[file], ARCHIVE_PASSWORD).unwrap();
    let original = fs::read(&archive).unwrap();
    let sig = root.join("data.kcsig");
    sign(&archive, &key, PASSWORD, &sig).unwrap();
    assert_eq!(fs::metadata(&sig).unwrap().len(), 113);
    let verification = Verification::from_file(&sig, &public).unwrap();
    verification.verify(&archive).unwrap();
    assert!(Verification::from_file(&sig, &other).is_err());
    let output = root.join("out");
    crate::unpack_native_with_inspection(
        &archive,
        &output,
        ARCHIVE_PASSWORD,
        &verification,
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        fs::read(output.join("data.txt")).unwrap(),
        b"synthetic contents"
    );
    assert_eq!(fs::read(&archive).unwrap(), original);
    // A different encrypted archive is valid under its password but has no signature from this signer.
    let replacement = root.join("replacement.kcc");
    let new = root.join("other.txt");
    fs::write(&new, b"other").unwrap();
    crate::pack(&replacement, &[new], ARCHIVE_PASSWORD).unwrap();
    let rejected = root.join("rejected");
    assert!(crate::unpack_native_with_inspection(
        &replacement,
        &rejected,
        ARCHIVE_PASSWORD,
        &verification,
        |_| panic!("must verify before scanner")
    )
    .is_err());
    assert!(!rejected.exists());
    let bytes = fs::read(&sig).unwrap();
    let signer = open_key(&key, PASSWORD).unwrap();
    let wrong_purpose = signer
        .sign(Purpose::ReleaseManifest, &bytes[..MANIFEST])
        .unwrap();
    let mut swapped = bytes[..MANIFEST].to_vec();
    swapped.extend_from_slice(&wrong_purpose.to_bytes());
    fs::write(&sig, swapped).unwrap();
    assert!(Verification::from_file(&sig, &public).is_err());
    for index in [0, 7, 8, 9, 17, 48, 49, 112] {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        fs::write(&sig, bad).unwrap();
        assert!(Verification::from_file(&sig, &public).is_err());
    }
    for length in [0, 8, 49, 64, 112, 114] {
        fs::write(&sig, vec![0; length]).unwrap();
        assert!(Verification::from_file(&sig, &public).is_err());
    }
    let before = fs::read(&key).unwrap();
    let mut changed = before.clone();
    changed[24] ^= 1;
    fs::write(&key, &changed).unwrap();
    assert!(export_public(&key, PASSWORD).is_err());
    assert_eq!(fs::read(&key).unwrap(), changed);
}

#[test]
fn executable_wrapper_and_scanner_rejection_are_bound_before_publication() {
    let (_owner, root) = root();
    let key = root.join("key.kcsk");
    let public = generate_key(&key, PASSWORD).unwrap();
    let stub = root.join("stub.exe");
    fs::write(&stub, b"synthetic stub - never executed").unwrap();
    let file = root.join("test.txt");
    fs::write(&file, b"test data").unwrap();
    let archive = root.join("wrapped.exe");
    crate::pack_executable(&stub, &archive, &[file], ARCHIVE_PASSWORD).unwrap();
    let sig = root.join("wrapped.kcsig");
    sign(&archive, &key, PASSWORD, &sig).unwrap();
    let verifier = Verification::from_file(&sig, &public).unwrap();
    let rejected = root.join("scan-rejected");
    assert!(crate::unpack_native_with_inspection(
        &archive,
        &rejected,
        ARCHIVE_PASSWORD,
        &verifier,
        |stage| {
            assert!(stage.join("test.txt").exists());
            Err(Error::ScanRejected)
        }
    )
    .is_err());
    assert!(!rejected.exists());
    crate::unpack_native_with_inspection(
        &archive,
        &root.join("out"),
        ARCHIVE_PASSWORD,
        &verifier,
        |_| Ok(()),
    )
    .unwrap();
    let mut bytes = fs::read(&archive).unwrap();
    bytes[0] ^= 1;
    fs::write(&archive, bytes).unwrap();
    assert!(verifier.verify(&archive).is_err());
    assert!(crate::unpack_native_with_inspection(
        &archive,
        &root.join("bad"),
        ARCHIVE_PASSWORD,
        &verifier,
        |_| panic!("signature must pass first")
    )
    .is_err());
    assert!(!root.join("bad").exists());
}

#[test]
fn public_code_requires_a_valid_separate_key_and_no_existing_files_are_replaced() {
    let (_owner, root) = root();
    for code in [
        "",
        "KCP1:",
        &format!("KCP1:{}", "00".repeat(32)),
        &format!("KCP1:{}", "gg".repeat(32)),
    ] {
        assert!(parse_public(code).is_err());
    }
    let target = root.join("preserve");
    fs::write(&target, b"preserve").unwrap();
    assert!(generate_key(&target, PASSWORD).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"preserve");
    assert!(generate_key(&root.join("short"), b"short").is_err());
    assert!(!root.join("short").exists());
}

#[test]
fn plaintext_budget_rejects_a_declared_entry_before_writing_its_data() {
    let (_owner, root) = root();
    let source = root.join("data");
    std::fs::write(&source, [0; 4096]).unwrap();
    let archive = root.join("bounded.kcc");
    crate::pack(&archive, &[source], ARCHIVE_PASSWORD).unwrap();
    let stage = root.join("stage");
    std::fs::create_dir(&stage).unwrap();
    assert!(crate::read_payload_limited(
        &mut File::open(archive).unwrap(),
        ARCHIVE_PASSWORD,
        Some(&stage),
        1024
    )
    .is_err());
    assert_eq!(std::fs::read_dir(stage).unwrap().count(), 0);
}

#[test]
fn native_wire_vector_from_independent_pynacl_framing_verifies() {
    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    let vector = include_str!("../../tests/fixtures/native-v1.txt");
    let lines: Vec<_> = vector.lines().collect();
    assert_eq!(lines.len(), 3);
    let (_owner, root) = root();
    let input = root.join("marker-only.kcc");
    let signature = root.join("reference.kcsig");
    std::fs::write(&input, unhex(lines[1])).unwrap();
    std::fs::write(&signature, unhex(lines[2])).unwrap();
    Verification::from_file(&signature, lines[0])
        .unwrap()
        .verify(&input)
        .unwrap();
    // Valid sender signatures are deliberately separate from valid encryption.
    assert!(crate::check(&input, ARCHIVE_PASSWORD).is_err());
}
