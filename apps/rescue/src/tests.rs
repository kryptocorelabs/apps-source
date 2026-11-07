use super::*;
use std::{fs, io::Cursor};

fn sample(marker: &[u8], size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..marker.len()].copy_from_slice(marker);
    bytes
}

#[test]
fn recognizes_current_markers_but_never_claims_authentication() {
    for (marker, size, expected) in [
        (b"KCV1\0".as_slice(), 61, Format::VaultV1),
        (b"KCV2\0".as_slice(), 221, Format::VaultV2),
        (b"KCC\0\0\0\0\x01".as_slice(), 136, Format::ContainerV1),
        (b"KCMI\0\0\0\x01".as_slice(), 128, Format::MsgIdentityV1),
        (b"KCMB\0\0\0\x01".as_slice(), 48, Format::MsgStoreV1),
    ] {
        // Deliberately invalid ciphertext: a marker is not proof of authenticity.
        let bytes = sample(marker, size);
        let result = inspect_reader(&mut Cursor::new(bytes), size as u64).unwrap();
        assert_eq!(result.format, expected);
        assert_eq!(result.authenticity, "not_verified");
        assert!(!result.data_access_available);
        assert_eq!(result.payload_offset, 0);
        assert_eq!(result.payload_bytes, size as u64);
    }
}

#[test]
fn catalog_matches_existing_credential_routes() {
    let recovery = formats::identify(b"KCV2\0").unwrap();
    assert_eq!(
        recovery.credentials,
        [CredentialRoute::Password, CredentialRoute::RecoveryKey]
    );
    let legacy = formats::identify(b"KCV1\0").unwrap();
    assert_eq!(legacy.credentials, [CredentialRoute::Password]);
    let sidecar = formats::identify(b"KCMB\0\0\0\x01").unwrap();
    assert_eq!(sidecar.credentials, [CredentialRoute::IdentityAndPassword]);
}

#[test]
fn rejects_unknown_versions_truncation_and_invalid_sizes() {
    for marker in [
        b"KCV9\0".as_slice(),
        b"KCC\0\0\0\0\x02",
        b"KCMI\0\0\0\x02",
        b"KCMB\0\0\0\x02",
    ] {
        assert_eq!(
            inspect_reader(&mut Cursor::new(sample(marker, 256)), 256).unwrap_err(),
            Error::UnsupportedVersion
        );
    }
    for size in 0..61 {
        let bytes = if size >= 5 {
            sample(b"KCV1\0", size)
        } else {
            vec![0; size]
        };
        assert!(inspect_reader(&mut Cursor::new(bytes), size as u64).is_err());
    }
    let descriptor = formats::identify(b"KCV2\0").unwrap();
    assert_eq!(
        describe(descriptor, 4 * 1024 * 1024 + 1, 0, 4 * 1024 * 1024 + 1).unwrap_err(),
        Error::InvalidSize
    );
    for size in [127, 129] {
        assert!(inspect_reader(
            &mut Cursor::new(sample(b"KCMI\0\0\0\x01", size)),
            size as u64
        )
        .is_err());
    }
    assert_eq!(
        inspect_reader(&mut Cursor::new(b"not a kryptocore file"), 20).unwrap_err(),
        Error::UnknownFormat
    );
}

fn wrapper(length: u64) -> Vec<u8> {
    let mut bytes = b"MZ-test-only-not-an-executable".to_vec();
    bytes.extend_from_slice(&sample(b"KCC\0\0\0\0\x01", 136));
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(FOOTER);
    bytes
}

#[test]
fn locates_embedded_payload_as_data_and_checks_length_arithmetic() {
    let bytes = wrapper(136);
    let result = inspect_reader(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    assert_eq!(result.format, Format::EmbeddedContainerV1);
    assert_eq!(
        result.payload_offset,
        b"MZ-test-only-not-an-executable".len() as u64
    );
    assert_eq!(result.payload_bytes, 136);
    for length in [0, 1, 135, u64::MAX, bytes.len() as u64] {
        let invalid = wrapper(length);
        assert!(inspect_reader(&mut Cursor::new(&invalid), invalid.len() as u64).is_err());
    }
}

#[test]
fn inspection_preserves_bytes_and_does_not_create_adjacent_files() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("misleading.exe");
    let bytes = sample(b"KCV2\0", 221);
    fs::write(&input, &bytes).unwrap();
    assert_eq!(inspect(&input).unwrap().format, Format::VaultV2);
    assert_eq!(fs::read(&input).unwrap(), bytes);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    fs::write(&input, b"corrupted").unwrap();
    assert!(inspect(&input).is_err());
    assert_eq!(fs::read(&input).unwrap(), b"corrupted");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    assert_eq!(
        inspect(directory.path()).unwrap_err(),
        Error::NotRegularFile
    );
}

#[cfg(unix)]
#[test]
fn rejects_leaf_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("original");
    let link = directory.path().join("link");
    fs::write(&target, sample(b"KCV1\0", 61)).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(inspect(&link).unwrap_err(), Error::NotRegularFile);
}
