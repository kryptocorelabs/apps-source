use super::*;

const PW: &[u8] = b"Synthetic migration vault password";
const RECOVERY: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DATA: &[u8] =
    br#"[{"origin":"www.example.invalid","username":"Synthetic","password":"Synthetic secret"}]"#;

#[test]
fn migration_creation_uses_a_new_seed_even_with_the_same_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.kcv");
    let second = directory.path().join("second.kcv");
    create_with_recovery(&first, PW, RECOVERY, DATA).unwrap();
    let original = read(&first).unwrap();
    create_with_recovery(&second, PW, RECOVERY, DATA).unwrap();
    let other = read(&second).unwrap();
    let (first_seed, _) = open_recoverable(&original, PW, 0).unwrap();
    let (second_seed, _) = open_recoverable(&other, PW, 0).unwrap();
    assert_ne!(&first_seed[..], &second_seed[..]);
    // Directly exercise the old-key boundary, beyond different salts/nonces.
    assert!(decrypt(
        &payload_key(&first_seed).unwrap(),
        &other[181..205].try_into().unwrap(),
        &other[205..],
        &other[..181]
    )
    .is_err());
    assert_eq!(&open_with_recovery(&second, RECOVERY).unwrap()[..], DATA);
    assert_eq!(read(&first).unwrap(), original);
    let (_, metadata) = open_with_metadata(&second, PW, false).unwrap();
    assert_eq!(metadata.format_version, 2);
    assert!(metadata.recovery_available && metadata.revision.is_none());
    let mut tampered = other;
    *tampered.last_mut().unwrap() ^= 1;
    std::fs::write(&second, tampered).unwrap();
    assert!(open_with_metadata(&second, PW, false).is_err());
}

#[test]
fn invalid_imports_and_existing_destinations_are_never_published_or_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("new.kcv");
    for invalid in [b"broken JSON".as_slice(), br#"[{"origin":"x"}]"#.as_slice()] {
        assert!(create_with_recovery(&path, PW, RECOVERY, invalid).is_err());
        assert!(!path.exists());
    }
    assert!(create_with_recovery(&path, PW, RECOVERY, &vec![b' '; MAX_FILE]).is_err());
    assert!(!path.exists());
    create_with_recovery(&path, PW, RECOVERY, DATA).unwrap();
    let original = read(&path).unwrap();
    assert!(create_with_recovery(&path, PW, RECOVERY, b"[]").is_err());
    assert_eq!(read(&path).unwrap(), original);
    let legacy = directory.path().join("legacy.kcv");
    save(&legacy, PW, DATA, true).unwrap();
    let (_, metadata) = open_with_metadata(&legacy, PW, false).unwrap();
    assert_eq!(metadata.format_version, 1);
    assert!(!metadata.recovery_available);
}
