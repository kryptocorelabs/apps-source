use super::*;

const OLD: &[u8] = b"Synthetic previous vault password";
const NEW: &[u8] = b"Synthetic changed vault password";
const NEXT: &[u8] = b"Synthetic rotated vault password";
const REC: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NEXT_REC: &[u8] = b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DATA: &[u8] =
    br#"[{"origin":"www.example.invalid","username":"Synthetic","password":"Synthetic secret"}]"#;

#[test]
fn password_slot_change_retains_seed_while_explicit_rotation_replaces_seed_and_recovery() {
    for epoch in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.kcv");
        create_with_recovery(&source, OLD, REC, DATA).unwrap();
        let path = if epoch {
            let path = directory.path().join("versioned.kcv");
            enable_epoch_copy(&source, &path, OLD).unwrap();
            path
        } else {
            source
        };
        let original = read(&path).unwrap();
        let (seed, _) = open_recoverable(&original, OLD, 0).unwrap();
        let old_key = payload_key(&seed).unwrap();
        let before = revision(&original);
        let (second, rotated) =
            change_password_with_revision(&path, OLD, NEW, false, None, before).unwrap();
        assert!(!rotated);
        let quick = read(&path).unwrap();
        let (slots, aad) = layout(&quick).unwrap();
        assert_eq!(
            &original[slots + SLOT_LEN..aad],
            &quick[slots + SLOT_LEN..aad]
        );
        assert!(open(&path, OLD).is_err());
        assert_eq!(&open(&path, NEW).unwrap()[..], DATA);
        assert_eq!(&open_with_recovery(&path, REC).unwrap()[..], DATA);
        let (same_seed, _) = open_recoverable(&quick, NEW, 0).unwrap();
        assert_eq!(&seed[..], &same_seed[..]);
        // Proves the quick-mode limitation: a seed from an earlier copy still works.
        assert!(decrypt(
            &old_key,
            &quick[aad..aad + 24].try_into().unwrap(),
            &quick[aad + 24..],
            &quick[..aad]
        )
        .is_ok());
        let (third, rotated) =
            change_password_with_revision(&path, NEW, NEXT, true, Some(NEXT_REC), second).unwrap();
        assert!(rotated);
        let current = read(&path).unwrap();
        let (fresh_seed, _) = open_recoverable(&current, NEXT, 0).unwrap();
        assert_ne!(&seed[..], &fresh_seed[..]);
        assert!(decrypt(
            &old_key,
            &current[aad..aad + 24].try_into().unwrap(),
            &current[aad + 24..],
            &current[..aad]
        )
        .is_err());
        assert!(open(&path, NEW).is_err());
        assert!(open_with_recovery(&path, REC).is_err());
        assert_eq!(&open_with_recovery(&path, NEXT_REC).unwrap()[..], DATA);
        assert_eq!(&open_bytes(&original, OLD).unwrap()[..], DATA);
        if epoch {
            assert_eq!(third.unwrap().vault_id, before.unwrap().vault_id);
            assert_eq!(second.unwrap().epoch, 2);
            assert_eq!(third.unwrap().epoch, 3);
        } else {
            assert!(third.is_none());
        }
    }
}

#[test]
fn rejected_password_changes_leave_originals_intact_and_kcv1_stays_compatible() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.kcv");
    create_with_recovery(&path, OLD, REC, DATA).unwrap();
    let original = read(&path).unwrap();
    assert!(change_password_with_revision(&path, b"wrong", NEW, false, None, None).is_err());
    assert!(change_password_with_revision(&path, OLD, NEW, true, None, None).is_err());
    assert!(change_password_with_revision(&path, OLD, NEW, false, Some(NEXT_REC), None).is_err());
    assert_eq!(read(&path).unwrap(), original);
    let versioned = directory.path().join("versioned.kcv");
    let first = enable_epoch_copy(&path, &versioned, OLD).unwrap();
    let stale = read(&versioned).unwrap();
    let (floor, _) =
        change_password_with_revision(&versioned, OLD, NEW, false, None, Some(first)).unwrap();
    std::fs::write(&versioned, &stale).unwrap();
    assert!(change_password_with_revision(&versioned, OLD, NEXT, false, None, floor).is_err());
    assert!(
        change_password_with_revision(&versioned, OLD, NEXT, true, Some(NEXT_REC), floor).is_err()
    );
    assert!(verified_snapshot(&versioned, OLD, floor).is_err());
    assert_eq!(read(&versioned).unwrap(), stale);
    let legacy = directory.path().join("legacy.kcv");
    save(&legacy, OLD, DATA, true).unwrap();
    let (revision, rotated) =
        change_password_with_revision(&legacy, OLD, NEW, false, None, None).unwrap();
    assert!(revision.is_none() && rotated);
    assert!(read(&legacy).unwrap().starts_with(HEADER));
    assert!(open(&legacy, OLD).is_err());
    assert_eq!(&open(&legacy, NEW).unwrap()[..], DATA);
}
