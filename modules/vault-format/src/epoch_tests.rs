use super::*;

const PW: &[u8] = b"synthetic epoch vault password";
const RECOVERY: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NEW: &[u8] = b"replacement synthetic vault password";

#[test]
fn opt_in_copy_preserves_legacy_and_advances_only_successful_writes() {
    let folder = tempfile::tempdir().unwrap();
    let old = folder.path().join("legacy.kcv");
    let path = folder.path().join("epoch.kcv");
    enable_recovery(&old, PW, RECOVERY, true).unwrap();
    let original = read(&old).unwrap();
    let first = enable_epoch_copy(&old, &path, PW).unwrap();
    assert_eq!(first.epoch, 1);
    assert_eq!(read(&old).unwrap(), original);
    assert_eq!(open_with_revision(&path, PW, false).unwrap().1, Some(first));
    assert_eq!(&open_with_recovery(&path, RECOVERY).unwrap()[..], b"[]");
    let second = save_with_revision(&path, PW, b"[]", false, Some(first))
        .unwrap()
        .unwrap();
    assert_eq!(second.vault_id, first.vault_id);
    assert_eq!(second.epoch, 2);
    let before = read(&path).unwrap();
    assert!(save_with_revision(&path, b"wrong", b"[]", false, Some(second)).is_err());
    assert!(save(&path, PW, &vec![0; MAX_FILE], false).is_err());
    assert_eq!(read(&path).unwrap(), before);
    let backup_path = folder.path().join("backup.kcv");
    assert_eq!(
        backup_with_revision(&path, &backup_path, PW, Some(second)).unwrap(),
        Some(second)
    );
    assert_eq!(read(&backup_path).unwrap(), before);
    let (_, third) = reset_password_with_revision(&path, RECOVERY, NEW, Some(second)).unwrap();
    assert_eq!(third.unwrap().epoch, 3);
    let fourth = enable_recovery_with_revision(&path, NEW, b"new recovery secret", false, third)
        .unwrap()
        .unwrap();
    assert_eq!(fourth.epoch, 4);
    assert_eq!(fourth.vault_id, first.vault_id);
    assert!(open_with_recovery(&path, RECOVERY).is_err());
    assert!(open_with_recovery(&path, b"new recovery secret").is_ok());
    assert_eq!(read(&old).unwrap(), original);
}

#[test]
fn epoch_identity_and_counter_are_authenticated_and_cannot_wrap() {
    let folder = tempfile::tempdir().unwrap();
    let old = folder.path().join("old.kcv");
    let path = folder.path().join("new.kcv");
    enable_recovery(&old, PW, RECOVERY, true).unwrap();
    enable_epoch_copy(&old, &path, PW).unwrap();
    let original = read(&path).unwrap();
    for offset in [
        0,
        5,
        20,
        21,
        28,
        29,
        29 + SLOT_LEN,
        EPOCH_AAD_LEN,
        original.len() - 1,
    ] {
        let mut damaged = original.clone();
        damaged[offset] ^= 1;
        assert!(open_bytes(&damaged, PW).is_err(), "offset {offset}");
        assert!(
            open_recoverable(&damaged, RECOVERY, 1).is_err(),
            "offset {offset}"
        );
    }
    for end in [
        4,
        28,
        29,
        EPOCH_AAD_LEN - 1,
        EPOCH_AAD_LEN + 23,
        original.len() - 1,
    ] {
        assert!(open_bytes(&original[..end], PW).is_err());
    }
    let (seed, data) = open_recoverable(&original, PW, 0).unwrap();
    let mut header = original[..EPOCH_AAD_LEN].to_vec();
    header[21..29].copy_from_slice(&u64::MAX.to_be_bytes());
    write_payload(&path, &payload_key(&seed).unwrap(), &header, &data, false).unwrap();
    let maximum = read(&path).unwrap();
    assert!(open(&path, PW).is_ok());
    assert!(save(&path, PW, b"[]", false).is_err());
    assert!(reset_password(&path, RECOVERY, NEW).is_err());
    assert!(enable_recovery(&path, PW, RECOVERY, false).is_err());
    assert!(change_password_with_revision(&path, PW, NEW, false, None, None).is_err());
    assert!(change_password_with_revision(&path, PW, NEW, true, Some(RECOVERY), None).is_err());
    assert_eq!(read(&path).unwrap(), maximum);
}

#[test]
fn authenticated_rollback_and_downgrade_are_rejected_when_a_floor_is_supplied() {
    let folder = tempfile::tempdir().unwrap();
    let old = folder.path().join("old.kcv");
    let path = folder.path().join("new.kcv");
    enable_recovery(&old, PW, RECOVERY, true).unwrap();
    let legacy = read(&old).unwrap();
    enable_epoch_copy(&old, &path, PW).unwrap();
    let older = read(&path).unwrap();
    let floor = save_with_revision(&path, PW, b"[]", false, None)
        .unwrap()
        .unwrap();
    for replaced in [older, legacy] {
        std::fs::write(&path, &replaced).unwrap();
        let observed = open_with_revision(&path, PW, false).unwrap().1;
        assert!(check_revision(observed, Some(floor)).is_err());
        assert!(save_with_revision(&path, PW, b"[]", false, Some(floor)).is_err());
        assert!(reset_password_with_revision(&path, RECOVERY, NEW, Some(floor)).is_err());
        assert!(enable_recovery_with_revision(&path, PW, RECOVERY, false, Some(floor)).is_err());
        assert!(
            backup_with_revision(&path, &folder.path().join("denied.kcv"), PW, Some(floor))
                .is_err()
        );
        assert_eq!(read(&path).unwrap(), replaced);
    }
}

#[test]
fn oversized_epoch_upgrade_does_not_change_or_create_files() {
    let folder = tempfile::tempdir().unwrap();
    let old = folder.path().join("old.kcv");
    let path = folder.path().join("new.kcv");
    enable_recovery(&old, PW, RECOVERY, true).unwrap();
    let mut data = b"[]".to_vec();
    data.resize(MAX_FILE - RECOVERY_AAD_LEN - 24 - 16, b' ');
    save(&old, PW, &data, false).unwrap();
    let before = read(&old).unwrap();
    assert!(enable_epoch_copy(&old, &path, PW).is_err());
    assert!(!path.exists());
    assert_eq!(read(&old).unwrap(), before);
}
