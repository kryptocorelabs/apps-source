use super::*;

#[test]
fn sidecar_readers_reject_directories_and_preserve_them() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("identity.kcmi");
    let identity = Identity::generate().unwrap();
    for suffix in [".contacts", ".blocked", ".verification", ".policy", ".onion-key"] {
        let leaf = root.path().join(format!("identity.kcmi{suffix}"));
        fs::create_dir(&leaf).unwrap();
        assert!(matches!(regular_store_file(&leaf), Err(Error::Identity)));
        assert!(leaf.is_dir());
    }
    assert!(ContactBook::open(&path, &identity).unwrap().read().is_err());
    assert!(ContactBook::open(&path, &identity).unwrap().write(b"[]").is_err());
    assert!(ContactBook::blocked(&path, &identity).unwrap().read().is_err());
    assert!(ContactBook::verification(&path, &identity).unwrap().read().is_err());
    assert!(ContactBook::require_two_codes(&path, &identity).is_err());
    assert!(OnionKeyStore::open(&path, &identity).unwrap().read().is_err());
}

#[test]
fn sidecar_locks_reject_non_files_before_opening_them() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("identity.kcmi");
    let identity = Identity::generate().unwrap();
    for suffix in [".contacts", ".blocked", ".verification", ".policy", ".onion-key"] {
        let leaf = root.path().join(format!("identity.kcmi{suffix}.lock"));
        fs::create_dir(&leaf).unwrap();
        assert!(matches!(store_lock(&leaf), Err(Error::Identity)));
        assert!(leaf.is_dir());
    }
    assert!(ContactBook::open(&path, &identity).is_err());
    assert!(ContactBook::blocked(&path, &identity).is_err());
    assert!(ContactBook::verification(&path, &identity).is_err());
    assert!(ContactBook::set_require_two_codes(&path, &identity, true).is_err());
    assert!(OnionKeyStore::open(&path, &identity).is_err());
}

#[cfg(unix)]
#[test]
fn linked_sidecars_and_locks_are_rejected_without_modifying_targets() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let identity = Identity::generate().unwrap();
    let source = root.path().join("original.kcmi");
    let contacts = ContactBook::open(&source, &identity).unwrap();
    contacts.write(b"synthetic private contacts").unwrap();
    drop(contacts);
    let encrypted = root.path().join("original.kcmi.contacts");
    let original = fs::read(&encrypted).unwrap();
    let path = root.path().join("linked.kcmi");
    symlink(&encrypted, root.path().join("linked.kcmi.contacts")).unwrap();
    let linked = ContactBook::open(&path, &identity).unwrap();
    assert!(matches!(linked.read(), Err(Error::Identity)));
    assert!(matches!(linked.write(b"[]"), Err(Error::Identity)));
    assert!(fs::symlink_metadata(root.path().join("linked.kcmi.contacts"))
        .unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&encrypted).unwrap(), original);

    for suffix in [".blocked", ".verification", ".policy", ".onion-key"] {
        let leaf = root.path().join(format!("linked.kcmi{suffix}"));
        symlink(&encrypted, &leaf).unwrap();
        assert!(matches!(regular_store_file(&leaf), Err(Error::Identity)));
    }
    let lock_target = root.path().join("lock-target");
    fs::write(&lock_target, b"unchanged lock target").unwrap();
    let lock = root.path().join("linked.kcmi.onion-key.lock");
    symlink(&lock_target, &lock).unwrap();
    assert!(OnionKeyStore::open(&path, &identity).is_err());
    assert_eq!(fs::read(&lock_target).unwrap(), b"unchanged lock target");
    assert_eq!(fs::read(&encrypted).unwrap(), original);
}
