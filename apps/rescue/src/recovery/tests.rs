use super::*;

const PASSWORD: &[u8] = b"synthetic test password only";
const RECOVERY: &[u8] = b"synthetic recovery credential only";
struct TestDirectory {
    _owner: tempfile::TempDir,
    canonical: std::path::PathBuf,
}
impl TestDirectory {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        // macOS /var and /tmp are symlinks. Select the actual trusted folder,
        // keeping the production rejection of linked destinations intact.
        let canonical = owner.path().canonicalize().unwrap();
        Self {
            _owner: owner,
            canonical,
        }
    }
    fn path(&self) -> &Path {
        &self.canonical
    }
}
const ENTRIES: &[u8] =
    br#"[{"origin":"example.test","username":"synthetic user","password":"synthetic secret"}]"#;

#[test]
fn vault_legacy_and_recovery_slot_export_without_touching_sources() {
    let dir = TestDirectory::new();
    let input = dir.path().join("source.kcv");
    kryptocore_vault_format::save(&input, PASSWORD, ENTRIES, true).unwrap();
    let before = fs::read(&input).unwrap();
    let legacy = dir.path().join("legacy.json");
    let result = recover(&input, &legacy, CredentialRoute::Password, PASSWORD, true).unwrap();
    assert_eq!(result.entries, 1);
    assert!(result.content_authenticated);
    assert_eq!(fs::read(&legacy).unwrap(), ENTRIES);
    assert_eq!(fs::read(&input).unwrap(), before);
    kryptocore_vault_format::enable_recovery(&input, PASSWORD, RECOVERY, false).unwrap();
    let before = fs::read(&input).unwrap();
    for (name, route, secret) in [
        ("password.json", CredentialRoute::Password, PASSWORD),
        ("recovery.json", CredentialRoute::RecoveryKey, RECOVERY),
    ] {
        recover(&input, &dir.path().join(name), route, secret, true).unwrap();
        assert_eq!(fs::read(dir.path().join(name)).unwrap(), ENTRIES);
        assert_eq!(fs::read(&input).unwrap(), before);
    }
    assert!(!dir.path().join("source.kcv.lock").exists());
}

#[test]
fn vault_backup_check_authenticates_and_never_creates_an_output() {
    let dir = TestDirectory::new();
    let source = dir.path().join("backup.kcv");
    let versioned = dir.path().join("versioned.kcv");
    kryptocore_vault_format::save(&source, PASSWORD, ENTRIES, true).unwrap();
    let check = check_vault(&source, CredentialRoute::Password, PASSWORD).unwrap();
    assert_eq!(check.format, Format::VaultV1);
    assert_eq!(check.entries, 1);
    assert!(matches!(
        check_vault(&source, CredentialRoute::RecoveryKey, RECOVERY),
        Err(RecoveryError::Credential)
    ));

    kryptocore_vault_format::enable_recovery(&source, PASSWORD, RECOVERY, false).unwrap();
    kryptocore_vault_format::enable_epoch_copy(&source, &versioned, PASSWORD).unwrap();
    for (path, format) in [(&source, Format::VaultV2), (&versioned, Format::VaultV3)] {
        let original = fs::read(path).unwrap();
        for (route, secret) in [
            (CredentialRoute::Password, PASSWORD),
            (CredentialRoute::RecoveryKey, RECOVERY),
        ] {
            let check = check_vault(path, route, secret).unwrap();
            assert!(check.content_authenticated);
            assert_eq!(check.format, format);
            assert_eq!(check.entries, 1);
        }
        assert!(matches!(
            check_vault(path, CredentialRoute::RecoveryKey, b"wrong"),
            Err(RecoveryError::AuthenticationOrData)
        ));
        assert_eq!(fs::read(path).unwrap(), original);
        let mut damaged = original;
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(path, &damaged).unwrap();
        assert!(matches!(
            check_vault(path, CredentialRoute::Password, PASSWORD),
            Err(RecoveryError::AuthenticationOrData)
        ));
        assert_eq!(fs::read(path).unwrap(), damaged);
    }
    let invalid = dir.path().join("invalid.kcv");
    kryptocore_vault_format::save(&invalid, PASSWORD, b"not JSON", true).unwrap();
    assert!(matches!(
        check_vault(&invalid, CredentialRoute::Password, PASSWORD),
        Err(RecoveryError::AuthenticationOrData)
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
}

#[test]
fn wrong_credentials_damage_and_invalid_records_never_publish_vault_output() {
    let dir = TestDirectory::new();
    let input = dir.path().join("source.kcv");
    let output = dir.path().join("export.json");
    kryptocore_vault_format::save(&input, PASSWORD, ENTRIES, true).unwrap();
    let before = fs::read(&input).unwrap();
    assert!(recover(&input, &output, CredentialRoute::Password, b"wrong", true).is_err());
    assert!(!output.exists());
    let mut damaged = before.clone();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&input, &damaged).unwrap();
    assert!(recover(&input, &output, CredentialRoute::Password, PASSWORD, true).is_err());
    assert_eq!(fs::read(&input).unwrap(), damaged);
    assert!(!output.exists());
    let invalid = dir.path().join("invalid.kcv");
    kryptocore_vault_format::save(&invalid, PASSWORD, b"not JSON", true).unwrap();
    assert!(recover(&invalid, &output, CredentialRoute::Password, PASSWORD, true).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn plaintext_confirmation_and_no_overwrite_are_mandatory() {
    let dir = TestDirectory::new();
    let input = dir.path().join("source.kcv");
    let output = dir.path().join("existing.json");
    kryptocore_vault_format::save(&input, PASSWORD, ENTRIES, true).unwrap();
    let before = fs::read(&input).unwrap();
    assert!(matches!(
        recover(&input, &output, CredentialRoute::Password, PASSWORD, false),
        Err(RecoveryError::PlaintextNotConfirmed)
    ));
    assert!(!output.exists());
    fs::write(&output, b"preserve").unwrap();
    assert!(matches!(
        recover(&input, &output, CredentialRoute::Password, PASSWORD, true),
        Err(RecoveryError::InvalidDestination)
    ));
    assert_eq!(fs::read(&output).unwrap(), b"preserve");
    assert!(recover(&input, &input, CredentialRoute::Password, PASSWORD, true).is_err());
    assert_eq!(fs::read(&input).unwrap(), before);
}

#[test]
fn ordinary_and_executable_containers_reuse_the_authenticated_extractor() {
    let dir = TestDirectory::new();
    let plain = dir.path().join("synthetic.txt");
    fs::write(&plain, b"example data").unwrap();
    let archive = dir.path().join("source.kcc");
    kryptocore_container::pack(&archive, &[plain.clone()], PASSWORD).unwrap();
    let before = fs::read(&archive).unwrap();
    let output = dir.path().join("restored");
    assert!(recover(&archive, &output, CredentialRoute::Password, b"wrong", true).is_err());
    assert!(!output.exists());
    recover(&archive, &output, CredentialRoute::Password, PASSWORD, true).unwrap();
    assert_eq!(
        fs::read(output.join("synthetic.txt")).unwrap(),
        b"example data"
    );
    assert!(recover(&archive, &output, CredentialRoute::Password, PASSWORD, true).is_err());
    assert_eq!(fs::read(&archive).unwrap(), before);
    let stub = dir.path().join("stub.exe");
    fs::write(&stub, b"synthetic wrapper, never execute").unwrap();
    let wrapped = dir.path().join("source.exe");
    kryptocore_container::pack_executable(&stub, &wrapped, &[plain], PASSWORD).unwrap();
    let output2 = dir.path().join("restored-wrapper");
    recover(
        &wrapped,
        &output2,
        CredentialRoute::Password,
        PASSWORD,
        true,
    )
    .unwrap();
    assert_eq!(
        fs::read(output2.join("synthetic.txt")).unwrap(),
        b"example data"
    );
    let mut damaged = before;
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&archive, &damaged).unwrap();
    let rejected = dir.path().join("rejected");
    assert!(recover(
        &archive,
        &rejected,
        CredentialRoute::Password,
        PASSWORD,
        true
    )
    .is_err());
    assert!(!rejected.exists());
    assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".kcc-")));
}
