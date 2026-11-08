use kryptocore_signatures::{Purpose, SigningKey};
use kryptocore_verify::*;
use zeroize::Zeroizing;

fn fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    SigningKey,
    ReleaseManifest,
) {
    let folder = tempfile::tempdir().unwrap();
    let file = folder.path().join("vault-demo.zip");
    std::fs::write(&file, b"synthetic release bytes").unwrap();
    let key = SigningKey::from_seed(Zeroizing::new([7; 32]));
    let manifest = ReleaseManifest {
        schema: "kryptocore-release/v1".into(),
        product: "vault".into(),
        version: "test.1".into(),
        sequence: 2,
        issued_at: 100,
        expires_at: 200,
        source_commit: "a".repeat(40),
        artifacts: vec![describe(&file, "windows-x86_64").unwrap()],
    };
    (folder, file, key, manifest)
}

fn expected() -> Expected<'static> {
    Expected {
        product: "vault",
        version: "test.1",
        target: "windows-x86_64",
        min_sequence: 2,
        now: 150,
    }
}

#[test]
fn signed_download_matches_only_the_expected_publisher_and_release() {
    let (_dir, path, key, manifest) = fixture();
    let (bytes, signature) = sign(&manifest, &key).unwrap();
    check(
        &bytes,
        &signature,
        &key.verification_key(),
        &expected(),
        &path,
    )
    .unwrap();
    let attacker = SigningKey::from_seed(Zeroizing::new([9; 32]));
    let (_, forged) = sign(&manifest, &attacker).unwrap();
    assert!(check(&bytes, &forged, &key.verification_key(), &expected(), &path).is_err());
    let wrong_purpose = key.sign(Purpose::ContainerManifest, &bytes).unwrap();
    assert!(check(
        &bytes,
        &wrong_purpose.to_bytes(),
        &key.verification_key(),
        &expected(),
        &path
    )
    .is_err());
    assert!(check(
        &bytes,
        &signature[..63],
        &key.verification_key(),
        &expected(),
        &path
    )
    .is_err());
    for index in 0..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[index] ^= 1;
        assert!(check(
            &damaged,
            &signature,
            &key.verification_key(),
            &expected(),
            &path
        )
        .is_err());
    }
}

#[test]
fn metadata_expiry_future_dates_and_rollback_policy_are_enforced() {
    let (_dir, path, key, manifest) = fixture();
    let (bytes, signature) = sign(&manifest, &key).unwrap();
    let run = |expected| {
        check(
            &bytes,
            &signature,
            &key.verification_key(),
            &expected,
            &path,
        )
    };
    assert!(run(Expected {
        product: "msg",
        ..expected()
    })
    .is_err());
    assert!(run(Expected {
        version: "test.2",
        ..expected()
    })
    .is_err());
    assert!(run(Expected {
        target: "linux-x86_64",
        ..expected()
    })
    .is_err());
    assert!(run(Expected {
        min_sequence: 3,
        ..expected()
    })
    .is_err());
    assert!(run(Expected {
        now: 99,
        ..expected()
    })
    .is_err());
    assert!(run(Expected {
        now: 200,
        ..expected()
    })
    .is_err());
}

#[test]
fn corruption_renaming_truncation_extension_and_input_types_are_rejected() {
    let (dir, path, key, manifest) = fixture();
    let (bytes, signature) = sign(&manifest, &key).unwrap();
    let run = |path: &std::path::Path| {
        check(
            &bytes,
            &signature,
            &key.verification_key(),
            &expected(),
            path,
        )
    };
    std::fs::write(&path, b"synthetic release byteX").unwrap();
    assert!(run(&path).is_err());
    std::fs::write(&path, b"synthetic release bytes extra").unwrap();
    assert!(run(&path).is_err());
    std::fs::write(&path, b"short").unwrap();
    assert!(run(&path).is_err());
    let renamed = dir.path().join("other.zip");
    std::fs::write(&renamed, b"synthetic release bytes").unwrap();
    assert!(run(&renamed).is_err());
    assert!(run(dir.path()).is_err());
    #[cfg(unix)]
    {
        let link = dir.path().join("link.zip");
        std::os::unix::fs::symlink(&renamed, &link).unwrap();
        assert!(describe(&link, "linux-x86_64").is_err());
    }
}

#[test]
fn malformed_but_signed_manifests_and_resource_limits_fail_closed() {
    let (dir, path, key, mut manifest) = fixture();
    let valid = String::from_utf8(manifest.encode().unwrap()).unwrap();
    for text in [
        valid.replacen("{", "{\"product\":\"evil\",", 1),
        valid.replacen("{", "{\"unexpected\":true,", 1),
    ] {
        let signature = key.sign(Purpose::ReleaseManifest, text.as_bytes()).unwrap();
        assert!(check(
            text.as_bytes(),
            &signature.to_bytes(),
            &key.verification_key(),
            &expected(),
            &path
        )
        .is_err());
    }
    manifest.artifacts[0].file = "../vault-demo.zip".into();
    assert!(manifest.encode().is_err());
    manifest.artifacts[0] = describe(&path, "windows-x86_64").unwrap();
    manifest
        .artifacts
        .push(describe(&path, "linux-x86_64").unwrap());
    assert!(manifest.encode().is_err());
    let oversized = dir.path().join("oversized.json");
    std::fs::write(&oversized, vec![0; MAX_MANIFEST as usize + 1]).unwrap();
    assert!(read_bounded(&oversized, MAX_MANIFEST).is_err());
    assert!(parse_public(&format!("KCP1:{}", "00".repeat(32))).is_err());
}

#[test]
fn signing_keys_are_encrypted_and_existing_files_are_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dedicated-release-key.kcsk");
    let password = b"synthetic release signing key password";
    let signer = keys::generate(&path, password).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert_eq!(original.len(), 96);
    assert_eq!(
        keys::open(&path, password).unwrap().verification_key(),
        signer.verification_key()
    );
    assert!(keys::open(&path, b"wrong password").is_err());
    assert!(keys::generate(&path, password).is_err());
    assert!(publish(&path, b"overwrite").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn command_line_checks_real_files_and_returns_failure_after_tampering() {
    let (dir, path, key, mut manifest) = fixture();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    manifest.issued_at = now - 60;
    manifest.expires_at = now + 3600;
    let (bytes, signature) = sign(&manifest, &key).unwrap();
    let manifest_path = dir.path().join("release.json");
    let signature_path = dir.path().join("release.sig");
    std::fs::write(&manifest_path, bytes).unwrap();
    std::fs::write(&signature_path, signature).unwrap();
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kryptocore-verify"))
            .arg("check")
            .arg(&path)
            .arg(&manifest_path)
            .arg(&signature_path)
            .args([
                "--key",
                &public_code(key.verification_key()),
                "--product",
                "vault",
                "--version",
                "test.1",
                "--target",
                "windows-x86_64",
            ])
            .output()
            .unwrap()
    };
    let valid = run();
    assert!(valid.status.success());
    assert!(String::from_utf8(valid.stdout)
        .unwrap()
        .starts_with("VERIFIED:"));
    std::fs::write(&path, b"synthetic release byteX").unwrap();
    let invalid = run();
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8(invalid.stderr)
        .unwrap()
        .starts_with("NOT VERIFIED:"));
}
