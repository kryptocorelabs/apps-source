use super::*;

const PASS: &[u8] = b"test-only-password-8724";
const HEADER: usize = 115;

#[test]
fn executable_payload_round_trip_rejects_modified_content_and_footer() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let opener = root.join("opener.exe");
    let source = root.join("sample.txt");
    let bundle = root.join("delivery.exe");
    let output = root.join("received");
    let opener_bytes = b"test opener prefix";
    let contents = b"test file contents";
    fs::write(&opener, opener_bytes).unwrap();
    fs::write(&source, contents).unwrap();
    pack_executable(&opener, &bundle, &[source], PASS).unwrap();
    let original = fs::read(&bundle).unwrap();
    assert!(original.starts_with(opener_bytes));
    assert!(!original
        .windows(contents.len())
        .any(|window| window == contents));
    assert!(
        unpack_executable_with_inspection(&bundle, &output, b"wrong password", |_| Ok(())).is_err()
    );
    assert!(!output.exists());
    for offset in [original.len() - 25, original.len() - 24, original.len() - 1] {
        let mut modified = original.clone();
        modified[offset] ^= 1;
        fs::write(&bundle, modified).unwrap();
        assert!(unpack_executable_with_inspection(&bundle, &output, PASS, |_| Ok(())).is_err());
        assert!(!output.exists());
    }
    fs::write(&bundle, original).unwrap();
    check_executable(&bundle, PASS).unwrap();
    unpack_executable_with_inspection(&bundle, &output, PASS, |_| Ok(())).unwrap();
    assert_eq!(fs::read(output.join("sample.txt")).unwrap(), contents);
}

#[test]
#[ignore = "writes about 1 GiB to disk; run for release verification"]
fn streams_a_file_larger_than_the_argon2_work_buffer() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let source = root.join("large.bin");
    let archive = root.join("large.kcc");
    let output = root.join("out");
    let mut file = File::create(&source).unwrap();
    let mut expected = Sha256::new();
    let mut buffer = [0x7a; CHUNK];
    for index in 0..(320u32 * 1024 * 1024 / CHUNK as u32) {
        buffer[..4].copy_from_slice(&index.to_be_bytes());
        file.write_all(&buffer).unwrap();
        expected.update(buffer);
    }
    drop(file);
    assert_eq!(
        pack(&archive, &[source], PASS).unwrap().bytes,
        320 * 1024 * 1024
    );
    assert_eq!(
        unpack(&archive, &output, PASS).unwrap().bytes,
        320 * 1024 * 1024
    );
    let mut reader = signature::HashReader::new(BufReader::new(
        File::open(output.join("large.bin")).unwrap(),
    ));
    io::copy(&mut reader, &mut io::sink()).unwrap();
    assert_eq!(reader.finish(), <[u8; 32]>::from(expected.finalize()));
}

#[test]
fn round_trip_nested_unicode_empty_and_multiple_chunks() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let source = root.join("documents");
    fs::create_dir_all(source.join("empty-dir")).unwrap();
    fs::write(source.join("empty"), []).unwrap();
    let data: Vec<_> = (0..2 * CHUNK + 31).map(|i| (i % 251) as u8).collect();
    fs::write(source.join("Grüße.bin"), &data).unwrap();
    let archive = root.join("test.kcc");
    let output = root.join("output");
    let packed = pack(&archive, &[source], PASS).unwrap();
    assert_eq!(
        packed,
        Summary {
            entries: 4,
            bytes: data.len() as u64
        }
    );
    assert_eq!(packed, check(&archive, PASS).unwrap());
    assert_eq!(packed, unpack(&archive, &output, PASS).unwrap());
    assert_eq!(data, fs::read(output.join("documents/Grüße.bin")).unwrap());
    assert!(output.join("documents/empty-dir").is_dir());
    assert_eq!(
        fs::metadata(output.join("documents/empty")).unwrap().len(),
        0
    );
    assert!(unpack(&archive, &output, PASS).is_err());
    assert_eq!(data, fs::read(output.join("documents/Grüße.bin")).unwrap());
}

#[test]
fn mutations_and_failed_scan_never_publish_plaintext() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let source = root.join("document");
    let contents: Vec<_> = (0..2 * CHUNK + 32)
        .map(|offset| (offset / CHUNK) as u8)
        .collect();
    fs::write(&source, contents).unwrap();
    let archive = root.join("test.kcc");
    pack(&archive, &[source.clone()], PASS).unwrap();
    let original = fs::read(&archive).unwrap();
    assert!(pack(&archive, &[source], PASS).is_err());
    let output = root.join("out");
    assert!(matches!(
        unpack(&archive, &output, b"incorrect"),
        Err(Error::Authentication)
    ));
    assert!(!output.exists());
    assert!(matches!(
        unpack_with_inspection(&archive, &output, PASS, |stage| {
            assert!(stage.join("document").is_file());
            assert!(!output.exists());
            Err(Error::ScanRejected)
        }),
        Err(Error::ScanRejected)
    ));
    assert!(!output.exists());

    let mut variants = Vec::new();
    for offset in [0, 8, 24, 43, 67, HEADER + 5, original.len() - 1] {
        let mut mutation = original.clone();
        mutation[offset] ^= 1;
        variants.push(mutation);
    }
    let mut oversized = original.clone();
    oversized[HEADER + 1..HEADER + 5].fill(255);
    variants.push(oversized);
    let mut extra = original.clone();
    extra.push(0);
    variants.push(extra);
    for end in [
        0,
        HEADER - 1,
        HEADER + 5,
        original.len() - 21,
        original.len() - 1,
    ] {
        variants.push(original[..end].to_vec());
    }
    // Swap two complete data frames of equal length. Framing remains valid,
    // so rejection depends on authenticating the frame position.
    let entry_bytes = 5 + 9 + "document".len() + TAG;
    let frame_bytes = 5 + CHUNK + TAG;
    let first = HEADER + entry_bytes;
    let second = first + frame_bytes;
    let end = second + frame_bytes;
    let mut reordered = original.clone();
    reordered[first..second].copy_from_slice(&original[second..end]);
    reordered[second..end].copy_from_slice(&original[first..second]);
    // Equal-length frames also cannot be copied from a separately encrypted container.
    let other = root.join("other.kcc");
    pack(&other, &[root.join("document")], PASS).unwrap();
    let other = fs::read(other).unwrap();
    let mut spliced = original.clone();
    spliced[HEADER..].copy_from_slice(&other[HEADER..]);
    variants.push(spliced);

    let corrupt = root.join("bad.kcc");
    fs::write(&corrupt, reordered).unwrap();
    assert!(matches!(
        unpack(&corrupt, &output, PASS),
        Err(Error::Authentication)
    ));
    assert!(!output.exists());
    for (index, mutation) in variants.iter().enumerate() {
        fs::write(&corrupt, mutation).unwrap();
        assert!(unpack(&corrupt, &output, PASS).is_err(), "mutation {index}");
        assert!(!output.exists(), "mutation {index}");
    }
    assert_eq!(original, fs::read(&archive).unwrap());
    assert!(!fs::read_dir(root).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".kcc-")));
}

#[test]
fn even_authenticated_unsafe_names_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let archive = root.join("adversarial.kcc");
    let destination = root.join("out");
    for names in [
        vec![(false, "../escaped")],
        vec![(true, "safe"), (false, "safe/../../escaped")],
        vec![(true, "safe"), (false, r"safe\..\escaped")],
        vec![(false, "/absolute")],
        vec![(false, r"\\host\share\file")],
        vec![(false, r"C:\root")],
        vec![(false, "file:stream")],
        vec![(false, "NUL.txt")],
        vec![(false, "COM¹.txt")],
        vec![(false, "folder/child")],
        vec![(false, "a"), (false, "a/child")],
        vec![(true, "a"), (false, "A")],
        vec![(true, "a"), (false, "A/child")],
    ] {
        let mut bytes = Vec::new();
        let mut cipher = begin_write(&mut bytes, PASS).unwrap();
        for (directory, name) in names {
            let mut metadata = vec![u8::from(directory); 1];
            metadata.extend_from_slice(&0u64.to_be_bytes());
            metadata.extend_from_slice(name.as_bytes());
            write_frame(&mut bytes, &mut cipher, ENTRY, &metadata).unwrap();
        }
        write_end(&mut bytes, cipher).unwrap();
        fs::write(&archive, &bytes).unwrap();
        assert!(check(&archive, PASS).is_err());
        assert!(unpack(&archive, &destination, PASS).is_err());
        assert!(!destination.exists());
        assert!(!root.join("escaped").exists());
    }
}

#[test]
fn unsafe_components_remain_invalid_between_valid_components() {
    for parent in ["docs", "Grüße", "目录"] {
        for child in ["file", "report.txt", "摘要"] {
            let mut entries = Entries::default();
            entries.add(parent, true, 0).unwrap();
            for component in ["", ".", "..", "NUL.txt", "drive:", "trail.", r"..\escape"] {
                let path = format!("{parent}/{component}/{child}");
                assert!(entries.add(&path, false, 1).is_err(), "{path}");
            }
            entries.add(&format!("{parent}/{child}"), false, 1).unwrap();
            assert_eq!(
                entries.summary,
                Summary {
                    entries: 2,
                    bytes: 1
                }
            );
        }
    }
}

#[test]
fn refuses_to_pack_a_link_or_write_into_a_source_folder() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    let target = source.join("self.kcc");
    assert!(pack(&target, &[source], PASS).is_err());
    assert!(!target.exists());
    let file = root.join("secret");
    fs::write(&file, b"should never follow a link").unwrap();
    let link = root.join("link");
    #[cfg(unix)]
    let created = std::os::unix::fs::symlink(&file, &link);
    #[cfg(windows)]
    let created = std::os::windows::fs::symlink_file(&file, &link);
    if created.is_ok() {
        assert!(pack(&root.join("link.kcc"), &[link], PASS).is_err());
    }
}

#[test]
fn openssh_signature_binds_sender_and_exact_container_bytes() {
    use std::process::{Command, Stdio};
    let ssh = std::env::var_os("KCC_TEST_SSH_KEYGEN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ssh-keygen"));
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let key = root.join("ed25519");
    let status = Command::new(&ssh)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .stdin(Stdio::null())
        .status();
    match status {
        Err(err)
            if err.kind() == io::ErrorKind::NotFound
                && std::env::var_os("KCC_TEST_SSH_KEYGEN").is_none() =>
        {
            eprintln!("Skipping OpenSSH integration test: ssh-keygen unavailable.");
            return;
        }
        status => assert!(status.unwrap().success()),
    }
    let public_key = fs::read_to_string(root.join("ed25519.pub")).unwrap();
    let allowed = root.join("allowed_signers");
    fs::write(&allowed, format!("alice {}", public_key)).unwrap();
    let source = root.join("source");
    fs::write(&source, b"test data").unwrap();
    let archive = root.join("signed.kcc");
    pack(&archive, &[source], PASS).unwrap();
    let signature = root.join("signed.sig");
    signature::sign(&ssh, &key, &archive, &signature).unwrap();
    let alice = signature::Verification {
        ssh_keygen: &ssh,
        allowed_signers: &allowed,
        principal: "alice",
        signature: &signature,
    };
    alice.verify(&archive).unwrap();
    let wrong_sender = signature::Verification {
        principal: "mallory",
        ..alice
    };
    let output = root.join("out");
    assert!(
        unpack_signed_with_inspection(&archive, &output, PASS, &wrong_sender, |_| panic!(
            "must not scan an unverified file"
        ))
        .is_err()
    );
    assert!(!output.exists());
    unpack_signed_with_inspection(&archive, &output, PASS, &alice, |_| Ok(())).unwrap();
    assert_eq!(fs::read(output.join("source")).unwrap(), b"test data");
    OpenOptions::new()
        .append(true)
        .open(&archive)
        .unwrap()
        .write_all(b"x")
        .unwrap();
    assert!(alice.verify(&archive).is_err());
}
