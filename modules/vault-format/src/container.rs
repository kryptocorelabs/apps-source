use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    path::Path,
};

use kryptocore::{decrypt, derive_key, encrypt, Key, Salt};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const HEADER: &[u8] = b"KCV1\0";
const RECOVERY_HEADER: &[u8] = b"KCV2\0";
const SLOT_LEN: usize = 16 + 24 + 48;
const RECOVERY_AAD_LEN: usize = RECOVERY_HEADER.len() + 2 * SLOT_LEN;
const MAX_FILE: usize = 4 * 1024 * 1024;

fn read(path: &Path) -> Result<Vec<u8>, &'static str> {
    let mut file = Vec::new();
    File::open(path)
        .map_err(|_| "Tresor konnte nicht geöffnet werden")?
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut file)
        .map_err(|_| "Lesefehler")?;
    if file.len() > MAX_FILE {
        return Err("Tresor überschreitet das Vorschaulimit von 4 MiB");
    }
    Ok(file)
}

pub fn open(path: &Path, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let file = read(path)?;
    open_bytes(&file, password)
}

/// Read-only KCV2 recovery access. Does not reset a password or write to the source.
pub fn open_with_recovery(
    path: &Path,
    recovery: &[u8],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let file = read(path)?;
    open_recoverable(&file, recovery, 1).map(|(_, data)| data)
}

fn open_bytes(file: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if file.starts_with(RECOVERY_HEADER) {
        return open_recoverable(file, password, 0).map(|(_, data)| data);
    }
    let aad_len = HEADER.len() + 16;
    if file.len() < aad_len + 24 + 16 || !file.starts_with(HEADER) {
        return Err("Ungültiges Tresorformat oder Dateigröße");
    }
    let salt = file[HEADER.len()..aad_len]
        .try_into()
        .map_err(|_| "Ungültiges Salt")?;
    let nonce = file[aad_len..aad_len + 24]
        .try_into()
        .map_err(|_| "Ungültige Nonce")?;
    let key = derive_key(password, &salt).map_err(|_| "Schlüsselableitung fehlgeschlagen")?;
    decrypt(&key, &nonce, &file[aad_len + 24..], &file[..aad_len])
        .map_err(|_| "Falsches Tresorpasswort oder beschädigter Tresor")
}

pub fn save(path: &Path, password: &[u8], data: &[u8], create: bool) -> Result<(), &'static str> {
    if !create {
        let file = read(path)?;
        if file.starts_with(RECOVERY_HEADER) {
            let (seed, _) = open_recoverable(&file, password, 0)?;
            return write_payload(
                path,
                &payload_key(&seed)?,
                &file[..RECOVERY_AAD_LEN],
                data,
                false,
            );
        }
        if !file.starts_with(HEADER) {
            return Err("Unbekanntes Tresorformat");
        }
        // Authenticate the file being replaced, even when the caller opened an earlier copy.
        open_bytes(&file, password)?;
    }
    if data.len() > MAX_FILE - HEADER.len() - 16 - 24 - 16 {
        return Err("Tresor überschreitet das Vorschaulimit von 4 MiB");
    }
    let mut salt = Salt::default();
    getrandom::fill(&mut salt).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let key = derive_key(password, &salt).map_err(|_| "Schlüsselableitung fehlgeschlagen")?;
    let mut aad = HEADER.to_vec();
    aad.extend_from_slice(&salt);
    write_payload(path, &key, &aad, data, create)
}

fn write_payload(
    path: &Path,
    key: &Key,
    aad: &[u8],
    data: &[u8],
    create: bool,
) -> Result<(), &'static str> {
    if data.len() > MAX_FILE - aad.len() - 24 - 16 {
        return Err("Tresor überschreitet das Vorschaulimit von 4 MiB");
    }
    let (nonce, ciphertext) =
        encrypt(key, data, aad).map_err(|_| "Verschlüsselung fehlgeschlagen")?;
    write_file(path, &[aad, &nonce, &ciphertext], create)
}

pub fn backup(path: &Path, destination: &Path, password: &[u8]) -> Result<(), &'static str> {
    let file = read(path)?;
    let data = open_bytes(&file, password)?;
    serde_json::from_slice::<Vec<crate::Login>>(&data).map_err(|_| "Ungültige Tresoreinträge")?;
    write_file(destination, &[&file], true)
}

fn write_file(path: &Path, chunks: &[&[u8]], create: bool) -> Result<(), &'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)
        .map_err(|_| "Temporäre Datei konnte nicht erstellt werden")?;
    for chunk in chunks {
        temp.write_all(chunk)
            .map_err(|_| "Tresor konnte nicht gespeichert werden")?;
    }
    temp.as_file()
        .sync_all()
        .map_err(|_| "Tresor konnte nicht gespeichert werden")?;
    let result = if create {
        temp.persist_noclobber(path)
    } else {
        temp.persist(path)
    };
    result.map(|_| ()).map_err(|error| {
        if create && error.error.kind() == ErrorKind::AlreadyExists {
            "Datei existiert bereits. Wähle einen neuen Namen."
        } else {
            "Datei konnte nicht übernommen werden"
        }
    })
}

fn payload_key(seed: &[u8]) -> Result<Key, &'static str> {
    derive_key(seed, b"KCV2 payload key").map_err(|_| "Schlüsselableitung fehlgeschlagen")
}

fn slot_aad(role: u8) -> [u8; 6] {
    [b'K', b'C', b'V', b'2', 0, role]
}

fn append_slot(
    header: &mut Vec<u8>,
    secret: &[u8],
    role: u8,
    seed: &[u8],
) -> Result<(), &'static str> {
    let mut salt = Salt::default();
    getrandom::fill(&mut salt).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let key = derive_key(secret, &salt).map_err(|_| "Schlüsselableitung fehlgeschlagen")?;
    let (nonce, ciphertext) =
        encrypt(&key, seed, &slot_aad(role)).map_err(|_| "Verschlüsselung fehlgeschlagen")?;
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&ciphertext);
    Ok(())
}

type Opened = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn open_recoverable(file: &[u8], secret: &[u8], role: u8) -> Result<Opened, &'static str> {
    if !file.starts_with(RECOVERY_HEADER) || file.len() < RECOVERY_AAD_LEN + 24 + 16 {
        return Err("Dieser Tresor hat keinen lesbaren Wiederherstellungszugang");
    }
    let start = RECOVERY_HEADER.len() + usize::from(role) * SLOT_LEN;
    let slot = &file[start..start + SLOT_LEN];
    let salt = slot[..16].try_into().expect("fixed slot salt");
    let nonce = slot[16..40].try_into().expect("fixed slot nonce");
    let key = derive_key(secret, &salt).map_err(|_| "Schlüsselableitung fehlgeschlagen")?;
    let seed = decrypt(&key, &nonce, &slot[40..], &slot_aad(role))
        .map_err(|_| "Falscher Zugang oder beschädigter Tresor")?;
    let nonce = file[RECOVERY_AAD_LEN..RECOVERY_AAD_LEN + 24]
        .try_into()
        .expect("fixed payload nonce");
    let data = decrypt(
        &payload_key(&seed)?,
        &nonce,
        &file[RECOVERY_AAD_LEN + 24..],
        &file[..RECOVERY_AAD_LEN],
    )
    .map_err(|_| "Beschädigter Tresor")?;
    Ok((seed, data))
}

pub fn enable_recovery(
    path: &Path,
    password: &[u8],
    recovery: &[u8],
    create: bool,
) -> Result<(), &'static str> {
    let data = if create {
        Zeroizing::new(b"[]".to_vec())
    } else {
        let data = open(path, password)?;
        serde_json::from_slice::<Vec<crate::Login>>(&data)
            .map_err(|_| "Ungültige Tresoreinträge")?;
        data
    };
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let mut header = RECOVERY_HEADER.to_vec();
    append_slot(&mut header, password, 0, &seed[..])?;
    append_slot(&mut header, recovery, 1, &seed[..])?;
    write_payload(path, &payload_key(&seed[..])?, &header, &data, create)
}

pub fn reset_password(
    path: &Path,
    recovery: &[u8],
    password: &[u8],
) -> Result<Vec<crate::Login>, &'static str> {
    let file = read(path)?;
    let (seed, data) = open_recoverable(&file, recovery, 1)?;
    let entries = serde_json::from_slice(&data).map_err(|_| "Ungültige Tresoreinträge")?;
    let mut header = RECOVERY_HEADER.to_vec();
    append_slot(&mut header, password, 0, &seed)?;
    header.extend_from_slice(&file[RECOVERY_HEADER.len() + SLOT_LEN..RECOVERY_AAD_LEN]);
    write_payload(path, &payload_key(&seed)?, &header, &data, false)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECOVERY: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ENTRIES: &[u8] =
        br#"[{"origin":"https://example.invalid","username":"demo","password":"synthetic"}]"#;

    #[test]
    fn recovery_survives_migration_and_edits_and_replaces_the_old_password() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("recoverable.kcv");
        let old = b"old test vault password";
        let new = b"new test vault password";
        let recovery = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        save(&path, old, b"[]", true).unwrap();
        enable_recovery(&path, old, recovery, false).unwrap();
        assert_eq!(&open(&path, old).unwrap()[..], b"[]");
        save(&path, old, ENTRIES, false).unwrap();
        let before = read(&path).unwrap();
        assert!(reset_password(&path, b"wrong recovery", new).is_err());
        assert_eq!(read(&path).unwrap(), before);
        reset_password(&path, recovery, new).unwrap();
        assert!(open(&path, old).is_err());
        assert_eq!(&open(&path, new).unwrap()[..], ENTRIES);
    }

    #[test]
    fn kcv2_rejects_tampering_and_truncation() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("vault.kcv");
        let password = b"synthetic master password";
        enable_recovery(&path, password, RECOVERY, true).unwrap();
        save(&path, password, ENTRIES, false).unwrap();
        let original = read(&path).unwrap();
        let regions = [
            ("magic", 0),
            ("password salt", RECOVERY_HEADER.len()),
            ("password slot nonce", RECOVERY_HEADER.len() + 16),
            ("password slot tag", RECOVERY_HEADER.len() + SLOT_LEN - 1),
            ("recovery slot", RECOVERY_HEADER.len() + SLOT_LEN),
            ("payload nonce", RECOVERY_AAD_LEN),
            ("payload ciphertext", RECOVERY_AAD_LEN + 24),
            ("payload tag", original.len() - 1),
        ];
        for (region, offset) in regions {
            let mut damaged = original.clone();
            damaged[offset] ^= 1;
            assert!(open_bytes(&damaged, password).is_err(), "{region}");
            if region == "password salt" || region == "recovery slot" {
                assert!(open_recoverable(&damaged, RECOVERY, 1).is_err(), "{region}");
            }
        }
        for end in [
            0,
            4,
            RECOVERY_AAD_LEN - 1,
            RECOVERY_AAD_LEN + 23,
            original.len() - 1,
        ] {
            assert!(
                open_bytes(&original[..end], password).is_err(),
                "length {end}"
            );
        }
        assert_eq!(&open_bytes(&original, password).unwrap()[..], ENTRIES);
    }

    #[test]
    fn legacy_writes_authenticate_the_original() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("vault.kcv");
        let password = b"synthetic master password";
        save(&path, password, ENTRIES, true).unwrap();
        let legacy = read(&path).unwrap();
        assert!(save(&path, b"wrong password", b"[]", false).is_err());
        assert_eq!(read(&path).unwrap(), legacy);

        let mut damaged = legacy;
        *damaged.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &damaged).unwrap();
        assert!(save(&path, password, b"[]", false).is_err());
        assert_eq!(read(&path).unwrap(), damaged);
    }

    #[test]
    fn recovery_rejects_invalid_entries_before_replacing_the_password() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("recovery.kcv");
        let password = b"synthetic master password";
        enable_recovery(&path, password, RECOVERY, true).unwrap();
        save(&path, password, b"invalid JSON", false).unwrap();
        let invalid = read(&path).unwrap();
        assert!(reset_password(&path, RECOVERY, b"new synthetic password").is_err());
        assert_eq!(read(&path).unwrap(), invalid);
        assert!(enable_recovery(&path, password, RECOVERY, false).is_err());
        assert_eq!(read(&path).unwrap(), invalid);
    }

    #[test]
    fn oversized_read_and_write_leave_original_bytes_intact() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("recovery.kcv");
        let password = b"synthetic master password";
        enable_recovery(&path, password, RECOVERY, true).unwrap();
        let original = read(&path).unwrap();
        assert!(save(&path, password, &vec![0; MAX_FILE], false).is_err());
        assert_eq!(read(&path).unwrap(), original);

        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_FILE as u64 + 1)
            .unwrap();
        let oversized = std::fs::read(&path).unwrap();
        assert!(open(&path, password).is_err());
        assert!(save(&path, password, b"[]", false).is_err());
        assert!(reset_password(&path, RECOVERY, b"new synthetic password").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), oversized);
    }

    #[test]
    fn verified_backups_keep_the_original_bytes_and_restore_independently() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("original.kcv");
        let legacy = folder.path().join("legacy-backup.kcv");
        let snapshot = folder.path().join("recovery-backup.kcv");
        let rejected = folder.path().join("rejected.kcv");
        let old = b"old test vault password";
        let new = b"new test vault password";
        let recovery = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let entries =
            br#"[{"origin":"https://example.invalid","username":"demo","password":"synthetic"}]"#;

        save(&path, old, entries, true).unwrap();
        backup(&path, &legacy, old).unwrap();
        assert_eq!(read(&legacy).unwrap(), read(&path).unwrap());
        assert_eq!(&open(&legacy, old).unwrap()[..], entries);
        enable_recovery(&path, old, recovery, false).unwrap();
        let original = read(&path).unwrap();
        backup(&path, &snapshot, old).unwrap();
        assert_eq!(read(&snapshot).unwrap(), original);
        assert!(backup(&path, &legacy, old).is_err());
        assert_eq!(&open(&legacy, old).unwrap()[..], entries);
        assert!(backup(&path, &path, old).is_err());
        assert_eq!(read(&path).unwrap(), original);

        reset_password(&snapshot, recovery, new).unwrap();
        assert_eq!(&open(&snapshot, new).unwrap()[..], entries);
        assert_eq!(read(&path).unwrap(), original);

        save(&path, old, b"invalid JSON", false).unwrap();
        assert!(backup(&path, &rejected, old).is_err());
        let mut corrupt = original;
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(backup(&path, &rejected, old).is_err());
        assert!(!rejected.exists());
        assert_eq!(&open(&snapshot, new).unwrap()[..], entries);
    }
}
