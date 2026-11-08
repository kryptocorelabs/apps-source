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
const EPOCH_HEADER: &[u8] = b"KCV3\0";
const EPOCH_PREFIX: usize = 5 + 16 + 8;
const EPOCH_AAD_LEN: usize = EPOCH_PREFIX + 2 * SLOT_LEN;
const MAX_FILE: usize = 4 * 1024 * 1024;

#[cfg(test)]
#[path = "epoch_tests.rs"]
mod epoch_tests;

#[cfg(test)]
#[path = "migration_tests.rs"]
mod migration_tests;

#[cfg(test)]
#[path = "password_tests.rs"]
mod password_tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub vault_id: [u8; 16],
    pub epoch: u64,
}

/// Format facts derived from the same authenticated bytes as the plaintext.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct VaultMetadata {
    pub format_version: u8,
    pub recovery_available: bool,
    pub revision: Option<Revision>,
}

pub const REVISION_REJECTED: &str = "Älterer oder anderer Tresorstand erkannt. Nutze für die bewusste Rettung eine Kopie in Rescue.";

/// Caller-owned freshness policy; this is not an external trusted counter.
pub fn check_revision(
    observed: Option<Revision>,
    minimum: Option<Revision>,
) -> Result<(), &'static str> {
    if let Some(minimum) = minimum {
        if !observed.is_some_and(|r| r.vault_id == minimum.vault_id && r.epoch >= minimum.epoch) {
            return Err(REVISION_REJECTED);
        }
    }
    Ok(())
}

fn layout(file: &[u8]) -> Result<(usize, usize), &'static str> {
    let (slots, aad) = if file.starts_with(RECOVERY_HEADER) {
        (5, RECOVERY_AAD_LEN)
    } else if file.starts_with(EPOCH_HEADER) {
        (EPOCH_PREFIX, EPOCH_AAD_LEN)
    } else {
        return Err("Dieser Tresor hat keinen lesbaren Wiederherstellungszugang");
    };
    if file.len() < aad + 24 + 16 {
        return Err("Ungültiges Tresorformat oder Dateigröße");
    }
    if slots == EPOCH_PREFIX
        && u64::from_be_bytes(file[21..29].try_into().expect("checked epoch")) == 0
    {
        return Err("Ungültige Tresorepoche");
    }
    Ok((slots, aad))
}

// Only expose this metadata after payload authentication.
fn revision(file: &[u8]) -> Option<Revision> {
    file.starts_with(EPOCH_HEADER).then(|| Revision {
        vault_id: file[5..21].try_into().expect("validated layout"),
        epoch: u64::from_be_bytes(file[21..29].try_into().expect("validated layout")),
    })
}

fn advanced_header(file: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (_, aad) = layout(file)?;
    let mut header = file[..aad].to_vec();
    if let Some(r) = revision(file) {
        let next = r
            .epoch
            .checked_add(1)
            .ok_or("Tresorepoche ist ausgeschöpft")?;
        header[21..29].copy_from_slice(&next.to_be_bytes());
    }
    Ok(header)
}

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

pub fn open_with_revision(
    path: &Path,
    secret: &[u8],
    recovery: bool,
) -> Result<(Zeroizing<Vec<u8>>, Option<Revision>), &'static str> {
    let (data, metadata) = open_with_metadata(path, secret, recovery)?;
    Ok((data, metadata.revision))
}

pub fn open_with_metadata(
    path: &Path,
    secret: &[u8],
    recovery: bool,
) -> Result<(Zeroizing<Vec<u8>>, VaultMetadata), &'static str> {
    let file = read(path)?;
    let data = if recovery {
        open_recoverable(&file, secret, 1)?.1
    } else {
        open_bytes(&file, secret)?
    };
    let format_version = if file.starts_with(EPOCH_HEADER) {
        3
    } else if file.starts_with(RECOVERY_HEADER) {
        2
    } else {
        1
    };
    Ok((
        data,
        VaultMetadata {
            format_version,
            recovery_available: format_version >= 2,
            revision: revision(&file),
        },
    ))
}

/// Explicit opt-in copy. Original bytes, slots, seed and recovery access stay valid.
pub fn enable_epoch_copy(
    path: &Path,
    destination: &Path,
    password: &[u8],
) -> Result<Revision, &'static str> {
    let file = read(path)?;
    if !file.starts_with(RECOVERY_HEADER) {
        return Err(
            "Richte zuerst ein Notfallblatt ein. Die Aktivierung erwartet einen KCV2-Tresor.",
        );
    }
    let (seed, data) = open_recoverable(&file, password, 0)?;
    serde_json::from_slice::<Vec<crate::Login>>(&data).map_err(|_| "Ungültige Tresoreinträge")?;
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let mut header = EPOCH_HEADER.to_vec();
    header.extend_from_slice(&id);
    header.extend_from_slice(&1u64.to_be_bytes());
    header.extend_from_slice(&file[5..RECOVERY_AAD_LEN]);
    write_payload(destination, &payload_key(&seed)?, &header, &data, true)?;
    Ok(Revision {
        vault_id: id,
        epoch: 1,
    })
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
    if file.starts_with(RECOVERY_HEADER) || file.starts_with(EPOCH_HEADER) {
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
    save_with_revision(path, password, data, create, None).map(|_| ())
}

pub fn save_with_revision(
    path: &Path,
    password: &[u8],
    data: &[u8],
    create: bool,
    minimum: Option<Revision>,
) -> Result<Option<Revision>, &'static str> {
    if create && minimum.is_some() {
        return Err("Neue Datei darf keinen bestehenden Versionsbezug ersetzen");
    }
    if !create {
        let file = read(path)?;
        if file.starts_with(RECOVERY_HEADER) || file.starts_with(EPOCH_HEADER) {
            let (seed, _) = open_recoverable(&file, password, 0)?;
            check_revision(revision(&file), minimum)?;
            let header = advanced_header(&file)?;
            write_payload(path, &payload_key(&seed)?, &header, data, false)?;
            return Ok(revision(&header));
        }
        if !file.starts_with(HEADER) {
            return Err("Unbekanntes Tresorformat");
        }
        // Authenticate the file being replaced, even when the caller opened an earlier copy.
        open_bytes(&file, password)?;
        check_revision(None, minimum)?;
    }
    if data.len() > MAX_FILE - HEADER.len() - 16 - 24 - 16 {
        return Err("Tresor überschreitet das Vorschaulimit von 4 MiB");
    }
    let mut salt = Salt::default();
    getrandom::fill(&mut salt).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let key = derive_key(password, &salt).map_err(|_| "Schlüsselableitung fehlgeschlagen")?;
    let mut aad = HEADER.to_vec();
    aad.extend_from_slice(&salt);
    write_payload(path, &key, &aad, data, create)?;
    Ok(None)
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
    backup_with_revision(path, destination, password, None).map(|_| ())
}

pub fn backup_with_revision(
    path: &Path,
    destination: &Path,
    password: &[u8],
    minimum: Option<Revision>,
) -> Result<Option<Revision>, &'static str> {
    let (file, observed) = verified_snapshot(path, password, minimum)?;
    write_file(destination, &[&file], true)?;
    Ok(observed)
}

/// Return the exact authenticated ciphertext snapshot, never plaintext or keys.
pub fn verified_snapshot(
    path: &Path,
    password: &[u8],
    minimum: Option<Revision>,
) -> Result<(Vec<u8>, Option<Revision>), &'static str> {
    let file = read(path)?;
    let data = open_bytes(&file, password)?;
    let observed = revision(&file);
    check_revision(observed, minimum)?;
    serde_json::from_slice::<Vec<crate::Login>>(&data).map_err(|_| "Ungültige Tresoreinträge")?;
    Ok((file, observed))
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
    // Part of the existing KCV2 profile. Changing this KDF requires a new
    // format version; readers must not silently reinterpret existing files.
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
    let (slots, aad_len) = layout(file)?;
    let start = slots + usize::from(role) * SLOT_LEN;
    let slot = &file[start..start + SLOT_LEN];
    let salt = slot[..16].try_into().expect("fixed slot salt");
    let nonce = slot[16..40].try_into().expect("fixed slot nonce");
    let key = derive_key(secret, &salt).map_err(|_| "Schlüsselableitung fehlgeschlagen")?;
    let seed = decrypt(&key, &nonce, &slot[40..], &slot_aad(role))
        .map_err(|_| "Falscher Zugang oder beschädigter Tresor")?;
    let nonce = file[aad_len..aad_len + 24]
        .try_into()
        .expect("fixed payload nonce");
    let data = decrypt(
        &payload_key(&seed)?,
        &nonce,
        &file[aad_len + 24..],
        &file[..aad_len],
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
    enable_recovery_with_revision(path, password, recovery, create, None).map(|_| ())
}

/// Atomically create a complete KCV2 vault with a fresh seed and both fresh slots.
/// No source or existing destination is replaced, including on validation failure.
pub fn create_with_recovery(
    path: &Path,
    password: &[u8],
    recovery: &[u8],
    data: &[u8],
) -> Result<(), &'static str> {
    if data.len() > MAX_FILE - RECOVERY_AAD_LEN - 24 - 16 {
        return Err("Tresor überschreitet das Vorschaulimit von 4 MiB");
    }
    serde_json::from_slice::<Vec<crate::Login>>(data).map_err(|_| "Ungültige Tresoreinträge")?;
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let mut header = RECOVERY_HEADER.to_vec();
    append_slot(&mut header, password, 0, &seed[..])?;
    append_slot(&mut header, recovery, 1, &seed[..])?;
    write_payload(path, &payload_key(&seed[..])?, &header, data, true)
}

pub fn enable_recovery_with_revision(
    path: &Path,
    password: &[u8],
    recovery: &[u8],
    create: bool,
    minimum: Option<Revision>,
) -> Result<Option<Revision>, &'static str> {
    if create && minimum.is_some() {
        return Err("Neue Datei darf keinen bestehenden Versionsbezug ersetzen");
    }
    let mut current_revision = None;
    let data = if create {
        Zeroizing::new(b"[]".to_vec())
    } else {
        let (data, observed) = open_with_revision(path, password, false)?;
        check_revision(observed, minimum)?;
        current_revision = observed;
        serde_json::from_slice::<Vec<crate::Login>>(&data)
            .map_err(|_| "Ungültige Tresoreinträge")?;
        data
    };
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let mut header = RECOVERY_HEADER.to_vec();
    if let Some(r) = current_revision {
        header = EPOCH_HEADER.to_vec();
        header.extend_from_slice(&r.vault_id);
        header.extend_from_slice(
            &r.epoch
                .checked_add(1)
                .ok_or("Tresorepoche ist ausgeschöpft")?
                .to_be_bytes(),
        );
    }
    append_slot(&mut header, password, 0, &seed[..])?;
    append_slot(&mut header, recovery, 1, &seed[..])?;
    write_payload(path, &payload_key(&seed[..])?, &header, &data, create)?;
    Ok(revision(&header))
}

/// Unlocked password change. The default retains the KCV2/KCV3 seed and recovery
/// slot. Rotation requires a caller-supplied recovery credential for the new slot.
/// Old files remain readable; KCV1 always derives a fresh key and stays KCV1.
pub fn change_password_with_revision(
    path: &Path,
    old_password: &[u8],
    new_password: &[u8],
    rotate_key: bool,
    new_recovery: Option<&[u8]>,
    minimum: Option<Revision>,
) -> Result<(Option<Revision>, bool), &'static str> {
    let file = read(path)?;
    if file.starts_with(HEADER) {
        let data = open_bytes(&file, old_password)?;
        check_revision(None, minimum)?;
        serde_json::from_slice::<Vec<crate::Login>>(&data)
            .map_err(|_| "Ungültige Tresoreinträge")?;
        if new_recovery.is_some() {
            return Err("Richte den Notfallzugang für diesen älteren Tresor separat ein.");
        }
        let mut salt = Salt::default();
        getrandom::fill(&mut salt).map_err(|_| "Zufallsquelle nicht verfügbar")?;
        let key =
            derive_key(new_password, &salt).map_err(|_| "Schlüsselableitung fehlgeschlagen")?;
        let mut header = HEADER.to_vec();
        header.extend_from_slice(&salt);
        write_payload(path, &key, &header, &data, false)?;
        return Ok((None, true));
    }
    let (seed, data) = open_recoverable(&file, old_password, 0)?;
    check_revision(revision(&file), minimum)?;
    serde_json::from_slice::<Vec<crate::Login>>(&data).map_err(|_| "Ungültige Tresoreinträge")?;
    let (slots, aad) = layout(&file)?;
    let mut header = advanced_header(&file)?[..slots].to_vec();
    if rotate_key {
        let recovery = new_recovery
            .ok_or("Speichere zuerst ein neues Notfallblatt für den Schlüsselwechsel.")?;
        let mut fresh_seed = Zeroizing::new([0; 32]);
        getrandom::fill(&mut fresh_seed[..]).map_err(|_| "Zufallsquelle nicht verfügbar")?;
        append_slot(&mut header, new_password, 0, &fresh_seed[..])?;
        append_slot(&mut header, recovery, 1, &fresh_seed[..])?;
        write_payload(path, &payload_key(&fresh_seed[..])?, &header, &data, false)?;
    } else {
        if new_recovery.is_some() {
            return Err("Ein neues Notfallblatt erfordert den Schlüsselwechsel.");
        }
        append_slot(&mut header, new_password, 0, &seed)?;
        header.extend_from_slice(&file[slots + SLOT_LEN..aad]);
        write_payload(path, &payload_key(&seed)?, &header, &data, false)?;
    }
    Ok((revision(&header), rotate_key))
}

/// Authenticate recovery access, rotate the payload seed and replace both slots.
/// The recovery secret stays valid. Previously copied files cannot be revoked.
pub fn reset_password(
    path: &Path,
    recovery: &[u8],
    password: &[u8],
) -> Result<Vec<crate::Login>, &'static str> {
    reset_password_with_revision(path, recovery, password, None).map(|(entries, _)| entries)
}

pub fn reset_password_with_revision(
    path: &Path,
    recovery: &[u8],
    password: &[u8],
    minimum: Option<Revision>,
) -> Result<(Vec<crate::Login>, Option<Revision>), &'static str> {
    let file = read(path)?;
    let data = open_recoverable(&file, recovery, 1)?.1;
    check_revision(revision(&file), minimum)?;
    let entries = serde_json::from_slice(&data).map_err(|_| "Ungültige Tresoreinträge")?;
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| "Zufallsquelle nicht verfügbar")?;
    let (slots, _) = layout(&file)?;
    let advanced = advanced_header(&file)?;
    let mut header = advanced[..slots].to_vec();
    append_slot(&mut header, password, 0, &seed[..])?;
    append_slot(&mut header, recovery, 1, &seed[..])?;
    write_payload(path, &payload_key(&seed[..])?, &header, &data, false)?;
    Ok((entries, revision(&header)))
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
    fn password_reset_rotates_seed_and_rejects_keys_from_an_old_copy() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("vault.kcv");
        let old = b"old synthetic vault password";
        let new = b"new synthetic vault password";
        enable_recovery(&path, old, RECOVERY, true).unwrap();
        save(&path, old, ENTRIES, false).unwrap();
        let stolen = read(&path).unwrap();
        // Model an attacker who unlocked an earlier copy, not just an old slot.
        let (old_seed, _) = open_recoverable(&stolen, old, 0).unwrap();
        let old_key = payload_key(&old_seed).unwrap();

        reset_password(&path, RECOVERY, new).unwrap();
        let current = read(&path).unwrap();
        let (new_seed, recovered) = open_recoverable(&current, RECOVERY, 1).unwrap();
        assert_eq!(&recovered[..], ENTRIES);
        assert_eq!(&open(&path, new).unwrap()[..], ENTRIES);
        assert!(open(&path, old).is_err());
        assert!(save(&path, old, b"[]", false).is_err());
        assert_eq!(read(&path).unwrap(), current);

        let reject_old_key = |file: &[u8]| {
            let nonce = file[RECOVERY_AAD_LEN..RECOVERY_AAD_LEN + 24]
                .try_into()
                .unwrap();
            assert!(decrypt(
                &old_key,
                &nonce,
                &file[RECOVERY_AAD_LEN + 24..],
                &file[..RECOVERY_AAD_LEN]
            )
            .is_err());
        };
        reject_old_key(&current);
        assert_ne!(&old_seed[..], &new_seed[..]);
        save(&path, new, b"[]", false).unwrap();
        reject_old_key(&read(&path).unwrap());
        // Re-keying cannot revoke data or credentials in the stolen snapshot.
        assert_eq!(&open_bytes(&stolen, old).unwrap()[..], ENTRIES);
        assert_eq!(
            &open_recoverable(&stolen, RECOVERY, 1).unwrap().1[..],
            ENTRIES
        );
    }

    #[test]
    fn ordinary_saves_keep_seed_and_slots_but_refresh_the_payload_nonce() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("vault.kcv");
        let password = b"synthetic vault password";
        enable_recovery(&path, password, RECOVERY, true).unwrap();
        let before = read(&path).unwrap();
        let (seed, _) = open_recoverable(&before, password, 0).unwrap();
        save(&path, password, ENTRIES, false).unwrap();
        let after = read(&path).unwrap();
        let (saved_seed, data) = open_recoverable(&after, RECOVERY, 1).unwrap();
        assert_eq!(&seed[..], &saved_seed[..]);
        assert_eq!(&before[..RECOVERY_AAD_LEN], &after[..RECOVERY_AAD_LEN]);
        assert_ne!(
            &before[RECOVERY_AAD_LEN..RECOVERY_AAD_LEN + 24],
            &after[RECOVERY_AAD_LEN..RECOVERY_AAD_LEN + 24]
        );
        assert_eq!(&data[..], ENTRIES);
    }

    #[test]
    fn renewed_recovery_and_repeated_resets_keep_snapshots_independent() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("vault.kcv");
        let password = b"synthetic vault password";
        let new_recovery = b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        enable_recovery(&path, password, RECOVERY, true).unwrap();
        save(&path, password, ENTRIES, false).unwrap();
        let original = read(&path).unwrap();
        let (seed, _) = open_recoverable(&original, RECOVERY, 1).unwrap();
        enable_recovery(&path, password, new_recovery, false).unwrap();
        let renewed = read(&path).unwrap();
        let (renewed_seed, _) = open_recoverable(&renewed, password, 0).unwrap();
        assert_ne!(&seed[..], &renewed_seed[..]);
        assert!(open_with_recovery(&path, RECOVERY).is_err());
        assert!(reset_password(&path, RECOVERY, b"rejected replacement password").is_err());
        assert_eq!(read(&path).unwrap(), renewed);

        let mut previous_seed = renewed_seed;
        for next_password in [
            b"first replacement password".as_slice(),
            b"second replacement password",
        ] {
            reset_password(&path, new_recovery, next_password).unwrap();
            let snapshot = read(&path).unwrap();
            let (next_seed, data) = open_recoverable(&snapshot, new_recovery, 1).unwrap();
            assert_ne!(&previous_seed[..], &next_seed[..]);
            assert_eq!(&data[..], ENTRIES);
            assert_eq!(&open_bytes(&snapshot, next_password).unwrap()[..], ENTRIES);
            previous_seed = next_seed;
        }
        assert_eq!(&open_bytes(&original, password).unwrap()[..], ENTRIES);
        assert_eq!(
            &open_recoverable(&original, RECOVERY, 1).unwrap().1[..],
            ENTRIES
        );
        assert_eq!(
            &open_recoverable(&renewed, new_recovery, 1).unwrap().1[..],
            ENTRIES
        );
    }

    #[test]
    fn reset_rejects_damaged_and_legacy_files_without_replacing_them() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("vault.kcv");
        let password = b"synthetic vault password";
        save(&path, password, ENTRIES, true).unwrap();
        let legacy = read(&path).unwrap();
        assert!(reset_password(&path, RECOVERY, password).is_err());
        assert_eq!(read(&path).unwrap(), legacy);
        enable_recovery(&path, password, RECOVERY, false).unwrap();
        let original = read(&path).unwrap();
        for offset in [
            RECOVERY_HEADER.len(),
            RECOVERY_HEADER.len() + SLOT_LEN,
            RECOVERY_AAD_LEN,
            original.len() - 1,
        ] {
            let mut damaged = original.clone();
            damaged[offset] ^= 1;
            std::fs::write(&path, &damaged).unwrap();
            assert!(reset_password(&path, RECOVERY, password).is_err());
            assert_eq!(read(&path).unwrap(), damaged);
        }
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
