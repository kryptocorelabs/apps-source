use crate::{Error, Identity, Result};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const LEGACY_HEADER: &[u8; 8] = b"KCMB\0\0\0\x01";
const HEADER: &[u8; 8] = b"KCMB\0\0\0\x02";
const LIMIT: usize = 64 * 1024;

pub struct ContactBook<'a> {
    path: PathBuf,
    key: kryptocore::Key,
    identity: &'a Identity,
    legacy_salt: &'static kryptocore::Salt,
    _lock: File,
}

impl<'a> ContactBook<'a> {
    pub fn open(identity_path: &Path, identity: &'a Identity) -> Result<Self> {
        Self::open_store(identity_path, identity, ".contacts", b"KCMB v1 contacts")
    }

    pub fn blocked(identity_path: &Path, identity: &'a Identity) -> Result<Self> {
        Self::open_store(identity_path, identity, ".blocked", b"KCMB v1 blocked!")
    }

    pub fn verification(identity_path: &Path, identity: &'a Identity) -> Result<Self> {
        Self::open_store(
            identity_path,
            identity,
            ".verification",
            b"KCMB v1 verify!!",
        )
    }

    pub fn require_two_codes(identity_path: &Path, identity: &'a Identity) -> Result<bool> {
        let mut path = identity_path.as_os_str().to_owned();
        path.push(".policy");
        match std::fs::symlink_metadata(Path::new(&path)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let store = Self::open_store(identity_path, identity, ".policy", b"KCMB v1 settings")?;
        match store.read()?.as_slice() {
            b"true" => Ok(true),
            b"false" => Ok(false),
            _ => Err(Error::Identity),
        }
    }

    pub fn set_require_two_codes(
        identity_path: &Path,
        identity: &'a Identity,
        required: bool,
    ) -> Result<()> {
        let store = Self::open_store(identity_path, identity, ".policy", b"KCMB v1 settings")?;
        store.write(if required { b"true" } else { b"false" })
    }

    fn open_store(
        identity_path: &Path,
        identity: &'a Identity,
        suffix: &str,
        legacy_salt: &'static kryptocore::Salt,
    ) -> Result<Self> {
        let mut path = identity_path.as_os_str().to_owned();
        path.push(suffix);
        let mut lock_path = path.clone();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock()?;
        let context =
            kryptocore::Context::new("org.kryptocorelabs.msg", 2, "sidecar-key", legacy_salt)
                .map_err(|_| Error::Identity)?;
        let key = kryptocore::Key::from_bytes(&identity.0).derive_subkey(&context);
        Ok(Self {
            path: path.into(),
            key,
            identity,
            legacy_salt,
            _lock: lock,
        })
    }

    pub fn read(&self) -> Result<Zeroizing<Vec<u8>>> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Zeroizing::new(b"[]".to_vec()))
            }
            Err(error) => return Err(error.into()),
        };
        let mut data = Vec::new();
        file.take((LIMIT + 49) as u64).read_to_end(&mut data)?;
        if !(48..=LIMIT + 48).contains(&data.len()) {
            return Err(Error::Identity);
        }
        let nonce = data[8..32].try_into().map_err(|_| Error::Identity)?;
        if data.starts_with(HEADER) {
            return kryptocore::decrypt(&self.key, nonce, &data[32..], HEADER)
                .map_err(|_| Error::Identity);
        }
        if !data.starts_with(LEGACY_HEADER) {
            return Err(Error::Identity);
        }
        let legacy_key = kryptocore::derive_key(&self.identity.0[..], self.legacy_salt)
            .map_err(|_| Error::Identity)?;
        let plaintext = kryptocore::decrypt(&legacy_key, nonce, &data[32..], LEGACY_HEADER)
            .map_err(|_| Error::Identity)?;
        // Keep a readable legacy store usable if its directory cannot be updated.
        let _ = self.write(&plaintext);
        Ok(plaintext)
    }

    pub fn write(&self, contents: &[u8]) -> Result<()> {
        if contents.len() > LIMIT {
            return Err(Error::Identity);
        }
        let (nonce, ciphertext) =
            kryptocore::encrypt(&self.key, contents, HEADER).map_err(|_| Error::Identity)?;
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(parent)?;
        staged.write_all(HEADER)?;
        staged.write_all(&nonce)?;
        staged.write_all(&ciphertext)?;
        staged.as_file().sync_all()?;
        staged.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
}
