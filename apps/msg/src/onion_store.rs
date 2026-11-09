use crate::{Error, Identity, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const ONION_KEY_SIZE: usize = 64;
const HEADER: &[u8; 8] = b"KCMO\0\0\0\x01";
const RECORD_SIZE: usize = 8 + 24 + ONION_KEY_SIZE + 16;

/// The Tor v3 service key paired with one unlocked MSG identity.
pub struct OnionKeyStore {
    path: PathBuf,
    key: kryptocore::Key,
    _lock: File,
}

impl OnionKeyStore {
    pub fn open(identity_path: &Path, identity: &Identity) -> Result<Self> {
        let mut path = identity_path.as_os_str().to_owned();
        path.push(".onion-key");
        let mut lock_path = path.clone();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock()?;
        let context = kryptocore::Context::new(
            "org.kryptocorelabs.msg",
            1,
            "onion-store-key",
            &identity.public(),
        )
        .map_err(|_| Error::Identity)?;
        let key = kryptocore::Key::from_bytes(&identity.0).derive_subkey(&context);
        Ok(Self {
            path: path.into(),
            key,
            _lock: lock,
        })
    }

    pub fn read(&self) -> Result<Option<Zeroizing<[u8; ONION_KEY_SIZE]>>> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Error::Identity),
        }
        let mut file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != RECORD_SIZE as u64 {
            return Err(Error::Identity);
        }
        let mut record = [0; RECORD_SIZE];
        file.read_exact(&mut record)?;
        if &record[..8] != HEADER || file.read(&mut [0])? != 0 {
            return Err(Error::Identity);
        }
        let nonce = record[8..32].try_into().map_err(|_| Error::Identity)?;
        let plaintext = kryptocore::decrypt(&self.key, nonce, &record[32..], HEADER)
            .map_err(|_| Error::Identity)?;
        if plaintext.len() != ONION_KEY_SIZE {
            return Err(Error::Identity);
        }
        let mut key = Zeroizing::new([0; ONION_KEY_SIZE]);
        key.copy_from_slice(&plaintext);
        Ok(Some(key))
    }

    /// Create a store or atomically rotate a matching authenticated key.
    pub fn write(
        &self,
        key: &[u8; ONION_KEY_SIZE],
        previous: Option<&[u8; ONION_KEY_SIZE]>,
    ) -> Result<()> {
        if let Some(previous) = previous {
            let current = self.read()?.ok_or(Error::Identity)?;
            if !bool::from(current.as_slice().ct_eq(previous)) {
                return Err(Error::Identity);
            }
        }
        let (nonce, ciphertext) =
            kryptocore::encrypt(&self.key, key, HEADER).map_err(|_| Error::Identity)?;
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
        if previous.is_some() {
            staged.persist(&self.path).map_err(|error| error.error)?;
        } else {
            staged
                .persist_noclobber(&self.path)
                .map_err(|error| error.error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_key_is_bound_to_identity_and_portable_with_it() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("identity.kcmi");
        let original = [0x25; ONION_KEY_SIZE];
        let identity = Identity::generate().unwrap();
        {
            let store = OnionKeyStore::open(&path, &identity).unwrap();
            assert!(store.read().unwrap().is_none());
            store.write(&original, None).unwrap();
            assert_eq!(*store.read().unwrap().unwrap(), original);
            let sealed = fs::read(&store.path).unwrap();
            assert!(!sealed.windows(ONION_KEY_SIZE).any(|part| part == original));
            fs::copy(&store.path, root.path().join("moved.kcmi.onion-key")).unwrap();
        }
        let wrong_identity = Identity::generate().unwrap();
        let wrong_store = OnionKeyStore::open(&path, &wrong_identity).unwrap();
        assert!(matches!(wrong_store.read(), Err(Error::Identity)));
        let moved = OnionKeyStore::open(&root.path().join("moved.kcmi"), &identity).unwrap();
        assert_eq!(*moved.read().unwrap().unwrap(), original);
    }

    #[test]
    fn onion_rotation_rejects_a_stale_key_and_preserves_damaged_records() {
        let root = tempfile::tempdir().unwrap();
        let identity = Identity::generate().unwrap();
        let store = OnionKeyStore::open(&root.path().join("identity.kcmi"), &identity).unwrap();
        let original = [0x25; ONION_KEY_SIZE];
        let rotated = [0x52; ONION_KEY_SIZE];
        assert!(matches!(
            store.write(&rotated, Some(&original)),
            Err(Error::Identity)
        ));
        store.write(&original, None).unwrap();
        assert!(
            matches!(store.write(&rotated, None), Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        store.write(&rotated, Some(&original)).unwrap();
        assert!(matches!(
            store.write(&original, Some(&original)),
            Err(Error::Identity)
        ));
        assert_eq!(*store.read().unwrap().unwrap(), rotated);

        let good = fs::read(&store.path).unwrap();
        for offset in [0, 8, 32, RECORD_SIZE - 1] {
            let mut damaged = good.clone();
            damaged[offset] ^= 1;
            fs::write(&store.path, &damaged).unwrap();
            assert!(matches!(store.read(), Err(Error::Identity)));
            assert!(matches!(
                store.write(&original, Some(&rotated)),
                Err(Error::Identity)
            ));
            assert_eq!(fs::read(&store.path).unwrap(), damaged);
        }
        for damaged in [&good[..RECORD_SIZE - 1], &[0; RECORD_SIZE + 1]] {
            fs::write(&store.path, damaged).unwrap();
            assert!(matches!(store.read(), Err(Error::Identity)));
        }
    }
}
