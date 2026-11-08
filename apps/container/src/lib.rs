#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{stream, Payload},
    XChaCha20Poly1305,
};
use std::{
    collections::HashMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Take, Write},
    path::{Path, PathBuf},
};
use tempfile::{Builder, NamedTempFile};
use zeroize::Zeroizing;

pub mod native_signature;
pub mod scanner;
pub mod signature;
#[cfg(test)]
mod tests;

type Encryptor = stream::EncryptorBE32<XChaCha20Poly1305>;
type Decryptor = stream::DecryptorBE32<XChaCha20Poly1305>;

const MAGIC: &[u8; 8] = b"KCC\0\0\0\0\x01";
const EXE_FOOTER: &[u8; 16] = b"KCC-WIN64-EXE-v1";
const CHUNK: usize = 64 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_PATH: usize = 512;
const MAX_DEPTH: usize = 32;
const MAX_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const TAG: usize = 16;
const ENTRY: u8 = 1;
const DATA: u8 = 2;
const END: u8 = 3;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Format(&'static str),
    Crypto,
    Authentication,
    SignatureRejected,
    ScanRejected,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Format(message) => f.write_str(message),
            Self::Crypto => f.write_str("Key derivation or encryption failed."),
            Self::Authentication => f.write_str("Wrong passphrase or damaged container."),
            Self::SignatureRejected => {
                f.write_str("Signature could not be verified for the selected sender.")
            }
            Self::ScanRejected => f.write_str("The scanner rejected the files or did not finish."),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub entries: usize,
    pub bytes: u64,
}

fn invalid(message: &'static str) -> Error {
    Error::Format(message)
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N]> {
    let mut value = [0; N];
    reader.read_exact(&mut value)?;
    Ok(value)
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut value = Zeroizing::new([0; N]);
    getrandom::fill(&mut value[..]).map_err(|_| Error::Crypto)?;
    Ok(value)
}

pub fn generate_passphrase() -> Result<Zeroizing<String>> {
    use std::fmt::Write as _;
    let bytes = random::<24>()?;
    let mut output = Zeroizing::new(String::with_capacity(48));
    for byte in bytes.iter() {
        write!(output, "{byte:02x}").map_err(|_| Error::Crypto)?;
    }
    Ok(output)
}

fn wrap_aad(salt: &[u8; 16], stream_nonce: &[u8; 19]) -> [u8; 43] {
    let mut aad = [0; 43];
    aad[..8].copy_from_slice(MAGIC);
    aad[8..24].copy_from_slice(salt);
    aad[24..].copy_from_slice(stream_nonce);
    aad
}

fn begin_write(writer: &mut impl Write, passphrase: &[u8]) -> Result<Encryptor> {
    let salt = random::<16>()?;
    let nonce = random::<19>()?;
    let data_key = random::<32>()?;
    let wrap_key = kryptocore::derive_key(passphrase, &salt).map_err(|_| Error::Crypto)?;
    let aad = wrap_aad(&salt, &nonce);
    let (wrap_nonce, wrapped) =
        kryptocore::encrypt(&wrap_key, &data_key[..], &aad).map_err(|_| Error::Crypto)?;
    writer.write_all(&aad)?;
    writer.write_all(&wrap_nonce)?;
    writer.write_all(&wrapped)?;
    Ok(Encryptor::new((&*data_key).into(), (&*nonce).into()))
}

fn begin_read(reader: &mut impl Read, passphrase: &[u8]) -> Result<Decryptor> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(invalid("Invalid passphrase length."));
    }
    if &read_array::<8>(reader)? != MAGIC {
        return Err(invalid("Unknown container format or version."));
    }
    let salt = read_array::<16>(reader)?;
    let nonce = read_array::<19>(reader)?;
    let wrap_nonce = read_array::<24>(reader)?;
    let wrapped = read_array::<48>(reader)?;
    let wrap_key = kryptocore::derive_key(passphrase, &salt).map_err(|_| Error::Crypto)?;
    let data_key = kryptocore::decrypt(&wrap_key, &wrap_nonce, &wrapped, &wrap_aad(&salt, &nonce))
        .map_err(|_| Error::Authentication)?;
    let key: &[u8; 32] = data_key.as_slice().try_into().map_err(|_| Error::Crypto)?;
    Ok(Decryptor::new(key.into(), (&nonce).into()))
}

fn prefix(kind: u8, plaintext_len: usize) -> [u8; 5] {
    let mut header = [kind, 0, 0, 0, 0];
    header[1..].copy_from_slice(&(plaintext_len as u32).to_be_bytes());
    header
}

fn write_frame(
    writer: &mut impl Write,
    cipher: &mut Encryptor,
    kind: u8,
    data: &[u8],
) -> Result<()> {
    let header = prefix(kind, data.len());
    let sealed = cipher
        .encrypt_next(Payload {
            msg: data,
            aad: &header,
        })
        .map_err(|_| Error::Crypto)?;
    writer.write_all(&header)?;
    writer.write_all(&sealed)?;
    Ok(())
}

fn write_end(writer: &mut impl Write, cipher: Encryptor) -> Result<()> {
    let header = prefix(END, 0);
    let sealed = cipher
        .encrypt_last(Payload {
            msg: &[],
            aad: &header,
        })
        .map_err(|_| Error::Crypto)?;
    writer.write_all(&header)?;
    writer.write_all(&sealed)?;
    Ok(())
}

fn open_frame(
    reader: &mut impl Read,
    cipher: &mut Decryptor,
    header: &[u8; 5],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut sealed = vec![0; len + TAG];
    reader.read_exact(&mut sealed)?;
    cipher
        .decrypt_next(Payload {
            msg: &sealed,
            aad: header,
        })
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

fn valid_component(name: &str) -> bool {
    // Use the intersection of ordinary Unix and Win32 names; preserve Unicode.
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let numbered = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"));
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 240
        && !name.ends_with(['.', ' '])
        && !name
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
        && !matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        && !numbered.is_some_and(|n| {
            matches!(
                n,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

#[derive(Default)]
struct Entries {
    // The value contains the original spelling for exact parent checks.
    names: HashMap<String, (String, bool)>,
    summary: Summary,
}

impl Entries {
    fn add(&mut self, path: &str, directory: bool, size: u64) -> Result<()> {
        if path.len() > MAX_PATH
            || path.split('/').count() > MAX_DEPTH
            || !path.split('/').all(valid_component)
        {
            return Err(invalid("Unsafe or unsupported entry name."));
        }
        if let Some((parent, _)) = path.rsplit_once('/') {
            if !self
                .names
                .get(&parent.to_lowercase())
                .is_some_and(|(original, dir)| *dir && original == parent)
            {
                return Err(invalid("An entry's parent directory must appear first."));
            }
        }
        let name = path.to_lowercase();
        if self.names.contains_key(&name) {
            return Err(invalid("Duplicate or conflicting entry names."));
        }
        if self.summary.entries >= MAX_ENTRIES || size > MAX_BYTES - self.summary.bytes {
            return Err(invalid("Container exceeds its entry or size limit."));
        }
        self.names.insert(name, (path.to_owned(), directory));
        self.summary.entries += 1;
        self.summary.bytes += size;
        Ok(())
    }
}

fn is_link(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(not(windows))]
    metadata.is_symlink()
}

fn source_path(path: &Path) -> Result<PathBuf> {
    // Check each component before canonicalization so junctions are not hidden.
    let absolute = std::path::absolute(path)?;
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        prefix.push(component);
        if matches!(component, std::path::Component::Normal(_))
            && is_link(&fs::symlink_metadata(&prefix)?)
        {
            return Err(invalid("Links and reparse points cannot be packed."));
        }
    }
    Ok(fs::canonicalize(absolute)?)
}

fn pack_entry(
    source: &Path,
    name: &str,
    writer: &mut impl Write,
    cipher: &mut Encryptor,
    entries: &mut Entries,
    buffer: &mut [u8],
) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if is_link(&metadata) || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(invalid("Only regular files and directories can be packed."));
    }
    let directory = metadata.is_dir();
    let size = if directory { 0 } else { metadata.len() };
    entries.add(name, directory, size)?;
    let mut description = Zeroizing::new(Vec::with_capacity(9 + name.len()));
    description.push(u8::from(directory));
    description.extend_from_slice(&size.to_be_bytes());
    description.extend_from_slice(name.as_bytes());
    write_frame(writer, cipher, ENTRY, &description)?;
    if directory {
        for child in fs::read_dir(source)? {
            let child = child?;
            let filename = child.file_name();
            let filename = filename
                .to_str()
                .ok_or(invalid("Entry names must be UTF-8."))?;
            if !valid_component(filename) {
                return Err(invalid("Unsafe or unsupported entry name."));
            }
            pack_entry(
                &child.path(),
                &format!("{name}/{filename}"),
                writer,
                cipher,
                entries,
                buffer,
            )?;
        }
    } else {
        let mut file = File::open(source)?;
        let mut remaining = size;
        while remaining != 0 {
            let count = remaining.min(CHUNK as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            write_frame(writer, cipher, DATA, &buffer[..count])?;
            remaining -= count as u64;
        }
        if file.read(&mut buffer[..1])? != 0 {
            return Err(invalid("A source file changed during packing."));
        }
    }
    Ok(())
}

fn output_location(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let name = path.file_name().ok_or(invalid("Provide an output name."))?;
    if !name.to_str().is_some_and(valid_component) {
        return Err(invalid("Unsafe or unsupported output name."));
    }
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let full = parent.join(name);
    match fs::symlink_metadata(&full) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((parent, full)),
        Err(e) => Err(e.into()),
        Ok(_) => Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
    }
}

pub fn pack(output: &Path, sources: &[PathBuf], passphrase: &[u8]) -> Result<Summary> {
    pack_impl(output, sources, passphrase, None)
}

/// Write a KCC payload after the Windows opener, followed by its length and version marker.
pub fn pack_executable(
    opener: &Path,
    output: &Path,
    sources: &[PathBuf],
    passphrase: &[u8],
) -> Result<Summary> {
    pack_impl(output, sources, passphrase, Some(open_container(opener)?))
}

fn pack_impl(
    output: &Path,
    sources: &[PathBuf],
    passphrase: &[u8],
    opener: Option<File>,
) -> Result<Summary> {
    if !(15..=1024).contains(&passphrase.len())
        || !std::str::from_utf8(passphrase).is_ok_and(|text| text.chars().count() >= 15)
    {
        return Err(invalid(
            "Use at least 15 characters (up to 1024 bytes), preferably a generated passphrase.",
        ));
    }
    if sources.is_empty() {
        return Err(invalid("Select at least one file or folder."));
    }
    let (parent, output) = output_location(output)?;
    let sources = sources
        .iter()
        .map(|source| source_path(source))
        .collect::<Result<Vec<_>>>()?;
    for source in &sources {
        // Compare ancestor identities as canonical paths. On Windows paths can
        // still differ in case, so also compare their case-insensitive spelling.
        for ancestor in parent.ancestors() {
            if ancestor == source
                || (cfg!(windows)
                    && ancestor.to_string_lossy().to_lowercase()
                        == source.to_string_lossy().to_lowercase())
            {
                return Err(invalid("Choose an output outside all source folders."));
            }
        }
    }
    let mut staged = NamedTempFile::new_in(parent)?;
    let mut writer = BufWriter::new(staged.as_file_mut());
    let opener_len = opener
        .map(|mut file| io::copy(&mut file, &mut writer))
        .transpose()?;
    let mut cipher = begin_write(&mut writer, passphrase)?;
    let mut entries = Entries::default();
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    for source in &sources {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(invalid("Select a named file or folder with a UTF-8 name."))?;
        if !valid_component(name) {
            return Err(invalid("Unsafe or unsupported entry name."));
        }
        pack_entry(
            source,
            name,
            &mut writer,
            &mut cipher,
            &mut entries,
            &mut buffer,
        )?;
    }
    write_end(&mut writer, cipher)?;
    if let Some(opener_len) = opener_len {
        let length = writer.stream_position()? - opener_len;
        writer.write_all(&length.to_le_bytes())?;
        writer.write_all(EXE_FOOTER)?;
    }
    writer.flush()?;
    drop(writer);
    staged.as_file().sync_all()?;
    staged.persist_noclobber(output).map_err(|e| e.error)?;
    Ok(entries.summary)
}

fn read_payload(
    reader: &mut impl Read,
    passphrase: &[u8],
    destination: Option<&Path>,
) -> Result<Summary> {
    read_payload_limited(reader, passphrase, destination, MAX_BYTES)
}

fn read_payload_limited(
    reader: &mut impl Read,
    passphrase: &[u8],
    destination: Option<&Path>,
    limit: u64,
) -> Result<Summary> {
    let mut cipher = begin_read(reader, passphrase)?;
    let mut entries = Entries::default();
    loop {
        let header = read_array::<5>(reader)?;
        let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
        match header[0] {
            END if length == 0 => {
                let sealed = read_array::<TAG>(reader)?;
                cipher
                    .decrypt_last(Payload {
                        msg: &sealed,
                        aad: &header,
                    })
                    .map_err(|_| Error::Authentication)?;
                if reader.read(&mut [0])? != 0 || entries.summary.entries == 0 {
                    return Err(invalid(
                        "Unexpected bytes after the end or an empty container.",
                    ));
                }
                return Ok(entries.summary);
            }
            ENTRY if (10..=9 + MAX_PATH).contains(&length) => {}
            _ => return Err(invalid("Invalid entry frame.")),
        }
        let record = open_frame(reader, &mut cipher, &header, length)?;
        let size = u64::from_be_bytes(record[1..9].try_into().unwrap());
        let directory = match record[0] {
            0 => false,
            1 if size == 0 => true,
            _ => return Err(invalid("Invalid entry metadata.")),
        };
        let name =
            std::str::from_utf8(&record[9..]).map_err(|_| invalid("Entry names must be UTF-8."))?;
        entries.add(name, directory, size)?;
        if entries.summary.bytes > limit {
            return Err(invalid(
                "Extraction exceeds the selected plaintext/scan byte limit.",
            ));
        }
        let path = destination.map(|root| root.join(name));
        if directory {
            if let Some(path) = path {
                fs::create_dir(path)?;
            }
            continue;
        }
        let mut output = match path {
            Some(path) => Some(OpenOptions::new().write(true).create_new(true).open(path)?),
            None => None,
        };
        let mut remaining = size;
        while remaining != 0 {
            let count = remaining.min(CHUNK as u64) as usize;
            let header = read_array::<5>(reader)?;
            if header != prefix(DATA, count) {
                return Err(invalid("Invalid file data frame."));
            }
            let block = open_frame(reader, &mut cipher, &header, count)?;
            if let Some(ref mut output) = output {
                output.write_all(&block)?;
            }
            remaining -= count as u64;
        }
        if let Some(output) = output {
            output.sync_all()?;
        }
    }
}

pub fn check(input: &Path, passphrase: &[u8]) -> Result<Summary> {
    read_payload(
        &mut BufReader::new(open_container(input)?),
        passphrase,
        None,
    )
}

pub fn check_executable(input: &Path, passphrase: &[u8]) -> Result<Summary> {
    read_payload(
        &mut BufReader::new(open_executable_payload(input)?),
        passphrase,
        None,
    )
}

fn open_executable_payload(input: &Path) -> Result<Take<File>> {
    let mut file = open_container(input)?;
    let end = file.seek(SeekFrom::End(-24))?;
    let length = u64::from_le_bytes(read_array(&mut file)?);
    if &read_array::<16>(&mut file)? != EXE_FOOTER || length == 0 || length >= end {
        return Err(invalid("Invalid executable container footer."));
    }
    file.seek(SeekFrom::Start(end - length))?;
    Ok(file.take(length))
}

fn open_container(input: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(input)?;
    if !metadata.is_file() || is_link(&metadata) {
        return Err(invalid("Select a regular container file."));
    }
    let file = File::open(input)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("Select a regular container file."));
    }
    Ok(file)
}

pub fn unpack(input: &Path, output: &Path, passphrase: &[u8]) -> Result<Summary> {
    unpack_with_inspection(input, output, passphrase, |_| Ok(()))
}

/// The callback sees the fully authenticated plaintext staging folder.
/// Use only a trusted inspector which does not modify the directory or files.
pub fn unpack_with_inspection(
    input: &Path,
    output: &Path,
    passphrase: &[u8],
    inspect: impl FnOnce(&Path) -> Result<()>,
) -> Result<Summary> {
    unpack_impl(output, inspect, |stage| {
        read_payload(
            &mut BufReader::new(open_container(input)?),
            passphrase,
            Some(stage),
        )
    })
}

pub fn unpack_executable_with_inspection(
    input: &Path,
    output: &Path,
    passphrase: &[u8],
    inspect: impl FnOnce(&Path) -> Result<()>,
) -> Result<Summary> {
    unpack_impl(output, inspect, |stage| {
        read_payload(
            &mut BufReader::new(open_executable_payload(input)?),
            passphrase,
            Some(stage),
        )
    })
}

pub fn unpack_signed_with_inspection(
    input: &Path,
    output: &Path,
    passphrase: &[u8],
    signature: &signature::Verification<'_>,
    inspect: impl FnOnce(&Path) -> Result<()>,
) -> Result<Summary> {
    unpack_impl(output, inspect, |stage| {
        let mut reader = signature::HashReader::new(BufReader::new(open_container(input)?));
        let result = read_payload(&mut reader, passphrase, Some(stage))?;
        signature.verify_digest(&reader.finish())?;
        Ok(result)
    })
}

/// Verify the shared signature protocol against the exact stream being
/// decrypted, before the inspection callback or any destination publication.
pub fn unpack_native_with_inspection(
    input: &Path,
    output: &Path,
    passphrase: &[u8],
    verification: &native_signature::Verification,
    inspect: impl FnOnce(&Path) -> Result<()>,
) -> Result<Summary> {
    unpack_impl(output, inspect, |stage| {
        native_signature::read_authenticated(input, passphrase, stage, verification)
    })
}

/// Requested checks run before any extraction is published.
#[derive(Default)]
pub struct OpenPolicy<'a> {
    pub embedded: bool,
    pub native: Option<&'a native_signature::Verification>,
    pub openssh: Option<&'a signature::Verification<'a>>,
    pub scanner: Option<&'a Path>,
}

pub fn unpack_protected(
    input: &Path,
    output: &Path,
    password: &[u8],
    policy: OpenPolicy<'_>,
) -> Result<Summary> {
    if policy.native.is_some() && policy.openssh.is_some() {
        return Err(invalid("Select one sender-signature protocol."));
    }
    if policy.embedded && policy.openssh.is_some() {
        return Err(invalid(
            "Check an executable OpenSSH signature in a trusted separate app before starting it.",
        ));
    }
    let limit = if policy.scanner.is_some() {
        scanner::MAX_TOTAL_BYTES
    } else {
        MAX_BYTES
    };
    unpack_impl(
        output,
        |stage| scanner::inspect(stage, policy.scanner),
        |stage| {
            if let Some(verification) = policy.native {
                native_signature::read_authenticated_limited(
                    input,
                    password,
                    stage,
                    verification,
                    limit,
                )
            } else if let Some(verification) = policy.openssh {
                let mut reader = signature::HashReader::new(BufReader::new(open_container(input)?));
                let result = read_payload_limited(&mut reader, password, Some(stage), limit)?;
                verification.verify_digest(&reader.finish())?;
                Ok(result)
            } else if policy.embedded {
                read_payload_limited(
                    &mut BufReader::new(open_executable_payload(input)?),
                    password,
                    Some(stage),
                    limit,
                )
            } else {
                read_payload_limited(
                    &mut BufReader::new(open_container(input)?),
                    password,
                    Some(stage),
                    limit,
                )
            }
        },
    )
}

fn unpack_impl(
    output: &Path,
    inspect: impl FnOnce(&Path) -> Result<()>,
    read: impl FnOnce(&Path) -> Result<Summary>,
) -> Result<Summary> {
    let (parent, output) = output_location(output)?;
    let mut builder = Builder::new();
    builder.prefix(".kcc-");
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o700));
    let stage = builder.tempdir_in(parent)?;
    let result = read(stage.path())?;
    inspect(stage.path())?;
    // Reserve the chosen directory without ever overwriting an existing one.
    // Move only fully authenticated roots out of the private staging area.
    let children = fs::read_dir(stage.path())?.collect::<io::Result<Vec<_>>>()?;
    let mut destination = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        destination.mode(0o700);
    }
    destination.recursive(false).create(&output)?;
    let publish = (|| -> io::Result<()> {
        for child in children {
            fs::rename(child.path(), output.join(child.file_name()))?;
        }
        Ok(())
    })();
    if let Err(error) = publish {
        // Both the destination and its parent must be under the user's control.
        if let Err(cleanup) = fs::remove_dir_all(&output) {
            return Err(io::Error::new(cleanup.kind(), format!("Extraction failed ({error}); could not clean up the new output directory ({cleanup}).")).into());
        }
        return Err(error.into());
    }
    Ok(result)
}
