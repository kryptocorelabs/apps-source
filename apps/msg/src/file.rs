use super::{
    validate_message, Connection, Error, Identity, Incoming, PublicKey, Result, SendProgress,
    RECEIPT,
};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;
pub(super) const PREFIX: &[u8] = b"\xffKCM-FILE1";
const CHUNK_SIZE: usize = 32 * 1024;
const TAG_SIZE: usize = 16;
const FILE_TIMEOUT: Duration = Duration::from_secs(240);
const READY: &[u8] = b"file-ready";

/// Save a complete attachment without overwriting an existing file.
pub fn save_received_file(
    folder: &Path,
    name: &str,
    bytes: &[u8],
) -> io::Result<std::path::PathBuf> {
    if !valid_name(name) || bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // The prefix also keeps Windows device names such as NUL out of the destination.
    let path = folder.join(format!("MSG-{name}"));
    let mut stage = tempfile::NamedTempFile::new_in(folder)?;
    stage.write_all(bytes)?;
    stage.as_file().sync_all()?;
    stage
        .persist_noclobber(&path)
        .map_err(|error| error.error)?;
    Ok(path)
}

pub(super) fn valid_name(name: &str) -> bool {
    name.len() <= 240
        && validate_message(name).is_ok()
        && name == name.trim()
        && !name.ends_with('.')
        && !name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
}

pub fn send_file(
    stream: &mut TcpStream,
    local: &Identity,
    peer: &PublicKey,
    path: &Path,
    mut progress: impl FnMut(SendProgress),
) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::File)?;
    if !valid_name(name) || !fs::symlink_metadata(path)?.is_file() {
        return Err(Error::File);
    }
    let mut source = File::open(path)?;
    let metadata = source.metadata()?;
    let size = metadata.len();
    if !metadata.is_file() || size > MAX_FILE_SIZE {
        return Err(Error::File);
    }
    let mut connection = Connection::new(stream);
    let mut session = connection.handshake(local, peer, true)?;
    progress(SendProgress::Encrypted);
    let mut header = PREFIX.to_vec();
    header.extend_from_slice(&size.to_be_bytes());
    header.extend_from_slice(name.as_bytes());
    let mut sealed = vec![0; CHUNK_SIZE + TAG_SIZE];
    write(&mut connection, &mut session, &header, &mut sealed)?;
    expect(&mut connection, &mut session, READY)?;

    connection.deadline = Instant::now() + FILE_TIMEOUT;
    let mut plain = Zeroizing::new(vec![0; CHUNK_SIZE]);
    let mut remaining = size;
    while remaining != 0 {
        let count = remaining.min(CHUNK_SIZE as u64) as usize;
        source.read_exact(&mut plain[..count])?;
        write(&mut connection, &mut session, &plain[..count], &mut sealed)?;
        remaining -= count as u64;
    }
    progress(SendProgress::AwaitingReceipt);
    expect(&mut connection, &mut session, RECEIPT)
}

pub(super) fn receive(
    connection: &mut Connection<'_>,
    session: &mut snow::TransportState,
    header: &[u8],
    accept: impl FnOnce(Incoming<'_>) -> io::Result<()>,
) -> Result<()> {
    let size = header.get(..8).ok_or(Error::File)?;
    let size = u64::from_be_bytes(size.try_into().map_err(|_| Error::File)?);
    let name = std::str::from_utf8(&header[8..]).map_err(|_| Error::File)?;
    if size > MAX_FILE_SIZE || !valid_name(name) {
        return Err(Error::File);
    }
    connection.deadline = Instant::now() + FILE_TIMEOUT;
    let mut sealed = vec![0; CHUNK_SIZE + TAG_SIZE];
    write(connection, session, READY, &mut sealed)?;
    // Keep incomplete transfers off disk. The authenticated length bounds the allocation.
    let mut bytes = Zeroizing::new(vec![0; size as usize]);
    for chunk in bytes.chunks_mut(CHUNK_SIZE) {
        let length = chunk.len() + TAG_SIZE;
        connection.read_frame(&mut sealed[..length], length)?;
        if session.read_message(&sealed[..length], chunk)? != chunk.len() {
            return Err(Error::File);
        }
    }
    accept(Incoming::File {
        name,
        bytes: &bytes,
    })?;
    write(connection, session, RECEIPT, &mut sealed)
}

fn write(
    connection: &mut Connection<'_>,
    session: &mut snow::TransportState,
    plain: &[u8],
    sealed: &mut [u8],
) -> Result<()> {
    let size = session.write_message(plain, sealed)?;
    connection.write_frame(&sealed[..size])
}

fn expect(
    connection: &mut Connection<'_>,
    session: &mut snow::TransportState,
    token: &[u8],
) -> Result<()> {
    let mut sealed = [0; TAG_SIZE + READY.len()];
    let mut plain = [0; READY.len()];
    let size = token.len() + TAG_SIZE;
    connection.read_frame(&mut sealed[..size], size)?;
    let count = session.read_message(&sealed[..size], &mut plain)?;
    if &plain[..count] != token {
        return Err(Error::Protocol);
    }
    Ok(())
}
