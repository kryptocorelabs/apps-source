#![forbid(unsafe_code)]

pub mod chat;
pub mod contact;
mod contact_book;
pub mod contact_request;
pub use contact_book::ContactBook;
mod dh;
mod file;
pub use file::{save_received_file, save_received_file_as, send_file, MAX_FILE_SIZE};
mod onion_store;
pub use onion_store::{OnionKeyStore, ONION_KEY_SIZE};
pub mod pairing;
pub mod presence;
#[cfg(test)]
mod tests;
pub mod tor;
pub mod transport;

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PROTOCOL: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"KryptoCore MSG direct text v1";
const MAGIC: &[u8; 8] = b"KCMI\0\0\0\x01";
pub const MAX_MESSAGE: usize = 4096;
const SEALED_MAX: usize = MAX_MESSAGE + 16;
const RECEIPT: &[u8] = b"accepted";
const SESSION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Identity,
    Protocol,
    Message,
    File,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<snow::Error> for Error {
    fn from(_: snow::Error) -> Self {
        Self::Protocol
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Identity => f.write_str("Invalid identity file, peer key, or passphrase."),
            Self::Protocol => f.write_str(
                "The authenticated connection could not be completed. Check the peer key.",
            ),
            Self::Message => f.write_str(
                "Use a single nonempty line of text, up to 4096 bytes, without terminal controls.",
            ),
            Self::File => f.write_str("Invalid file name, size, or transfer data."),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;
pub type PublicKey = [u8; 32];

pub struct Identity(Zeroizing<[u8; 32]>);

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(&mut secret[..]).map_err(|_| Error::Identity)?;
        Ok(Self(secret))
    }

    pub fn public(&self) -> PublicKey {
        dh::public_key(&self.0)
    }

    pub fn save(&self, path: &Path, password: &[u8]) -> Result<()> {
        if password.len() > 1024
            || !std::str::from_utf8(password).is_ok_and(|p| p.chars().count() >= 15)
        {
            return Err(Error::Identity);
        }
        let mut salt = [0; 16];
        getrandom::fill(&mut salt).map_err(|_| Error::Identity)?;
        let key = kryptocore::derive_key(password, &salt).map_err(|_| Error::Identity)?;
        let mut aad = [0; 56];
        aad[..8].copy_from_slice(MAGIC);
        aad[8..24].copy_from_slice(&salt);
        aad[24..].copy_from_slice(&self.public());
        let (nonce, ciphertext) =
            kryptocore::encrypt(&key, &self.0[..], &aad).map_err(|_| Error::Identity)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut stage = tempfile::NamedTempFile::new_in(parent)?;
        stage.write_all(&aad)?;
        stage.write_all(&nonce)?;
        stage.write_all(&ciphertext)?;
        stage.as_file().sync_all()?;
        stage.persist_noclobber(path).map_err(|err| err.error)?;
        Ok(())
    }

    pub fn load(path: &Path, password: &[u8]) -> Result<Self> {
        if !fs::symlink_metadata(path)?.is_file() || password.is_empty() || password.len() > 1024 {
            return Err(Error::Identity);
        }
        let mut file = File::open(path)?;
        let mut record = [0; 128];
        if !file.metadata()?.is_file() || file.metadata()?.len() != record.len() as u64 {
            return Err(Error::Identity);
        }
        file.read_exact(&mut record)?;
        if &record[..8] != MAGIC || file.read(&mut [0])? != 0 {
            return Err(Error::Identity);
        }
        let salt = record[8..24].try_into().map_err(|_| Error::Identity)?;
        let nonce = record[56..80].try_into().map_err(|_| Error::Identity)?;
        let key = kryptocore::derive_key(password, salt).map_err(|_| Error::Identity)?;
        let secret = kryptocore::decrypt(&key, nonce, &record[80..], &record[..56])
            .map_err(|_| Error::Identity)?;
        if secret.len() != 32 {
            return Err(Error::Identity);
        }
        let mut identity = Self(Zeroizing::new([0; 32]));
        identity.0.copy_from_slice(&secret);
        if identity.public() != record[24..56] {
            return Err(Error::Identity);
        }
        Ok(identity)
    }

    fn handshake(
        &self,
        peer: &PublicKey,
        initiator: bool,
        prologue: &[u8],
    ) -> Result<snow::HandshakeState> {
        if peer == &self.public() {
            return Err(Error::Identity);
        }
        let builder = snow::Builder::with_resolver(PROTOCOL.parse()?, Box::new(dh::Resolver))
            .prologue(prologue)?
            .local_private_key(&self.0[..])?
            .remote_public_key(peer)?;
        Ok(if initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        })
    }
}

struct Connection<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl<'a> Connection<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self {
            stream,
            deadline: Instant::now() + SESSION_TIMEOUT,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        let time = self.deadline.saturating_duration_since(Instant::now());
        if time.is_zero() {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(time)
        }
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.stream.set_read_timeout(Some(self.remaining()?))?;
            match self.stream.read(bytes) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => bytes = &mut bytes[n..],
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.stream.set_write_timeout(Some(self.remaining()?))?;
            match self.stream.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => bytes = &bytes[n..],
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn read_frame(&mut self, buffer: &mut [u8], minimum: usize) -> Result<usize> {
        let mut size = [0; 2];
        self.read_exact(&mut size)?;
        let count = usize::from(u16::from_be_bytes(size));
        if count < minimum || count > buffer.len() {
            return Err(Error::Protocol);
        }
        self.read_exact(&mut buffer[..count])?;
        Ok(count)
    }

    fn write_frame(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_all(
            &u16::try_from(bytes.len())
                .map_err(|_| Error::Protocol)?
                .to_be_bytes(),
        )?;
        self.write_all(bytes)?;
        Ok(())
    }

    fn handshake(
        &mut self,
        local: &Identity,
        peer: &PublicKey,
        initiator: bool,
    ) -> Result<snow::TransportState> {
        self.handshake_for(local, peer, initiator, PROLOGUE)
    }

    fn handshake_for(
        &mut self,
        local: &Identity,
        peer: &PublicKey,
        initiator: bool,
        prologue: &[u8],
    ) -> Result<snow::TransportState> {
        let mut state = local.handshake(peer, initiator, prologue)?;
        // KK uses 32 bytes for the ephemeral public key and a 16-byte tag on each flight.
        let mut handshake = [0; 48];
        let send =
            |conn: &mut Self, state: &mut snow::HandshakeState, frame: &mut [u8]| -> Result<()> {
                let n = state.write_message(&[], frame)?;
                conn.write_frame(&frame[..n])
            };
        let receive =
            |conn: &mut Self, state: &mut snow::HandshakeState, frame: &mut [u8]| -> Result<()> {
                conn.read_frame(frame, 48)?;
                if state.read_message(frame, &mut [])? != 0 {
                    return Err(Error::Protocol);
                }
                Ok(())
            };
        if initiator {
            send(self, &mut state, &mut handshake)?;
            receive(self, &mut state, &mut handshake)?;
        } else {
            receive(self, &mut state, &mut handshake)?;
            send(self, &mut state, &mut handshake)?;
        }
        Ok(state.into_transport_mode()?)
    }
}

pub fn validate_message(message: &str) -> Result<()> {
    if message.trim().is_empty() || message.len() > MAX_MESSAGE || message.chars().any(|c|
        c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    ) {
        return Err(Error::Message);
    }
    Ok(())
}

pub fn send(
    stream: &mut TcpStream,
    local: &Identity,
    peer: &PublicKey,
    message: &str,
) -> Result<()> {
    send_with_progress(stream, local, peer, message, |_| {})
}

#[derive(Clone, Copy)]
pub enum SendProgress {
    Encrypted,
    AwaitingReceipt,
}

pub fn send_with_progress(
    stream: &mut TcpStream,
    local: &Identity,
    peer: &PublicKey,
    message: &str,
    mut progress: impl FnMut(SendProgress),
) -> Result<()> {
    validate_message(message)?;
    let mut connection = Connection::new(stream);
    let mut session = connection.handshake(local, peer, true)?;
    progress(SendProgress::Encrypted);
    let mut sealed = [0; SEALED_MAX];
    let size = session.write_message(message.as_bytes(), &mut sealed)?;
    connection.write_frame(&sealed[..size])?;
    progress(SendProgress::AwaitingReceipt);
    let mut ack = [0; 16 + RECEIPT.len()];
    let size = connection.read_frame(&mut ack, 16 + RECEIPT.len())?;
    let mut plain = [0; RECEIPT.len()];
    let count = session.read_message(&ack[..size], &mut plain)?;
    if &plain[..count] != RECEIPT {
        return Err(Error::Protocol);
    }
    Ok(())
}

pub fn receive(
    stream: &mut TcpStream,
    local: &Identity,
    peer: &PublicKey,
    accept: impl FnOnce(&str) -> io::Result<()>,
) -> Result<()> {
    receive_until(
        stream,
        local,
        peer,
        Instant::now() + SESSION_TIMEOUT,
        accept,
    )
}

/// Receive one message within a caller's listening window.
pub fn receive_until(
    stream: &mut TcpStream,
    local: &Identity,
    peer: &PublicKey,
    deadline: Instant,
    accept: impl FnOnce(&str) -> io::Result<()>,
) -> Result<()> {
    receive_payload_until(
        stream,
        local,
        peer,
        deadline,
        false,
        |payload| match payload {
            Incoming::Text(text) => accept(text),
            Incoming::File { .. } => Err(io::ErrorKind::InvalidData.into()),
        },
    )
}

pub enum Incoming<'a> {
    Text(&'a str),
    File { name: &'a str, bytes: &'a [u8] },
}

/// Receive one payload. Accept files only when the caller has a destination.
pub fn receive_payload_until(
    stream: &mut TcpStream,
    local: &Identity,
    peer: &PublicKey,
    deadline: Instant,
    allow_files: bool,
    accept: impl FnOnce(Incoming<'_>) -> io::Result<()>,
) -> Result<()> {
    let mut connection = Connection::new(stream);
    connection.deadline = deadline.min(Instant::now() + Duration::from_secs(4));
    let mut session = connection.handshake(local, peer, false)?;
    connection.deadline = deadline.min(Instant::now() + SESSION_TIMEOUT);
    let mut sealed = [0; SEALED_MAX];
    let size = connection.read_frame(&mut sealed, 17)?;
    let mut plain = Zeroizing::new([0; MAX_MESSAGE]);
    let length = session.read_message(&sealed[..size], &mut plain[..])?;
    if let Some(header) = plain[..length].strip_prefix(file::PREFIX) {
        if !allow_files {
            return Err(Error::File);
        }
        return file::receive(&mut connection, &mut session, header, accept);
    }
    let text = std::str::from_utf8(&plain[..length]).map_err(|_| Error::Message)?;
    validate_message(text)?;
    accept(Incoming::Text(text))?;
    let size = session.write_message(RECEIPT, &mut sealed)?;
    connection.write_frame(&sealed[..size])?;
    Ok(())
}
