//! Bidirectional chat over one authenticated Noise transport.
use super::{file, validate_message, Connection, Error, Identity, PublicKey, Result};
use std::{
    fs::{self, File},
    io::Read,
    net::{Shutdown, TcpStream},
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CONTEXT: &[u8] = b"KryptoCore MSG chat v1";
const CHUNK: usize = 32 * 1024;
const READY: u8 = 0;
const TEXT: u8 = 1;
const FILE: u8 = 2;
const DATA: u8 = 3;
const ACCEPTED: u8 = 4;
const REJECTED: u8 = 5;
const STATUS_ON: u8 = 6;
const STATUS_OFF: u8 = 7;

pub struct Channel {
    socket: TcpStream,
    session: Mutex<snow::TransportState>,
    writer: Mutex<TcpStream>,
}

pub enum Event<'a> {
    Text(&'a str),
    File { name: &'a str, size: usize },
    Data(&'a [u8]),
    Receipt(bool),
    Status(bool),
}

impl Channel {
    pub fn open(
        mut socket: TcpStream,
        identity: &Identity,
        peer: &PublicKey,
        dial: bool,
    ) -> Result<Self> {
        socket.set_nodelay(true)?;
        let mut connection = Connection::new(&mut socket);
        connection.deadline = Instant::now() + Duration::from_secs(10);
        let mut session = connection.handshake_for(identity, peer, dial, CONTEXT)?;
        let send = |connection: &mut Connection<'_>, session: &mut snow::TransportState| {
            let mut sealed = [0; 17];
            session.write_message(&[READY], &mut sealed)?;
            connection.write_frame(&sealed)
        };
        let receive = |connection: &mut Connection<'_>, session: &mut snow::TransportState| {
            let mut sealed = [0; 17];
            let mut plain = [0];
            connection.read_frame(&mut sealed, 17)?;
            if session.read_message(&sealed, &mut plain)? != 1 || plain != [READY] {
                return Err(Error::Protocol);
            }
            Ok(())
        };
        if dial {
            send(&mut connection, &mut session)?;
            receive(&mut connection, &mut session)?;
        } else {
            // A replay of the first KK handshake flight alone must not open a channel.
            receive(&mut connection, &mut session)?;
            send(&mut connection, &mut session)?;
        }
        Ok(Self {
            writer: Mutex::new(socket.try_clone()?),
            socket,
            session: Mutex::new(session),
        })
    }

    fn write(&self, kind: u8, body: &[u8]) -> Result<()> {
        self.write_until(kind, body, Instant::now() + super::SESSION_TIMEOUT)
    }

    fn write_until(&self, kind: u8, body: &[u8], deadline: Instant) -> Result<()> {
        let mut plain = Zeroizing::new(Vec::with_capacity(1 + body.len()));
        plain.push(kind);
        plain.extend_from_slice(body);
        let mut sealed = vec![0; plain.len() + 16];
        let mut socket = self.writer.lock().map_err(|_| Error::Protocol)?;
        self.session
            .lock()
            .map_err(|_| Error::Protocol)?
            .write_message(&plain, &mut sealed)?;
        let mut connection = Connection::new(&mut socket);
        connection.deadline = deadline;
        connection.write_frame(&sealed)
    }

    pub fn send_text(&self, text: &str) -> Result<()> {
        validate_message(text)?;
        self.write(TEXT, text.as_bytes())
    }

    pub fn send_file(&self, path: &Path) -> Result<()> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::File)?;
        if !file::valid_name(name) || !fs::symlink_metadata(path)?.is_file() {
            return Err(Error::File);
        }
        let mut source = File::open(path)?;
        let metadata = source.metadata()?;
        let size = metadata.len();
        if !metadata.is_file() || size > file::MAX_FILE_SIZE {
            return Err(Error::File);
        }
        let mut header = size.to_be_bytes().to_vec();
        header.extend_from_slice(name.as_bytes());
        let deadline = Instant::now() + Duration::from_secs(240);
        self.write_until(FILE, &header, deadline)?;
        let mut bytes = Zeroizing::new(vec![0; CHUNK]);
        let mut remaining = size;
        while remaining != 0 {
            let count = remaining.min(CHUNK as u64) as usize;
            source.read_exact(&mut bytes[..count])?;
            self.write_until(DATA, &bytes[..count], deadline)?;
            remaining -= count as u64;
        }
        Ok(())
    }

    pub fn receipt(&self, accepted: bool) -> Result<()> {
        self.write(if accepted { ACCEPTED } else { REJECTED }, &[])
    }

    pub fn share_status(&self, enabled: bool) -> Result<()> {
        self.write(if enabled { STATUS_ON } else { STATUS_OFF }, &[])
    }

    /// Use one reader. Its callback is invoked only for authenticated frames.
    pub fn read(&self, mut on_event: impl FnMut(Event<'_>) -> Result<()>) -> Result<()> {
        let mut socket = self.socket.try_clone()?;
        let mut sealed = vec![0; CHUNK + 17];
        let mut plain = Zeroizing::new(vec![0; CHUNK + 1]);
        loop {
            let mut size = [0; 2];
            socket.set_read_timeout(None)?;
            socket.read_exact(&mut size[..1])?;
            let mut connection = Connection::new(&mut socket);
            connection.read_exact(&mut size[1..])?;
            let size = usize::from(u16::from_be_bytes(size));
            if !(17..=sealed.len()).contains(&size) {
                return Err(Error::Protocol);
            }
            connection.read_exact(&mut sealed[..size])?;
            let len = self
                .session
                .lock()
                .map_err(|_| Error::Protocol)?
                .read_message(&sealed[..size], &mut plain)?;
            let (&kind, body) = plain[..len].split_first().ok_or(Error::Protocol)?;
            let event = match kind {
                TEXT => {
                    let text = std::str::from_utf8(body).map_err(|_| Error::Message)?;
                    validate_message(text)?;
                    Event::Text(text)
                }
                FILE => {
                    let size = body.get(..8).ok_or(Error::File)?;
                    let size = u64::from_be_bytes(size.try_into().map_err(|_| Error::File)?);
                    let name = std::str::from_utf8(&body[8..]).map_err(|_| Error::File)?;
                    if size > file::MAX_FILE_SIZE || !file::valid_name(name) {
                        return Err(Error::File);
                    }
                    Event::File {
                        name,
                        size: size as usize,
                    }
                }
                DATA if !body.is_empty() => Event::Data(body),
                ACCEPTED | REJECTED if body.is_empty() => Event::Receipt(kind == ACCEPTED),
                STATUS_ON | STATUS_OFF if body.is_empty() => Event::Status(kind == STATUS_ON),
                _ => return Err(Error::Protocol),
            };
            on_event(event)?;
            plain[..len].fill(0);
        }
    }

    pub fn close(&self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
