use super::{emit_progress, msg, msg_error, read_frame, Outcome, Target};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::{self, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Text { text: String },
    File { path: PathBuf },
    Folder { path: PathBuf },
    Status { enabled: bool },
}

fn emit(frame: &impl Serialize) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, frame)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

#[derive(Serialize)]
struct TextEvent<'a> {
    event: &'static str,
    text: &'a str,
}

struct Attachment {
    name: String,
    remaining: usize,
    destination: Option<(PathBuf, Zeroizing<Vec<u8>>)>,
}

fn read_channel(
    channel: &msg::chat::Channel,
    folder: &Mutex<Option<PathBuf>>,
    pending: &AtomicBool,
) -> Result<(), msg::Error> {
    use msg::chat::Event;
    let mut attachment: Option<Attachment> = None;
    channel.read(|event| {
        match event {
            Event::Text(text) if attachment.is_none() => {
                emit(&TextEvent { event: "chat_text", text })?;
                channel.receipt(true)?;
            }
            Event::File { name, size } if attachment.is_none() => {
                let selected = folder.lock().map_err(|_| msg::Error::Protocol)?.clone();
                attachment = Some(Attachment {
                    name: name.into(),
                    remaining: size,
                    destination: selected.map(|path| (path, Zeroizing::new(Vec::with_capacity(size)))),
                });
            }
            Event::Data(bytes) => {
                let file = attachment.as_mut().ok_or(msg::Error::Protocol)?;
                file.remaining = file.remaining.checked_sub(bytes.len()).ok_or(msg::Error::File)?;
                if let Some((_, buffer)) = &mut file.destination {
                    buffer.extend_from_slice(bytes);
                }
            }
            Event::Receipt(ok) if pending.swap(false, Ordering::AcqRel) => {
                emit(&json!({ "event": "chat_receipt", "ok": ok }))?;
            }
            Event::Status(enabled) => {
                emit(&json!({ "event": "chat_status", "ok": enabled }))?;
            }
            _ => return Err(msg::Error::Protocol),
        }
        if attachment.as_ref().is_some_and(|file| file.remaining == 0) {
            let file = attachment.take().ok_or(msg::Error::Protocol)?;
            let saved = file.destination.and_then(|(folder, bytes)| {
                msg::save_received_file(&folder, &file.name, &bytes).ok()
            });
            emit(&json!({
                "event": "chat_file",
                "saved_file": saved,
                "message": if saved.is_some() { "Datei gespeichert." } else {
                    "Datei nicht gespeichert. Wähle einen Empfangsordner und prüfe, ob der Dateiname schon vorhanden ist."
                },
            }))?;
            channel.receipt(saved.is_some())?;
        }
        Ok(())
    })
}

fn connect(
    identity: &msg::Identity,
    peer: &msg::PublicKey,
    target: Target,
    local: SocketAddr,
    socks_port: Option<u16>,
    stopped: &AtomicBool,
) -> Result<msg::chat::Channel, String> {
    // Both sides choose the same direction independently, even on simultaneous opens.
    let dial = identity.public() > *peer;
    let listener = if dial {
        emit_progress(true, "connecting");
        None
    } else {
        let listener =
            TcpListener::bind(local).map_err(|_| "Der lokale Chat-Port ist bereits belegt.")?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        emit_progress(true, "chat_waiting");
        Some(listener)
    };
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline && !stopped.load(Ordering::Acquire) {
        let stream = match (&listener, &target) {
            (Some(listener), _) => match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|error| error.to_string())?;
                    Ok(stream)
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    Err(error)
                }
                Err(error) => return Err(error.to_string()),
            },
            (None, Target::Direct(address)) => {
                TcpStream::connect_timeout(address, Duration::from_secs(3))
            }
            (None, Target::Onion(address)) => address.connect(socks_port.unwrap_or(0), || {}),
        };
        if let Ok(stream) = stream {
            if let Ok(channel) = msg::chat::Channel::open(stream, identity, peer, dial) {
                return Ok(channel);
            }
        }
        thread::sleep(Duration::from_millis(if dial { 750 } else { 100 }));
    }
    Err("Kein Chatkanal geöffnet. Öffnet ihn auf beiden Geräten und prüft, ob ihr die aktuellen Kontaktcodes und dieselbe MSG-Version verwendet.".into())
}

pub(super) fn run(
    identity: msg::Identity,
    peer: msg::PublicKey,
    target: Target,
    local: SocketAddr,
    socks_port: Option<u16>,
) -> Result<Outcome, String> {
    let (sender, commands) = mpsc::sync_channel(1);
    let stopped = Arc::new(AtomicBool::new(false));
    let input_closed = Arc::clone(&stopped);
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        while let Ok(frame) = read_frame(&mut input, 32 * 1024) {
            if sender.send(frame).is_err() {
                break;
            }
        }
        input_closed.store(true, Ordering::Release);
    });
    let channel = Arc::new(connect(
        &identity, &peer, target, local, socks_port, &stopped,
    )?);
    drop(identity);
    let folder = Arc::new(Mutex::new(None));
    let pending = Arc::new(AtomicBool::new(false));
    emit_progress(true, "chat_connected");
    let reader = {
        let (channel, folder, pending) = (
            Arc::clone(&channel),
            Arc::clone(&folder),
            Arc::clone(&pending),
        );
        thread::spawn(move || read_channel(&channel, &folder, &pending))
    };
    let result = (|| {
        while !reader.is_finished() && !stopped.load(Ordering::Acquire) {
            let frame = match commands.recv_timeout(Duration::from_millis(100)) {
                Ok(frame) => frame,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let command = serde_json::from_slice(&frame).map_err(|_| msg::Error::Protocol)?;
            let sent = match command {
                Command::Folder { path } if path.is_absolute() && path.is_dir() => {
                    *folder.lock().map_err(|_| msg::Error::Protocol)? = Some(path);
                    emit_progress(true, "chat_folder");
                    continue;
                }
                Command::Folder { .. } => {
                    emit_progress(true, "chat_folder_error");
                    continue;
                }
                Command::Status { enabled } => {
                    channel.share_status(enabled)?;
                    continue;
                }
                Command::Text { text } if !pending.swap(true, Ordering::AcqRel) => {
                    channel.send_text(&Zeroizing::new(text))
                }
                Command::File { path } if !pending.swap(true, Ordering::AcqRel) => {
                    channel.send_file(&path)
                }
                _ => return Err(msg::Error::Protocol),
            };
            match sent {
                Err(msg::Error::Message | msg::Error::File) => {
                    pending.store(false, Ordering::Release);
                    emit_progress(true, "chat_invalid_payload");
                }
                result => result?,
            }
        }
        Ok(())
    })();
    channel.close();
    let _ = reader.join();
    result.map_err(msg_error)?;
    Ok(Outcome::message("Chatkanal geschlossen."))
}
