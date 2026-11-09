#![forbid(unsafe_code)]

use kryptocore_container as container;
use kryptocore_msg as msg;
use msg::contact::{
    decode_invitation, encode_invitation, format_key, parse_key, Contact, Target, INVITE_PREFIX,
    OPEN_INVITE_PREFIX, SEALED_PREFIX,
};
use msg::{
    tor::SocksOnionTransport,
    transport::{OnionTarget, OnionTransport},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, IsTerminal, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

mod chat;
mod contact_request;

const MAX_PENDING_INVITATIONS: usize = 8;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Generate,
    CheckTor,
    Pack {
        output: PathBuf,
        sources: Vec<PathBuf>,
        opener: Option<PathBuf>,
    },
    Check {
        input: PathBuf,
        #[serde(default)]
        embedded: bool,
    },
    Unpack {
        input: PathBuf,
        output: PathBuf,
        signer: Option<Signer>,
        native_signer: Option<NativeSigner>,
        scanner: Option<PathBuf>,
        #[serde(default)]
        embedded: bool,
    },
    Sign {
        input: PathBuf,
        tool: PathBuf,
        key: PathBuf,
        output: PathBuf,
    },
    Verify {
        input: PathBuf,
        signer: Signer,
    },
    NewSigningKey {
        output: PathBuf,
    },
    SigningPublic {
        key: PathBuf,
    },
    NativeSign {
        input: PathBuf,
        key: PathBuf,
        output: PathBuf,
    },
    NativeVerify {
        input: PathBuf,
        signer: NativeSigner,
    },
    NewIdentity {
        path: PathBuf,
    },
    PublicKey {
        path: PathBuf,
    },
    MakeContact {
        key: String,
        address: Option<String>,
        #[serde(default)]
        one_code: bool,
        #[serde(default)]
        without_password: bool,
    },
    ReadContact {
        code: String,
    },
    SetContactPolicy {
        path: PathBuf,
        required: bool,
    },
    WaitInvitation {
        path: PathBuf,
    },
    JoinInvitation {
        path: PathBuf,
        peer: String,
        address: String,
        own_address: String,
        socks_port: u16,
    },
    ListenContactRequests {
        path: PathBuf,
    },
    SendContactRequest {
        path: PathBuf,
        address: String,
        own_address: String,
        socks_port: u16,
    },
    Contacts {
        path: PathBuf,
        update: Option<ContactUpdate>,
    },
    BlockedContacts {
        path: PathBuf,
        remove: Option<String>,
    },
    Presence {
        path: PathBuf,
        peer: String,
        address: String,
        socks_port: u16,
    },
    Chat {
        path: PathBuf,
        peer: String,
        address: String,
        local: SocketAddr,
        tor: bool,
        socks_port: Option<u16>,
    },
    Send {
        path: PathBuf,
        peer: String,
        address: String,
        #[serde(default)]
        tor: bool,
        #[serde(default)]
        progress: bool,
        socks_port: Option<u16>,
        attachment: Option<PathBuf>,
    },
    Receive {
        path: PathBuf,
        peer: String,
        address: SocketAddr,
        #[serde(default)]
        tor: bool,
        #[serde(default)]
        progress: bool,
        folder: Option<PathBuf>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedContact {
    name: String,
    key: String,
    address: Option<String>,
    #[serde(default)]
    verified: bool,
}

#[derive(Serialize)]
struct StoredContact<'a> {
    name: &'a str,
    key: &'a str,
    address: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ContactUpdate {
    Save { contact: SavedContact },
    Remove { key: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signer {
    tool: PathBuf,
    allowed: PathBuf,
    principal: String,
    signature: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSigner {
    signature: PathBuf,
    expected_public: String,
}
impl NativeSigner {
    fn verification(&self) -> Result<container::native_signature::Verification, String> {
        container::native_signature::Verification::from_file(&self.signature, &self.expected_public)
            .map_err(container_error)
    }
}

impl Signer {
    fn verification(&self) -> Result<container::signature::Verification<'_>, String> {
        Ok(container::signature::Verification {
            ssh_keygen: absolute_tool(&self.tool)?,
            allowed_signers: &self.allowed,
            principal: &self.principal,
            signature: &self.signature,
        })
    }
}

#[derive(Default)]
struct Outcome {
    message: String,
    text: Option<Zeroizing<String>>,
    address: Option<String>,
    acknowledged: Option<bool>,
    saved_file: Option<String>,
    ticket: Option<Zeroizing<String>>,
    two_codes: Option<bool>,
    invitation_index: Option<usize>,
}

impl Outcome {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ..Self::default()
        }
    }
    fn text(message: &str, value: Zeroizing<String>) -> Self {
        Self {
            message: message.into(),
            text: Some(value),
            ..Self::default()
        }
    }
}

#[derive(Serialize)]
struct Response<'a> {
    ok: bool,
    message: &'a str,
    text: Option<&'a str>,
    address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acknowledged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    saved_file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ticket: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_codes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invitation_index: Option<usize>,
}

#[derive(Serialize)]
struct ProgressEvent {
    event: &'static str,
}

fn emit_progress(enabled: bool, event: &'static str) {
    if !enabled {
        return;
    }
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &ProgressEvent { event }).is_ok() {
        let _ = stdout.write_all(b"\n").and_then(|()| stdout.flush());
    }
}

fn read_frame(input: &mut impl Read, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut size = [0; 4];
    input.read_exact(&mut size)?;
    let size = u32::from_le_bytes(size) as usize;
    if size > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn container_error(error: container::Error) -> String {
    match error {
        container::Error::Authentication => "Passphrase falsch oder Container beschädigt.".into(),
        container::Error::SignatureRejected => "Die Signatur passt nicht zum ausgewählten Absender. Zum Signieren mit einem geschützten Schlüssel muss er im SSH-Agent geladen sein.".into(),
        container::Error::ScanRejected => "ClamAV hat die Dateien abgelehnt oder den Scan nicht abgeschlossen.".into(),
        container::Error::Io(ref io) if io.kind() == io::ErrorKind::AlreadyExists => "Das Ziel existiert schon. Wähle einen neuen Namen.".into(),
        container::Error::Io(ref io) if io.kind() == io::ErrorKind::UnexpectedEof => "Die Containerdatei ist unvollständig.".into(),
        _ => error.to_string(),
    }
}

fn msg_error(error: msg::Error) -> String {
    match error {
        msg::Error::Identity => "Identitätsdatei, öffentlicher Schlüssel oder Passphrase ungültig.".into(),
        msg::Error::Protocol => "Die Gegenstelle konnte nicht bestätigt werden. Öffnet auf beiden Rechnern jeweils den Code der anderen Person.".into(),
        msg::Error::Message => "Die Nachricht muss eine einzelne Textzeile mit maximal 4096 UTF-8-Bytes sein.".into(),
        msg::Error::File => "Dateiname oder Dateigröße ungültig. Das Limit liegt bei 16 MiB.".into(),
        msg::Error::Io(ref io) if io.kind() == io::ErrorKind::AlreadyExists => "Diese Identitätsdatei existiert bereits.".into(),
        _ => error.to_string(),
    }
}

fn absolute_tool(path: &Path) -> Result<&Path, String> {
    path.is_absolute()
        .then_some(path)
        .ok_or("Wähle den vollständigen Pfad des vertrauenswürdigen Programms.".into())
}

fn confirm(first: &[u8], second: &[u8]) -> Result<(), String> {
    if first != second {
        return Err("Die Passphrasen stimmen nicht überein.".into());
    }
    if first.len() > 1024
        || !std::str::from_utf8(first).is_ok_and(|value| value.chars().count() >= 15)
    {
        return Err(
            "Die Passphrase muss mindestens 15 Zeichen und darf höchstens 1024 UTF-8-Bytes haben."
                .into(),
        );
    }
    Ok(())
}

fn result_summary(label: &str, result: container::Summary) -> Outcome {
    Outcome::message(format!(
        "{label} · {} Einträge · {} Bytes",
        result.entries, result.bytes
    ))
}

fn public_outcome(label: &str, identity: &msg::Identity) -> Outcome {
    Outcome::text(label, Zeroizing::new(format_key(&identity.public())))
}

fn contact_outcome(label: &str, contact: Contact) -> Outcome {
    let mut outcome = Outcome::text(label, Zeroizing::new(format_key(&contact.key)));
    outcome.address = contact.endpoint().map(ToString::to_string);
    outcome
}

fn ticket_from_wire(bytes: &[u8]) -> Result<Zeroizing<msg::PublicKey>, String> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| parse_key(value).ok())
        .map(Zeroizing::new)
        .ok_or_else(|| "Erstelle oder öffne zuerst eine gültige Einladung.".into())
}

fn wait_invitation(
    identity: &msg::Identity,
    tickets: &[Zeroizing<msg::PublicKey>],
) -> Result<Outcome, String> {
    let address = SocketAddr::from(([127, 0, 0, 1], 49424));
    let listener = TcpListener::bind(address)
        .map_err(|_| "Der MSG-Empfang ist auf diesem Rechner bereits belegt.")?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(300);
    emit_progress(true, "invitation_listening");
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|error| error.to_string())?;
                let mut contact = None;
                let result = msg::pairing::accept_any(
                    &mut stream,
                    identity,
                    tickets.iter().map(|ticket| &**ticket),
                    deadline,
                    |index, peer| contact = Some((index, peer)),
                );
                if let Some((index, peer)) = contact {
                    let mut outcome = contact_outcome(
                        if result.is_ok() {
                            "Einladung angenommen."
                        } else {
                            "Einladung angenommen. Die Bestätigung konnte nicht zugestellt werden."
                        },
                        peer,
                    );
                    outcome.invitation_index = Some(index);
                    return Ok(outcome);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("In fünf Minuten wurde keine Einladung angenommen. Du kannst erneut warten.".into())
}

fn listen_for_peer(
    address: SocketAddr,
    identity: &msg::Identity,
    peer: &msg::PublicKey,
    progress: bool,
    folder: Option<&Path>,
    wait: Duration,
) -> Result<Outcome, String> {
    let listener = TcpListener::bind(address).map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + wait;
    emit_progress(progress, "listening");
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|error| error.to_string())?;
                let mut received = None;
                let mut save_error = None;
                let result = msg::receive_payload_until(
                    &mut stream,
                    identity,
                    peer,
                    deadline,
                    folder.is_some(),
                    |payload| {
                        // A replayed first handshake flight cannot produce a valid transport message.
                        emit_progress(progress, "encrypted");
                        received = Some(match payload {
                            msg::Incoming::Text(message) => Outcome::text(
                                "Nachricht empfangen.",
                                Zeroizing::new(message.to_owned()),
                            ),
                            msg::Incoming::File { name, bytes } => {
                                let folder = folder.ok_or(io::ErrorKind::InvalidInput)?;
                                let path = msg::save_received_file(folder, name, bytes).inspect_err(|error| {
                                save_error = Some(if error.kind() == io::ErrorKind::AlreadyExists {
                                    "Eine Datei mit diesem Namen liegt bereits im Empfangsordner. Verschiebe sie oder wähle einen anderen Ordner."
                                } else {
                                    "Die Datei konnte im Empfangsordner nicht gespeichert werden."
                                });
                            })?;
                                Outcome {
                                    saved_file: Some(path.to_string_lossy().into_owned()),
                                    ..Outcome::message("Datei gespeichert.")
                                }
                            }
                        });
                        Ok(())
                    },
                );
                // A port scan or a different key must not cancel the listening window.
                if let Some(mut outcome) = received {
                    if result.is_err() {
                        outcome
                            .message
                            .push_str(" Die Empfangsbestätigung konnte nicht gesendet werden.");
                    }
                    outcome.acknowledged = Some(result.is_ok());
                    return Ok(outcome);
                }
                if let Some(error) = save_error {
                    return Err(error.into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Err(format!("Innerhalb von {} Minuten kam keine bestätigte Übertragung an. Prüft, ob beide den Code der jeweils anderen Person geöffnet haben.", wait.as_secs() / 60))
}

fn manage_contacts(
    path: &Path,
    password: &[u8],
    update: Option<ContactUpdate>,
) -> Result<Outcome, String> {
    let identity = msg::Identity::load(path, password).map_err(msg_error)?;
    let book = msg::ContactBook::open(path, &identity).map_err(msg_error)?;
    let error = "Die verschlüsselte Kontaktliste konnte nicht gelesen oder gespeichert werden.";
    let mut contacts: Vec<SavedContact> =
        serde_json::from_slice(&book.read().map_err(|_| error)?).map_err(|_| error)?;
    let verification = msg::ContactBook::verification(path, &identity).map_err(|_| error)?;
    let mut verified_keys: Vec<String> =
        serde_json::from_slice(&verification.read().map_err(|_| error)?).map_err(|_| error)?;
    if verified_keys.len() > 256 || verified_keys.iter().any(|key| parse_key(key).is_err()) {
        return Err(error.into());
    }
    verified_keys.retain(|key| contacts.iter().any(|contact| &contact.key == key));
    for contact in &mut contacts {
        contact.verified = verified_keys.contains(&contact.key);
    }
    if let Some(update) = update {
        match update {
            ContactUpdate::Save { mut contact } => {
                contact.name = contact.name.trim().to_owned();
                let key = parse_key(&contact.key).map_err(msg_error)?;
                if key == identity.public()
                    || contact.name.len() > 120
                    || msg::validate_message(&contact.name).is_err()
                {
                    return Err("Wähle einen Namen mit höchstens 120 UTF-8-Bytes und den Schlüssel der anderen Person.".into());
                }
                if let Some(address) = &contact.address {
                    address
                        .parse::<Target>()
                        .map_err(|_| "Die Kontaktadresse ist ungültig.")?;
                }
                contact.key = format_key(&key);
                contacts.retain(|saved| saved.key != contact.key);
                if contacts.len() >= 100 {
                    return Err("Die Kontaktliste kann bis zu 100 Kontakte enthalten.".into());
                }
                contacts.push(contact);
            }
            ContactUpdate::Remove { key } => {
                let key = format_key(&parse_key(&key).map_err(msg_error)?);
                contacts.retain(|saved| saved.key != key);
            }
        }
        contacts.sort_by(|left, right| left.name.cmp(&right.name));
        let updated_verified: Vec<_> = contacts
            .iter()
            .filter(|contact| contact.verified)
            .map(|contact| contact.key.clone())
            .collect();
        verified_keys.retain(|key| updated_verified.contains(key));
        // Remove trust first, then update records, then add explicit comparisons.
        // Partial writes and missing metadata can only reduce the displayed trust.
        verification
            .write(&serde_json::to_vec(&verified_keys).map_err(|_| error)?)
            .map_err(|_| error)?;
        let stored: Vec<_> = contacts
            .iter()
            .map(|contact| StoredContact {
                name: &contact.name,
                key: &contact.key,
                address: contact.address.as_deref(),
            })
            .collect();
        let contents = Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| error)?);
        book.write(&contents).map_err(|_| error)?;
        verification
            .write(&serde_json::to_vec(&updated_verified).map_err(|_| error)?)
            .map_err(|_| error)?;
    }
    let contents = Zeroizing::new(serde_json::to_string(&contacts).map_err(|_| error)?);
    Ok(Outcome::text("Kontaktliste geöffnet.", contents))
}

fn run_presence(
    identity: msg::Identity,
    peer: msg::PublicKey,
    target: OnionTarget,
    onion: impl OnionTransport + Send + 'static,
) -> Result<Outcome, String> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], msg::presence::PORT)))
        .map_err(|_| "Der lokale Statusdienst ist bereits belegt.")?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let stopped = Arc::new(AtomicBool::new(false));
    let parent_closed = Arc::clone(&stopped);
    std::thread::spawn(move || {
        let _ = io::stdin().read(&mut [0]);
        parent_closed.store(true, Ordering::Relaxed);
    });
    let identity = Arc::new(identity);
    let probe_identity = Arc::clone(&identity);
    let probe_stopped = Arc::clone(&stopped);
    let target = target.with_port(msg::presence::PORT);
    emit_progress(true, "presence_ready");
    std::thread::spawn(move || {
        while !probe_stopped.load(Ordering::Relaxed) {
            let online = onion.connect_presence(&target).is_ok_and(|mut stream| {
                msg::presence::check(&mut stream, &probe_identity, &peer).is_ok()
            });
            if !probe_stopped.load(Ordering::Relaxed) {
                emit_progress(
                    true,
                    if online {
                        "presence_online"
                    } else {
                        "presence_unknown"
                    },
                );
            }
            std::thread::sleep(Duration::from_secs(25));
        }
    });
    while !stopped.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if stream.set_nonblocking(false).is_ok() {
                    let _ = msg::presence::respond(&mut stream, &identity, &peer);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(Outcome::message("Online-Status beendet."))
}

fn execute(request: Request, first: &mut [u8], second: &[u8]) -> Result<Outcome, String> {
    match request {
        Request::CheckTor => {
            msg::tor::probe_proxy(9050)
                .map_err(|_| "Kein SOCKS-Proxy auf 127.0.0.1:9050 erreichbar. Starte Tor mit der MSG-Konfiguration.")?;
            Ok(Outcome::message(
                "Lokaler SOCKS-Proxy antwortet. Die Gegenstelle ist damit noch nicht geprüft.",
            ))
        }
        Request::Generate => Ok(Outcome::text(
            "Passphrase erzeugt.",
            container::generate_passphrase().map_err(container_error)?,
        )),
        Request::Pack {
            output,
            sources,
            opener,
        } => {
            confirm(first, second)?;
            if sources.is_empty() || sources.len() > 10_000 {
                return Err("Wähle mindestens eine und höchstens 10.000 Quellen.".into());
            }
            let result = if let Some(opener) = opener {
                container::pack_executable(&opener, &output, &sources, first)
            } else {
                container::pack(&output, &sources, first)
            };
            Ok(result_summary(
                "Container erstellt",
                result.map_err(container_error)?,
            ))
        }
        Request::Check { input, embedded } => {
            let result = if embedded {
                container::check_executable(&input, first)
            } else {
                container::check(&input, first)
            };
            Ok(result_summary(
                "Integrität bestätigt",
                result.map_err(container_error)?,
            ))
        }
        Request::Unpack {
            input,
            output,
            signer,
            native_signer,
            scanner,
            embedded,
        } => {
            let native = native_signer
                .as_ref()
                .map(NativeSigner::verification)
                .transpose()?;
            let legacy = signer.as_ref().map(Signer::verification).transpose()?;
            let result = container::unpack_protected(
                &input,
                &output,
                first,
                container::OpenPolicy {
                    embedded,
                    native: native.as_ref(),
                    openssh: legacy.as_ref(),
                    scanner: scanner.as_deref(),
                },
            );
            let label = if native.is_some() || legacy.is_some() {
                "Entpackt; ausgewählter Signierschlüssel bestätigt"
            } else {
                "Entpackt; Absender nicht geprüft"
            };
            let mut outcome = result_summary(label, result.map_err(container_error)?);
            outcome.message.push_str(if scanner.is_some() {
                " · Malware-Scan abgeschlossen, keine Erkennung"
            } else {
                " · Kein Malware-Scan angefordert"
            });
            Ok(outcome)
        }
        Request::NewSigningKey { output } => {
            confirm(first, second)?;
            let public = container::native_signature::generate_key(&output, first)
                .map_err(container_error)?;
            Ok(Outcome::text("Passwortgeschützter Signierschlüssel angelegt. Öffentlichen Code separat abgleichen.",Zeroizing::new(public)))
        }
        Request::SigningPublic { key } => {
            let public =
                container::native_signature::export_public(&key, first).map_err(container_error)?;
            Ok(Outcome::text(
                "Öffentlicher Signiercode. Diesen Code über einen vertrauenswürdigen Kanal teilen.",
                Zeroizing::new(public),
            ))
        }
        Request::NativeSign { input, key, output } => {
            container::native_signature::sign(&input, &key, first, &output)
                .map_err(container_error)?;
            Ok(Outcome::message(
                "KryptoCore-Signatur gespeichert. Sie bestätigt keine Virenfreiheit.",
            ))
        }
        Request::NativeVerify { input, signer } => {
            signer
                .verification()?
                .verify(&input)
                .map_err(container_error)?;
            Ok(Outcome::message("Dateisignatur entspricht dem gewählten öffentlichen Schlüssel. Kein Virenscan durchgeführt."))
        }
        Request::Sign {
            input,
            tool,
            key,
            output,
        } => {
            container::signature::sign_noninteractive(absolute_tool(&tool)?, &key, &input, &output)
                .map_err(container_error)?;
            Ok(Outcome::message("Signaturdatei gespeichert."))
        }
        Request::Verify { input, signer } => {
            signer
                .verification()?
                .verify(&input)
                .map_err(container_error)?;
            Ok(Outcome::message(
                "Signatur und ausgewählter Absender bestätigt.",
            ))
        }
        Request::NewIdentity { path } => {
            confirm(first, second)?;
            let identity = msg::Identity::generate().map_err(msg_error)?;
            identity.save(&path, first).map_err(msg_error)?;
            Ok(public_outcome(
                "Identität gespeichert. Teile nur den öffentlichen Schlüssel.",
                &identity,
            ))
        }
        Request::PublicKey { path } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            let mut outcome = public_outcome("Eigener öffentlicher Schlüssel geladen.", &identity);
            outcome.two_codes =
                Some(msg::ContactBook::require_two_codes(&path, &identity).map_err(msg_error)?);
            Ok(outcome)
        }
        Request::MakeContact {
            key,
            address,
            one_code,
            without_password,
        } => {
            let key = parse_key(&key).map_err(msg_error)?;
            let address = address
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|_| {
                    "Gib eine Onion-Adresse oder eine erreichbare IP-Adresse mit Port ein."
                })?;
            let contact = Contact::new(key, address).map_err(msg_error)?;
            if one_code && !matches!(contact.endpoint(), Some(Target::Onion(_))) {
                return Err("Für die einfache Einladung braucht MSG eine Tor-Adresse.".into());
            }
            let ticket = one_code
                .then(msg::pairing::new_ticket)
                .transpose()
                .map_err(msg_error)?;
            let code = if one_code || without_password {
                if !without_password && first.is_empty() {
                    return Err("Gib eine Code-Passphrase ein.".into());
                }
                encode_invitation(
                    &contact,
                    ticket.as_deref(),
                    if without_password { &[] } else { first },
                )
            } else {
                contact.seal(first)
            }
            .map_err(|_| {
                "Verwende für den Kontaktcode eine Passphrase mit mindestens 20 Zeichen."
            })?;
            let mut outcome = Outcome::text("Kontaktcode erstellt.", Zeroizing::new(code));
            outcome.ticket = ticket.map(|value| Zeroizing::new(format_key(&value)));
            Ok(outcome)
        }
        Request::ReadContact { code } => {
            if code.starts_with(INVITE_PREFIX) || code.starts_with(OPEN_INVITE_PREFIX) {
                let (contact, ticket) = decode_invitation(&code, first)
                    .map_err(|_| "Einladung oder Code-Passphrase ungültig.")?;
                let mut outcome = contact_outcome("Einladung geöffnet.", contact);
                outcome.ticket = ticket.map(|value| Zeroizing::new(format_key(&value)));
                return Ok(outcome);
            }
            let contact: Contact = if code.starts_with(SEALED_PREFIX) {
                Contact::open(&code, first).map_err(|_| "Kontaktcode oder Passphrase ungültig.")?
            } else {
                let contact: Contact = code
                    .parse()
                    .map_err(|_| "Dieser MSG-Kontaktcode ist ungültig.")?;
                if matches!(contact.endpoint(), Some(Target::Onion(_))) {
                    return Err("Onion-Adressen brauchen einen verschlüsselten Kontaktcode.".into());
                }
                contact
            };
            let mut result = Outcome::text(
                "Kontaktcode geöffnet. Öffne auch auf dem anderen Rechner den Code der Gegenstelle.",
                Zeroizing::new(format_key(&contact.key)),
            );
            result.address = contact.endpoint().map(ToString::to_string);
            Ok(result)
        }
        Request::SetContactPolicy { path, required } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            msg::ContactBook::set_require_two_codes(&path, &identity, required)
                .map_err(msg_error)?;
            Ok(Outcome::message("Einladungseinstellung gespeichert."))
        }
        Request::WaitInvitation { path } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            if msg::ContactBook::require_two_codes(&path, &identity).map_err(msg_error)? {
                return Err("Diese Identität verlangt zwei Kontaktcodes.".into());
            }
            first.zeroize();
            const WIRE_TICKET: usize = 64;
            if second.is_empty()
                || second.len() > MAX_PENDING_INVITATIONS * WIRE_TICKET
                || second.len() % WIRE_TICKET != 0
            {
                return Err("Die Einladungsliste ist ungültig.".into());
            }
            let tickets = second
                .chunks_exact(WIRE_TICKET)
                .map(ticket_from_wire)
                .collect::<Result<Vec<_>, _>>()?;
            wait_invitation(&identity, &tickets)
        }
        Request::JoinInvitation {
            path,
            peer,
            address,
            own_address,
            socks_port,
        } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            if msg::ContactBook::require_two_codes(&path, &identity).map_err(msg_error)? {
                return Err("Diese Identität verlangt zwei Kontaktcodes.".into());
            }
            first.zeroize();
            let peer = parse_key(&peer).map_err(msg_error)?;
            let target: OnionTarget = address.parse().map_err(msg_error)?;
            let own_address = own_address.parse().map_err(msg_error)?;
            let ticket = ticket_from_wire(second)?;
            emit_progress(true, "connecting");
            let mut stream = SocksOnionTransport::new(socks_port)
                .connect(&target, &mut || emit_progress(true, "tor_retry"))
                .map_err(|_| "Die Einladung ist nicht erreichbar. Die andere Person muss auf „Auf Annahme warten“ klicken.")?;
            emit_progress(true, "handshake");
            msg::pairing::join(&mut stream, &identity, &peer, &ticket, &own_address)
                .map_err(|_| "Einladung konnte nicht bestätigt werden. Prüfe, ob die andere Person noch auf diese Einladung wartet.")?;
            Ok(Outcome::message("Einladung angenommen."))
        }
        Request::ListenContactRequests { path } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            first.zeroize();
            if msg::ContactBook::require_two_codes(&path, &identity).map_err(msg_error)? {
                return Err("Diese Identität verlangt zwei Kontaktcodes.".into());
            }
            contact_request::listen(&path, &identity)
        }
        Request::SendContactRequest {
            path,
            address,
            own_address,
            socks_port,
        } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            first.zeroize();
            if msg::ContactBook::require_two_codes(&path, &identity).map_err(msg_error)? {
                return Err("Diese Identität verlangt zwei Kontaktcodes.".into());
            }
            let onion = (socks_port != 0).then(|| SocksOnionTransport::new(socks_port));
            contact_request::send(
                &identity,
                &address,
                &own_address,
                onion.as_ref().map(|transport| transport as &dyn OnionTransport),
            )
        }
        Request::Contacts { path, update } => manage_contacts(&path, first, update),
        Request::BlockedContacts { path, remove } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            first.zeroize();
            contact_request::blocked_contacts(&path, &identity, remove.as_deref())
        }
        Request::Presence {
            path,
            peer,
            address,
            socks_port,
        } => {
            let peer = parse_key(&peer).map_err(msg_error)?;
            let target = address
                .parse()
                .map_err(|_| "Der Kontakt braucht eine Onion-Adresse.")?;
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            first.zeroize();
            if identity.public() == peer || socks_port == 0 {
                return Err("Wähle einen bestätigten Kontakt und starte Tor.".into());
            }
            run_presence(identity, peer, target, SocksOnionTransport::new(socks_port))
        }
        Request::Chat {
            path,
            peer,
            address,
            local,
            tor,
            socks_port,
        } => {
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            first.zeroize();
            let peer = parse_key(&peer).map_err(msg_error)?;
            let target = address.parse::<Target>().map_err(msg_error)?;
            if identity.public() == peer
                || tor
                    && (local != SocketAddr::from(([127, 0, 0, 1], 49424))
                        || !matches!(target, Target::Onion(_))
                        || socks_port.unwrap_or(0) == 0)
                || !tor && !matches!(target, Target::Direct(_))
            {
                return Err("Prüfe den Kontaktcode und die Verbindungseinstellungen.".into());
            }
            let onion = socks_port.filter(|port| *port != 0).map(SocksOnionTransport::new);
            chat::run(
                identity,
                peer,
                target,
                local,
                onion.as_ref().map(|transport| transport as &dyn OnionTransport),
            )
        }
        Request::Send {
            path,
            peer,
            address,
            tor,
            progress,
            socks_port,
            attachment,
        } => {
            let peer = parse_key(&peer).map_err(msg_error)?;
            let target: Target = address.parse().map_err(|_| "Ungültige Zieladresse.")?;
            if tor && !matches!(target, Target::Onion(_)) {
                return Err("Im Tor-Modus ist eine Onion-Adresse erforderlich.".into());
            }
            let message = std::str::from_utf8(second)
                .map_err(|_| "Die Nachricht ist kein gültiger UTF-8-Text.")?;
            if attachment.is_none() {
                msg::validate_message(message).map_err(msg_error)?;
            }
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            emit_progress(progress, "connecting");
            let mut stream = match target {
                Target::Direct(address) => TcpStream::connect_timeout(&address, Duration::from_secs(10))
                    .map_err(|_| "Gegenstelle nicht erreichbar. Prüfe Zieladresse, Port und ob der Empfang läuft.")?,
                Target::Onion(address) => SocksOnionTransport::new(
                    socks_port.filter(|port| *port != 0).ok_or("Der lokale Tor-Dienst wurde noch nicht gestartet.")?,
                ).connect(
                    &address,
                    &mut || emit_progress(progress, "tor_retry"),
                ).map_err(|error| match error.kind() {
                    io::ErrorKind::InvalidData => "Tor meldet eine ungültige Zieladresse. Öffne einen frisch erstellten Code der Gegenstelle.",
                    io::ErrorKind::NotFound => "Tor findet die Empfangsadresse noch nicht. Prüfe den aktuellen Kontaktcode und ob am Zielrechner „Empfang bereit“ steht.",
                    _ => "Tor erreicht den Kontakt nicht. Prüfe am Zielrechner, ob „Empfang bereit“ steht und ob die Tor-Adresse inzwischen gewechselt wurde.",
                })?,
            };
            emit_progress(progress, "handshake");
            let report = |stage| {
                let event = match stage {
                    msg::SendProgress::Encrypted => "encrypted",
                    msg::SendProgress::AwaitingReceipt => "awaiting_receipt",
                };
                emit_progress(progress, event);
            };
            if let Some(file) = attachment {
                msg::send_file(&mut stream, &identity, &peer, &file, report).map_err(msg_error)?;
                Ok(Outcome::message("Datei von der Gegenstelle bestätigt."))
            } else {
                msg::send_with_progress(&mut stream, &identity, &peer, message, report)
                    .map_err(msg_error)?;
                Ok(Outcome::message("Nachricht von der Gegenstelle bestätigt."))
            }
        }
        Request::Receive {
            path,
            peer,
            address,
            tor,
            progress,
            folder,
        } => {
            if tor && address != SocketAddr::from(([127, 0, 0, 1], 49424)) {
                return Err("Tor-Empfang lauscht ausschließlich auf 127.0.0.1:49424.".into());
            }
            let peer = parse_key(&peer).map_err(msg_error)?;
            let identity = msg::Identity::load(&path, first).map_err(msg_error)?;
            if identity.public() == peer {
                return Err("Wähle den Schlüssel der Gegenstelle. Für einen lokalen Test brauchst du zwei Identitäten.".into());
            }
            let wait = Duration::from_secs(if tor { 300 } else { 120 });
            listen_for_peer(address, &identity, &peer, progress, folder.as_deref(), wait)
        }
    }
}

fn handle() -> Result<Outcome, String> {
    let mut input = io::stdin().lock();
    let data = read_frame(&mut input, 1024 * 1024).map_err(|_| "Ungültige App-Anfrage.")?;
    let request = serde_json::from_slice(&data).map_err(|_| "Ungültige App-Anfrage.")?;
    let mut first =
        read_frame(&mut input, 1024).map_err(|_| "Die Passphrase ist zu lang oder fehlt.")?;
    let second = read_frame(&mut input, msg::MAX_MESSAGE)
        .map_err(|_| "Die Eingabe ist zu lang oder fehlt.")?;
    drop(input);
    execute(request, &mut first, &second)
}

fn main() -> io::Result<()> {
    if io::stdin().is_terminal() || io::stdout().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Start the Windows desktop app.",
        ));
    }
    let result = handle();
    let response = match &result {
        Ok(value) => Response {
            ok: true,
            message: &value.message,
            text: value.text.as_deref().map(String::as_str),
            address: value.address.as_deref(),
            acknowledged: value.acknowledged,
            saved_file: value.saved_file.as_deref(),
            ticket: value.ticket.as_deref().map(String::as_str),
            two_codes: value.two_codes,
            invitation_index: value.invitation_index,
        },
        Err(message) => Response {
            ok: false,
            message,
            text: None,
            address: None,
            acknowledged: None,
            saved_file: None,
            ticket: None,
            two_codes: None,
            invitation_index: None,
        },
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response)?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_save_preserves_legacy_records_and_tracks_optional_key_comparison() {
        let directory =
            std::env::temp_dir().join(format!("msg-contact-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("identity.kcmi");
        let password = b"only a synthetic test passphrase";
        let identity = msg::Identity::generate().unwrap();
        identity.save(&path, password).unwrap();
        let peer = format_key(&msg::Identity::generate().unwrap().public());
        {
            let store = msg::ContactBook::open(&path, &identity).unwrap();
            let legacy =
                serde_json::json!([{ "name": "Old contact", "key": peer, "address": null }]);
            store.write(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        }
        let legacy = manage_contacts(&path, password, None).unwrap();
        let data: serde_json::Value =
            serde_json::from_str(legacy.text.as_deref().unwrap()).unwrap();
        assert_eq!(data[0]["verified"], false);
        for verified in [false, true] {
            let reply = manage_contacts(
                &path,
                password,
                Some(ContactUpdate::Save {
                    contact: SavedContact {
                        name: "Chat contact".into(),
                        key: peer.clone(),
                        address: None,
                        verified,
                    },
                }),
            )
            .unwrap();
            let data: serde_json::Value =
                serde_json::from_str(reply.text.as_deref().unwrap()).unwrap();
            assert_eq!(data[0]["verified"], verified);
            let store = msg::ContactBook::open(&path, &identity).unwrap();
            let stored: serde_json::Value = serde_json::from_slice(&store.read().unwrap()).unwrap();
            assert!(stored[0].get("verified").is_none());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
