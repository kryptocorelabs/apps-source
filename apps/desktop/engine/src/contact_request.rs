use super::{
    contact_outcome, emit_progress, format_key, msg, parse_key, read_frame, Outcome, Target,
};
use msg::{contact::Contact, contact_request as request, tor::OnionTarget};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{self, Write},
    net::{Ipv4Addr, TcpListener},
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: u64,
    accept: bool,
    #[serde(default)]
    block: bool,
}

fn read_blocked(store: &msg::ContactBook) -> Result<Vec<String>, String> {
    let keys: Vec<String> = serde_json::from_slice(
        &store
            .read()
            .map_err(|_| "Die Blockierliste konnte nicht gelesen werden.")?,
    )
    .map_err(|_| "Die Blockierliste ist beschädigt.")?;
    if keys.len() > 256 || keys.iter().any(|key| parse_key(key).is_err()) {
        return Err("Die Blockierliste ist ungültig.".into());
    }
    Ok(keys)
}

pub(super) fn blocked_contacts(
    path: &Path,
    identity: &msg::Identity,
    remove: Option<&str>,
) -> Result<Outcome, String> {
    let store = msg::ContactBook::blocked(path, identity)
        .map_err(|_| "Die Blockierliste ist nicht verfügbar.")?;
    let mut keys = read_blocked(&store)?;
    if let Some(key) = remove {
        let key = format_key(&parse_key(key).map_err(|_| "Ungültiger Kontaktschlüssel.")?);
        keys.retain(|blocked| blocked != &key);
        store
            .write(&serde_json::to_vec(&keys).map_err(|_| "Ungültige Blockierliste.")?)
            .map_err(|_| "Die Blockierliste konnte nicht gespeichert werden.")?;
    }
    Ok(Outcome::text(
        "Blockierte Kontakte geladen.",
        zeroize::Zeroizing::new(
            serde_json::to_string(&keys).map_err(|_| "Ungültige Blockierliste.")?,
        ),
    ))
}

pub(super) fn listen(path: &Path, identity: &msg::Identity) -> Result<Outcome, String> {
    blocked_contacts(path, identity, None)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, request::PORT))
        .map_err(|_| "Kontaktanfragen sind bereits in einem MSG-Fenster aktiv.")?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let (sender, decisions) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        while let Ok(frame) = read_frame(&mut input, 256) {
            let Ok(decision) = serde_json::from_slice::<Decision>(&frame) else {
                break;
            };
            if sender.send(decision).is_err() {
                break;
            }
        }
    });
    emit_progress(true, "request_listening");
    let mut id = 0;
    loop {
        if matches!(decisions.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
            return Ok(Outcome::message("Kontaktanfragen ausgeschaltet."));
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|error| error.to_string())?;
                id += 1;
                let mut shown = false;
                let mut block_error = false;
                let mut blocked_now = false;
                let result = request::receive(&mut stream, identity, |contact, timeout| {
                    let key = format_key(&contact.key);
                    let Ok(store) = msg::ContactBook::blocked(path, identity) else {
                        return false;
                    };
                    let Ok(mut blocked) = read_blocked(&store) else {
                        return false;
                    };
                    if blocked.contains(&key) {
                        return false;
                    }
                    // Release the file lock while waiting for the user's decision.
                    drop(store);
                    let frame = json!({
                        "event": "incoming_request", "id": id, "key": format_key(&contact.key),
                        "address": contact.endpoint().map(ToString::to_string),
                    });
                    let published = {
                        let mut stdout = io::stdout().lock();
                        serde_json::to_writer(&mut stdout, &frame).is_ok()
                            && stdout
                                .write_all(b"\n")
                                .and_then(|()| stdout.flush())
                                .is_ok()
                    };
                    if !published {
                        return false;
                    }
                    shown = true;
                    let deadline = Instant::now() + timeout;
                    while let Ok(decision) =
                        decisions.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    {
                        if decision.id == id {
                            if !decision.accept && decision.block {
                                let saved = (|| {
                                    let store = msg::ContactBook::blocked(path, identity).ok()?;
                                    blocked = read_blocked(&store).ok()?;
                                    if !blocked.contains(&key) {
                                        blocked.push(key.clone());
                                    }
                                    if blocked.len() > 256 {
                                        return None;
                                    }
                                    store.write(&serde_json::to_vec(&blocked).ok()?).ok()
                                })();
                                block_error = saved.is_none();
                                blocked_now = saved.is_some();
                            }
                            return decision.accept;
                        }
                    }
                    false
                });
                if block_error {
                    emit_progress(true, "request_block_error");
                }
                if blocked_now {
                    emit_progress(true, "request_blocked");
                }
                if shown {
                    emit_progress(true, "request_cleared");
                }
                if let Ok(Some(contact)) = result {
                    return Ok(contact_outcome("Kontaktanfrage angenommen.", contact));
                }
                thread::sleep(Duration::from_millis(750));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionAborted
                ) =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return Err("Kontaktanfragen wurden unterbrochen.".into()),
        }
    }
}

pub(super) fn send(
    identity: &msg::Identity,
    address: &str,
    own_address: &str,
    socks_port: u16,
) -> Result<Outcome, String> {
    let target: OnionTarget = address
        .parse()
        .map_err(|_| "Gib eine gültige .onion-Adresse ein.")?;
    let own: OnionTarget = own_address
        .parse()
        .map_err(|_| "Deine Tor-Adresse ist noch nicht verfügbar.")?;
    let target = target.with_port(request::CHAT_PORT);
    if target == own.with_port(request::CHAT_PORT) || socks_port == 0 {
        return Err("Gib die Tor-Adresse der anderen Person ein.".into());
    }
    emit_progress(true, "request_connecting");
    let mut stream = target.with_port(request::PORT).connect(socks_port, || {})
        .map_err(|_| "Die Adresse ist nicht erreichbar oder die andere Person hat Kontaktanfragen ausgeschaltet.")?;
    emit_progress(true, "request_waiting");
    let key = request::send(&mut stream, identity, &own)
        .map_err(|_| "Die Anfrage wurde unterbrochen oder ist abgelaufen.")?
        .ok_or("Die andere Person hat die Anfrage abgelehnt oder sie ist abgelaufen.")?;
    let contact =
        Contact::new(key, Some(Target::Onion(target))).map_err(|_| "Ungültiger Kontakt.")?;
    Ok(contact_outcome("Kontaktanfrage angenommen.", contact))
}
