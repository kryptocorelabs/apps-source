use super::{contact_outcome, emit_progress, format_key, msg, read_frame, Outcome, Target};
use msg::{contact::Contact, contact_request as request, tor::OnionTarget};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{self, Write},
    net::{Ipv4Addr, TcpListener},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: u64,
    accept: bool,
}

pub(super) fn listen(identity: &msg::Identity) -> Result<Outcome, String> {
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
                let result = request::receive(&mut stream, identity, |contact, timeout| {
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
                            return decision.accept;
                        }
                    }
                    false
                });
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
