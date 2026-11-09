//! First contact over an authenticated Tor onion service.
use super::{
    contact::{Contact, Target},
    dh::Resolver,
    transport::OnionTarget,
    Connection, Error, Identity, PublicKey, Result,
};
use std::{
    net::TcpStream,
    time::{Duration, Instant},
};

pub const PORT: u16 = 49426;
pub const CHAT_PORT: u16 = 49424;
const PROTOCOL: &str = "Noise_XN_25519_ChaChaPoly_BLAKE2s";
const CONTEXT: &[u8] = b"KryptoCore MSG onion contact request v1";
const DECISION_TIMEOUT: Duration = Duration::from_secs(45);

fn handshake(
    connection: &mut Connection<'_>,
    local: Option<&Identity>,
) -> Result<(snow::TransportState, Option<PublicKey>)> {
    let builder =
        snow::Builder::with_resolver(PROTOCOL.parse()?, Box::new(Resolver)).prologue(CONTEXT)?;
    let mut state = if let Some(identity) = local {
        builder
            .local_private_key(&identity.0[..])?
            .build_initiator()?
    } else {
        builder.build_responder()?
    };
    for (flight, length) in [32, 48, 64].into_iter().enumerate() {
        let mut frame = [0; 64];
        if (flight % 2 == 0) == local.is_some() {
            if state.write_message(&[], &mut frame)? != length {
                return Err(Error::Protocol);
            }
            connection.write_frame(&frame[..length])?;
        } else {
            connection.read_frame(&mut frame[..length], length)?;
            if state.read_message(&frame[..length], &mut [])? != 0 {
                return Err(Error::Protocol);
            }
        }
    }
    let peer = state
        .get_remote_static()
        .map(PublicKey::try_from)
        .transpose()
        .map_err(|_| Error::Protocol)?;
    Ok((state.into_transport_mode()?, peer))
}

/// Tor authenticates the supplied onion service. The returned MSG key is pinned
/// for the subsequent mutually authenticated chat.
pub fn send(
    stream: &mut TcpStream,
    local: &Identity,
    own_address: &OnionTarget,
) -> Result<Option<PublicKey>> {
    let mut connection = Connection::new(stream);
    let (mut session, _) = handshake(&mut connection, Some(local))?;
    let mut frame = [0; 96];
    let address = own_address.with_port(CHAT_PORT).to_string();
    let size = session.write_message(address.as_bytes(), &mut frame)?;
    connection.write_frame(&frame[..size])?;
    connection.deadline = Instant::now() + DECISION_TIMEOUT + Duration::from_secs(10);
    let mut plain = [0; 32];
    let size = connection.read_frame(&mut frame[..48], 16)?;
    match session.read_message(&frame[..size], &mut plain)? {
        0 => Ok(None),
        32 if plain != local.public() && plain != [0; 32] => Ok(Some(plain)),
        _ => Err(Error::Protocol),
    }
}

pub fn receive(
    stream: &mut TcpStream,
    local: &Identity,
    decide: impl FnOnce(&Contact, Duration) -> bool,
) -> Result<Option<Contact>> {
    let mut connection = Connection::new(stream);
    connection.deadline = Instant::now() + Duration::from_secs(6);
    let (mut session, peer) = handshake(&mut connection, None)?;
    let peer = peer
        .filter(|key| *key != local.public())
        .ok_or(Error::Identity)?;
    let mut frame = [0; 96];
    let mut plain = [0; 80];
    let size = connection.read_frame(&mut frame, 17)?;
    let size = session.read_message(&frame[..size], &mut plain)?;
    let address = std::str::from_utf8(&plain[..size])
        .map_err(|_| Error::Protocol)?
        .parse::<OnionTarget>()?
        .with_port(CHAT_PORT);
    let contact = Contact::new(peer, Some(Target::Onion(address)))?;
    let accepted = decide(&contact, DECISION_TIMEOUT);
    let key = local.public();
    let size = session.write_message(if accepted { &key } else { &[] }, &mut frame)?;
    connection.deadline = Instant::now() + Duration::from_secs(5);
    connection.write_frame(&frame[..size])?;
    Ok(accepted.then_some(contact))
}
