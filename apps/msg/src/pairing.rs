use super::{
    contact::{Contact, Target},
    transport::OnionTarget,
    Connection, Error, Identity, PublicKey, Result, RECEIPT,
};
use std::{
    net::TcpStream,
    time::{Duration, Instant},
};

const PROTOCOL: &str = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s";
const CONTEXT: &[u8] = b"KryptoCore MSG one-code invitation v1";

pub fn new_ticket() -> Result<zeroize::Zeroizing<PublicKey>> {
    let mut ticket = zeroize::Zeroizing::new([0; 32]);
    getrandom::fill(&mut ticket[..]).map_err(|_| Error::Identity)?;
    Ok(ticket)
}

fn state(
    local: &Identity,
    peer: Option<&PublicKey>,
    ticket: &PublicKey,
) -> Result<snow::HandshakeState> {
    let builder = snow::Builder::with_resolver(PROTOCOL.parse()?, Box::new(super::dh::Resolver))
        .prologue(CONTEXT)?
        .local_private_key(&local.0[..])?
        .psk(1, ticket)?;
    if let Some(peer) = peer {
        if peer == &local.public() {
            return Err(Error::Identity);
        }
        Ok(builder.remote_public_key(peer)?.build_initiator()?)
    } else {
        Ok(builder.build_responder()?)
    }
}

pub fn join(
    stream: &mut TcpStream,
    local: &Identity,
    peer: &PublicKey,
    ticket: &PublicKey,
    address: &OnionTarget,
) -> Result<()> {
    let mut connection = Connection::new(stream);
    let mut state = state(local, Some(peer), ticket)?;
    let mut first = [0; 96];
    if state.write_message(&[], &mut first)? != first.len() {
        return Err(Error::Protocol);
    }
    connection.write_frame(&first)?;
    let mut second = [0; 48];
    connection.read_frame(&mut second, 48)?;
    if state.read_message(&second, &mut [])? != 0 {
        return Err(Error::Protocol);
    }
    let mut session = state.into_transport_mode()?;
    let mut sealed = [0; 96];
    let n = session.write_message(address.to_string().as_bytes(), &mut sealed)?;
    connection.write_frame(&sealed[..n])?;
    let n = connection.read_frame(&mut sealed, RECEIPT.len() + 16)?;
    let mut plain = [0; 80];
    let length = session.read_message(&sealed[..n], &mut plain)?;
    if &plain[..length] != RECEIPT {
        return Err(Error::Protocol);
    }
    Ok(())
}

pub fn accept(
    stream: &mut TcpStream,
    local: &Identity,
    ticket: &PublicKey,
    deadline: Instant,
    on_contact: impl FnOnce(Contact),
) -> Result<()> {
    accept_any(stream, local, [ticket], deadline, |_, contact| {
        on_contact(contact)
    })
}

/// Identify the pending invitation by authenticating the same first flight
/// against the bounded set of secrets supplied by the desktop listener.
pub fn accept_any<'a>(
    stream: &mut TcpStream,
    local: &Identity,
    tickets: impl IntoIterator<Item = &'a PublicKey>,
    deadline: Instant,
    on_contact: impl FnOnce(usize, Contact),
) -> Result<()> {
    let mut connection = Connection::new(stream);
    connection.deadline = deadline.min(Instant::now() + Duration::from_secs(8));
    let mut first = [0; 96];
    connection.read_frame(&mut first, 96)?;
    let (index, mut state) = tickets
        .into_iter()
        .enumerate()
        .find_map(|(index, ticket)| {
            let mut candidate = state(local, None, ticket).ok()?;
            (candidate.read_message(&first, &mut []).ok()? == 0).then_some((index, candidate))
        })
        .ok_or(Error::Protocol)?;
    let peer: PublicKey = state
        .get_remote_static()
        .ok_or(Error::Protocol)?
        .try_into()
        .map_err(|_| Error::Protocol)?;
    if peer == local.public() {
        return Err(Error::Identity);
    }
    let mut second = [0; 48];
    if state.write_message(&[], &mut second)? != second.len() {
        return Err(Error::Protocol);
    }
    connection.write_frame(&second)?;
    let mut session = state.into_transport_mode()?;
    let mut sealed = [0; 96];
    let size = connection.read_frame(&mut sealed, 17)?;
    let mut plain = [0; 80];
    let length = session.read_message(&sealed[..size], &mut plain)?;
    let target = std::str::from_utf8(&plain[..length])
        .map_err(|_| Error::Protocol)?
        .parse::<OnionTarget>()?;
    on_contact(index, Contact::new(peer, Some(Target::Onion(target)))?);
    let length = session.write_message(RECEIPT, &mut sealed)?;
    connection.write_frame(&sealed[..length])
}
