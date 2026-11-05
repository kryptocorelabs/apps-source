//! Authenticated online checks, separate from the message protocol.
use crate::{Connection, Error, Identity, PublicKey, Result};
use std::{
    net::TcpStream,
    time::{Duration, Instant},
};

pub const PORT: u16 = 49425;
const CONTEXT: &[u8] = b"KryptoCore MSG presence v1";
const QUERY: &[u8; 8] = b"presence";
const AVAILABLE: &[u8; 8] = b"online!!";

pub fn check(stream: &mut TcpStream, identity: &Identity, peer: &PublicKey) -> Result<()> {
    exchange(stream, identity, peer, true)
}

pub fn respond(stream: &mut TcpStream, identity: &Identity, peer: &PublicKey) -> Result<()> {
    exchange(stream, identity, peer, false)
}

fn exchange(
    stream: &mut TcpStream,
    identity: &Identity,
    peer: &PublicKey,
    initiator: bool,
) -> Result<()> {
    let mut connection = Connection::new(stream);
    connection.deadline = Instant::now() + Duration::from_secs(if initiator { 12 } else { 5 });
    let mut session = connection.handshake_for(identity, peer, initiator, CONTEXT)?;
    let mut sealed = [0; 24];
    if initiator {
        session.write_message(QUERY, &mut sealed)?;
        connection.write_frame(&sealed)?;
    }
    connection.read_frame(&mut sealed, 24)?;
    let mut plain = [0; 8];
    let expected = if initiator { AVAILABLE } else { QUERY };
    if session.read_message(&sealed, &mut plain)? != plain.len() || &plain != expected {
        return Err(Error::Protocol);
    }
    if !initiator {
        session.write_message(AVAILABLE, &mut sealed)?;
        connection.write_frame(&sealed)?;
    }
    Ok(())
}
