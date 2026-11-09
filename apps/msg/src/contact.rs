//! A versioned contact card. Authenticity depends on how its key is verified.
use crate::{Error, PublicKey};
use std::{
    fmt::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

const PREFIX: &str = "KCM1-";
pub const SEALED_PREFIX: &str = "KCM2-";
pub const INVITE_PREFIX: &str = "KCM3-";
pub const OPEN_INVITE_PREFIX: &str = "KCM3O-";
const CONTACT_CONTEXT: &[u8] = b"KryptoCore MSG encrypted contact v2";
const INVITE_CONTEXT: &[u8] = b"KryptoCore MSG invitation v3";
const MAX_CODE: usize = 160;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
    Direct(SocketAddr),
    Onion(crate::transport::OnionTarget),
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return valid_destination(address)
                .then_some(Self::Direct(address))
                .ok_or(Error::Identity);
        }
        Ok(Self::Onion(value.parse()?))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(address) => address.fmt(out),
            Self::Onion(address) => address.fmt(out),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contact {
    pub key: PublicKey,
    endpoint: Option<Target>,
}

impl Contact {
    pub fn new(key: PublicKey, endpoint: Option<Target>) -> Result<Self, Error> {
        if matches!(endpoint, Some(Target::Direct(address)) if !valid_destination(address)) {
            return Err(Error::Identity);
        }
        Ok(Self { key, endpoint })
    }

    pub fn endpoint(&self) -> Option<&Target> {
        self.endpoint.as_ref()
    }

    pub fn seal(&self, passphrase: &[u8]) -> Result<String, Error> {
        seal_code(
            &self.to_string(),
            passphrase,
            SEALED_PREFIX,
            CONTACT_CONTEXT,
        )
    }

    pub fn open(code: &str, passphrase: &[u8]) -> Result<Self, Error> {
        let plain = open_code(code, passphrase, SEALED_PREFIX, CONTACT_CONTEXT, MAX_CODE)?;
        std::str::from_utf8(&plain)
            .map_err(|_| Error::Identity)?
            .parse()
    }
}

pub fn encode_invitation(
    contact: &Contact,
    ticket: Option<&PublicKey>,
    passphrase: &[u8],
) -> Result<String, Error> {
    let mut plain = zeroize::Zeroizing::new(contact.to_string());
    if let Some(ticket) = ticket {
        plain.push('\n');
        write_hex(&mut *plain, ticket.iter()).expect("writing to String");
    }
    if passphrase.is_empty() {
        let mut code = String::from(OPEN_INVITE_PREFIX);
        write_hex(&mut code, plain.as_bytes().iter()).expect("writing to String");
        Ok(code)
    } else {
        seal_code(&plain, passphrase, INVITE_PREFIX, INVITE_CONTEXT)
    }
}

pub fn decode_invitation(
    code: &str,
    passphrase: &[u8],
) -> Result<(Contact, Option<zeroize::Zeroizing<PublicKey>>), Error> {
    let limit = MAX_CODE + 65;
    let plain = if let Some(hex) = code.strip_prefix(OPEN_INVITE_PREFIX) {
        zeroize::Zeroizing::new(read_hex(hex, 69, limit)?)
    } else {
        open_code(code, passphrase, INVITE_PREFIX, INVITE_CONTEXT, limit)?
    };
    let plain = std::str::from_utf8(&plain).map_err(|_| Error::Identity)?;
    if let Some((contact, ticket)) = plain.split_once('\n') {
        let ticket = zeroize::Zeroizing::new(parse_key(ticket)?);
        Ok((contact.parse()?, Some(ticket)))
    } else {
        Ok((plain.parse()?, None))
    }
}

fn seal_code(
    plain: &str,
    passphrase: &[u8],
    prefix: &str,
    context: &[u8],
) -> Result<String, Error> {
    let mut salt = [0; 16];
    getrandom::fill(&mut salt).map_err(|_| Error::Identity)?;
    let key = invitation_key(passphrase, &salt)?;
    let (nonce, ciphertext) =
        kryptocore::encrypt(&key, plain.as_bytes(), context).map_err(|_| Error::Identity)?;
    let mut code = String::from(prefix);
    write_hex(&mut code, salt.iter().chain(&nonce).chain(&ciphertext)).expect("writing to String");
    Ok(code)
}

fn open_code(
    code: &str,
    passphrase: &[u8],
    prefix: &str,
    context: &[u8],
    limit: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let hex = code.strip_prefix(prefix).ok_or(Error::Identity)?;
    const OVERHEAD: usize = 16 + 24 + 16;
    let bytes = read_hex(hex, OVERHEAD + 69, OVERHEAD + limit)?;
    let salt = bytes[..16].try_into().map_err(|_| Error::Identity)?;
    let nonce = bytes[16..40].try_into().map_err(|_| Error::Identity)?;
    let key = invitation_key(passphrase, salt)?;
    kryptocore::decrypt(&key, nonce, &bytes[40..], context).map_err(|_| Error::Identity)
}

fn read_hex(hex: &str, minimum: usize, limit: usize) -> Result<Vec<u8>, Error> {
    if !(2 * minimum..=2 * limit).contains(&hex.len())
        || hex.len() % 2 != 0
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::Identity);
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| Error::Identity))
        .collect()
}

fn invitation_key(passphrase: &[u8], salt: &kryptocore::Salt) -> Result<kryptocore::Key, Error> {
    if passphrase.len() > 1024
        || std::str::from_utf8(passphrase)
            .map_err(|_| Error::Identity)?
            .chars()
            .count()
            < 20
    {
        return Err(Error::Identity);
    }
    kryptocore::derive_key(passphrase, salt).map_err(|_| Error::Identity)
}

pub fn valid_destination(address: SocketAddr) -> bool {
    let ip = address.ip().to_canonical();
    address.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
        && !matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0)
}

impl FromStr for Contact {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_CODE {
            return Err(Error::Identity);
        }
        let payload = value.strip_prefix(PREFIX).ok_or(Error::Identity)?;
        let (key, endpoint) = match payload.split_once('~') {
            Some((key, endpoint)) => (key, Some(endpoint.parse().map_err(|_| Error::Identity)?)),
            None => (payload, None),
        };
        Self::new(parse_key(key)?, endpoint)
    }
}

impl fmt::Display for Contact {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(PREFIX)?;
        write_hex(out, &self.key)?;
        if let Some(endpoint) = &self.endpoint {
            write!(out, "~{endpoint}")?;
        }
        Ok(())
    }
}

pub fn parse_key(value: &str) -> Result<PublicKey, Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Identity);
    }
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::Identity)?;
    }
    Ok(key)
}

fn write_hex<'a>(out: &mut impl Write, bytes: impl IntoIterator<Item = &'a u8>) -> fmt::Result {
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    Ok(())
}

pub fn format_key(key: &PublicKey) -> String {
    let mut text = String::with_capacity(64);
    write_hex(&mut text, key).expect("writing to String");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_key_only_and_ipv4_or_ipv6_contacts() {
        for endpoint in [
            None,
            Some("127.0.0.1:49424".parse().unwrap()),
            Some("[2001:db8::42]:443".parse().unwrap()),
        ] {
            let contact = Contact::new([0x9b; 32], endpoint).unwrap();
            assert_eq!(contact.to_string().parse::<Contact>().unwrap(), contact);
        }
    }

    #[test]
    fn encrypted_contacts_hide_the_route_and_reject_modifications() {
        let route = format!("{}.onion:49424", "a".repeat(56));
        let contact = Contact::new([0x9b; 32], Some(route.parse().unwrap())).unwrap();
        let passphrase = b"test only invitation secret";
        let code = contact.seal(passphrase).unwrap();
        assert!(!code.contains(&route));
        assert!(!code.contains(&format_key(&contact.key)));
        assert_eq!(Contact::open(&code, passphrase).unwrap(), contact);
        assert!(Contact::open(&code, b"a different passphrase").is_err());
        let mut modified = code;
        let final_digit = modified.pop().unwrap();
        modified.push(if final_digit == '0' { '1' } else { '0' });
        assert!(Contact::open(&modified, passphrase).is_err());
    }

    #[test]
    fn rejects_invalid_codes_and_non_destination_addresses() {
        let key = format_key(&[0x9b; 32]);
        for suffix in [
            "~",
            "~0.0.0.0:77",
            "~[::]:77",
            "~255.255.255.255:77",
            "~[ff02::1]:77",
            "~[::ffff:0.0.0.0]:77",
            "~127.0.0.1:0",
            "~host.example:77",
            "~127.0.0.1:77~127.0.0.1:88",
        ] {
            assert!(format!("{PREFIX}{key}{suffix}").parse::<Contact>().is_err());
        }
        assert!(format!("KCM2-{key}").parse::<Contact>().is_err());
        assert!(format!("{PREFIX}abcd").parse::<Contact>().is_err());
    }
}
