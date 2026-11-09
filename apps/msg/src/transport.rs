//! App-owned interface for connecting to a validated onion destination.

use crate::Error;
use std::{fmt, io, net::TcpStream, str::FromStr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl FromStr for OnionTarget {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        let (host, port) = value.rsplit_once(':').ok_or(Error::Identity)?;
        let name = host.strip_suffix(".onion").ok_or(Error::Identity)?;
        let port = port.parse::<u16>().map_err(|_| Error::Identity)?;
        if name.len() != 56
            || !name
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
            || port == 0
        {
            return Err(Error::Identity);
        }
        Ok(Self {
            host: host.into(),
            port,
        })
    }
}

impl fmt::Display for OnionTarget {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{}:{}", self.host, self.port)
    }
}

impl OnionTarget {
    pub fn with_port(&self, port: u16) -> Self {
        Self {
            host: self.host.clone(),
            port,
        }
    }
}

/// Route only through the onion network and return a stream for the MSG protocol.
/// Implementations must keep onion names away from local DNS and fail if the
/// onion connection cannot be made. The caller owns peer authentication.
pub trait OnionTransport {
    fn connect(&self, target: &OnionTarget, retrying: &mut dyn FnMut()) -> io::Result<TcpStream>;

    /// Open a single bounded connection for a presence probe.
    fn connect_presence(&self, target: &OnionTarget) -> io::Result<TcpStream>;
}
