use crate::Error;
use std::{
    fmt,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    str::FromStr,
    time::Duration,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionTarget {
    host: String,
    port: u16,
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

    pub fn connect_presence(&self, socks_port: u16) -> io::Result<TcpStream> {
        let mut stream = proxy_stream(socks_port, Duration::from_secs(15))?;
        let target = Self {
            host: self.host.clone(),
            port: crate::presence::PORT,
        };
        target.socks_connect(&mut stream)?;
        Ok(stream)
    }

    pub fn connect(&self, socks_port: u16, mut retrying: impl FnMut()) -> io::Result<TcpStream> {
        for attempt in 1..=3 {
            let mut stream = proxy_stream(socks_port, Duration::from_secs(25))?;
            match self.socks_connect(&mut stream) {
                Ok(()) => return Ok(stream),
                Err(error)
                    if attempt < 3
                        && matches!(
                            error.kind(),
                            io::ErrorKind::NotFound
                                | io::ErrorKind::HostUnreachable
                                | io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::WouldBlock
                        ) =>
                {
                    retrying();
                    std::thread::sleep(Duration::from_secs(3));
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the final connection attempt always returns")
    }

    fn socks_connect(&self, stream: &mut (impl Read + Write)) -> io::Result<()> {
        negotiate(stream)?;

        // Pass the domain to Tor. Local DNS never receives an onion name.
        let mut request = vec![5, 1, 0, 3, self.host.len() as u8];
        request.extend_from_slice(self.host.as_bytes());
        request.extend_from_slice(&self.port.to_be_bytes());
        stream.write_all(&request)?;

        let mut reply = [0; 4];
        stream.read_exact(&mut reply)?;
        if reply[0] != 5 || reply[2] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SOCKS response",
            ));
        }
        let failure = match reply[1] {
            0 => None,
            0xf0 => Some(io::ErrorKind::NotFound),
            4 | 0xf2 | 0xf3 => Some(io::ErrorKind::HostUnreachable),
            5 => Some(io::ErrorKind::ConnectionRefused),
            6 | 0xf7 => Some(io::ErrorKind::TimedOut),
            0xf1 | 0xf6 => Some(io::ErrorKind::InvalidData),
            0xf4 | 0xf5 => Some(io::ErrorKind::PermissionDenied),
            _ => Some(io::ErrorKind::Other),
        };
        if let Some(kind) = failure {
            return Err(io::Error::new(
                kind,
                "Tor could not reach the onion service",
            ));
        }
        let length = match reply[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut length = [0];
                stream.read_exact(&mut length)?;
                usize::from(length[0])
            }
            _ => return Err(io::Error::other("Invalid SOCKS response")),
        };
        let mut remainder = [0; 257];
        stream.read_exact(&mut remainder[..length + 2])?;
        Ok(())
    }
}

fn proxy_stream(port: u16, read_timeout: Duration) -> io::Result<TcpStream> {
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok(stream)
}

fn negotiate(stream: &mut (impl Read + Write)) -> io::Result<()> {
    stream.write_all(&[5, 1, 0])?;
    let mut method = [0; 2];
    stream.read_exact(&mut method)?;
    if method != [5, 0] {
        return Err(io::Error::other("Tor SOCKS negotiation failed"));
    }
    Ok(())
}

/// Checks the local SOCKS endpoint only. It does not verify a remote onion service.
pub fn probe_proxy(port: u16) -> io::Result<()> {
    negotiate(&mut proxy_stream(port, Duration::from_secs(3))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn sends_onion_name_to_proxy_and_rejects_proxy_failure() {
        struct Proxy(Cursor<Vec<u8>>, Vec<u8>);
        impl Read for Proxy {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.0.read(buffer)
            }
        }
        impl Write for Proxy {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.1.write(buffer)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let host = format!("{}.onion", "a".repeat(56));
        let target: OnionTarget = format!("{host}:49424").parse().unwrap();
        let mut proxy = Proxy(
            Cursor::new(vec![5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            Vec::new(),
        );
        target.socks_connect(&mut proxy).unwrap();
        assert_eq!(&proxy.1[..8], &[5, 1, 0, 5, 1, 0, 3, 62]);
        assert_eq!(&proxy.1[8..70], host.as_bytes());
        assert_eq!(&proxy.1[70..], &49424u16.to_be_bytes());
        let mut denied = Proxy(Cursor::new(vec![5, 0, 5, 4, 0, 1]), Vec::new());
        assert_eq!(
            target.socks_connect(&mut denied).unwrap_err().kind(),
            io::ErrorKind::HostUnreachable
        );
        let mut absent = Proxy(Cursor::new(vec![5, 0, 5, 0xf0, 0, 1]), Vec::new());
        assert_eq!(
            target.socks_connect(&mut absent).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let mut invalid = Proxy(Cursor::new(vec![5, 0, 5, 0xf6, 0, 1]), Vec::new());
        assert_eq!(
            target.socks_connect(&mut invalid).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
