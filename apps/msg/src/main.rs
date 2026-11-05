#![forbid(unsafe_code)]

use kryptocore_msg::{receive, send, validate_message, Error, Identity, PublicKey, MAX_MESSAGE};
use std::{
    ffi::OsString,
    io::{self, BufRead, IsTerminal, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

const USAGE: &str = "KryptoCore MSG (alpha)

  kryptocore-msg keygen <new-identity.kcmi>
  kryptocore-msg public <identity.kcmi>
  kryptocore-msg receive <identity.kcmi> <verified-peer-public-key> <listen-ip:port>
  kryptocore-msg send <identity.kcmi> <verified-peer-public-key> <peer-ip:port>

Share public keys via a trusted channel. Start receive before send.";

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if (args.is_empty() && io::stdin().is_terminal() && io::stdout().is_terminal())
        || args == ["--interactive"]
    {
        menu()
    } else {
        run(&args)
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn menu() -> Result<(), Box<dyn std::error::Error>> {
    println!("KryptoCore MSG");
    println!("Beide Seiten brauchen eine Identität und den geprüften öffentlichen Schlüssel der anderen Seite.");
    println!(
        "Relative Pfade beziehen sich auf: {}",
        std::env::current_dir()?.display()
    );
    loop {
        println!("\n1  Identität erstellen\n2  Eigenen öffentlichen Schlüssel anzeigen\n3  Nachricht empfangen\n4  Nachricht senden\n0  Beenden");
        let Some(choice) = ask("Auswahl: ")? else {
            return Ok(());
        };
        let (command, label) = match choice.as_str() {
            "1" => ("keygen", "Neue Identitätsdatei, z. B. ich.kcmi"),
            "2" => ("public", "Eigene Identitätsdatei"),
            "3" => ("receive", "Eigene Identitätsdatei"),
            "4" => ("send", "Eigene Identitätsdatei"),
            "0" => return Ok(()),
            _ => {
                println!("Bitte wähle 0 bis 4.");
                continue;
            }
        };
        let Some(path) = ask(&format!("{label} (leer zum Abbrechen): "))? else {
            return Ok(());
        };
        let path = path
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .unwrap_or(&path);
        if path.is_empty() {
            continue;
        }
        let mut args = vec![command.into(), OsString::from(path)];
        if matches!(command, "receive" | "send") {
            let Some(peer) =
                ask("Geprüfter öffentlicher Schlüssel der Gegenstelle (leer zum Abbrechen): ")?
            else {
                return Ok(());
            };
            if peer.is_empty() {
                continue;
            }
            let Some(address) =
                ask("IP-Adresse:Port (Enter für Test auf diesem PC, 127.0.0.1:49424): ")?
            else {
                return Ok(());
            };
            args.push(peer.into());
            args.push(if address.is_empty() {
                "127.0.0.1:49424".into()
            } else {
                address.into()
            });
        }
        if let Err(error) = run(&args) {
            eprintln!("{error}");
        }
    }
}

fn ask(label: &str) -> io::Result<Option<String>> {
    print!("{label}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_owned()))
}

fn prompt(label: &str) -> Result<Zeroizing<String>, Error> {
    Ok(Zeroizing::new(rpassword::prompt_password(label)?))
}

fn parse_key(value: &OsString) -> Result<PublicKey, Error> {
    let text = value
        .to_str()
        .filter(|s| s.len() == 64 && s.is_ascii())
        .ok_or(Error::Identity)?;
    let mut key = [0; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        let pair = &text[i * 2..i * 2 + 2];
        if !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Identity);
        }
        *byte = u8::from_str_radix(pair, 16).map_err(|_| Error::Identity)?;
    }
    Ok(key)
}

fn print_public(identity: &Identity) {
    for byte in identity.public() {
        print!("{byte:02x}");
    }
    println!();
}

fn read_message() -> Result<Zeroizing<Vec<u8>>, Error> {
    eprint!("Message: ");
    io::stderr().flush()?;
    let mut message = Zeroizing::new(Vec::with_capacity(MAX_MESSAGE + 2));
    io::stdin()
        .lock()
        .take((MAX_MESSAGE + 3) as u64)
        .read_until(b'\n', &mut message)?;
    if message.last() == Some(&b'\n') {
        message.pop();
        if message.last() == Some(&b'\r') {
            message.pop();
        }
    }
    let text = std::str::from_utf8(&message).map_err(|_| Error::Message)?;
    validate_message(text)?;
    Ok(message)
}

fn run(args: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    let command = args.first().and_then(|arg| arg.to_str());
    let args = args.get(1..).unwrap_or_default();
    match (command, args) {
        (None | Some("--help" | "-h"), []) => println!("{USAGE}"),
        (Some("--version" | "-V"), []) => println!("kryptocore-msg {}", env!("CARGO_PKG_VERSION")),
        (Some("keygen"), [path]) => {
            let passphrase = prompt("New identity passphrase (at least 15 characters): ")?;
            let repeated = prompt("Repeat passphrase: ")?;
            if *passphrase != *repeated {
                return Err("Passphrases do not match.".into());
            }
            drop(repeated);
            let identity = Identity::generate()?;
            identity.save(Path::new(path), passphrase.as_bytes())?;
            eprintln!("Share only this public key:");
            print_public(&identity);
        }
        (Some("public"), [path]) => {
            let passphrase = prompt("Identity passphrase: ")?;
            print_public(&Identity::load(Path::new(path), passphrase.as_bytes())?);
        }
        (Some(action @ ("receive" | "send")), [path, peer, address]) => {
            let peer = parse_key(peer)?;
            let address: SocketAddr = address
                .to_str()
                .ok_or("Provide an IP address and port.")?
                .parse()?;
            let passphrase = prompt("Identity passphrase: ")?;
            let identity = Identity::load(Path::new(path), passphrase.as_bytes())?;
            drop(passphrase);
            if action == "receive" {
                let listener = TcpListener::bind(address)?;
                eprintln!(
                    "Waiting for the selected peer on {} ...",
                    listener.local_addr()?
                );
                let (mut stream, _) = listener.accept()?;
                drop(listener);
                receive(&mut stream, &identity, &peer, |message| {
                    let mut stdout = io::stdout().lock();
                    writeln!(stdout, "{message}")?;
                    stdout.flush()
                })?;
            } else {
                let message = read_message()?;
                let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
                send(
                    &mut stream,
                    &identity,
                    &peer,
                    std::str::from_utf8(&message)?,
                )?;
                eprintln!("The selected peer accepted the message.");
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
