#![forbid(unsafe_code)]

use kryptocore_container::{
    check, generate_passphrase, pack, scanner::inspect, signature, unpack_signed_with_inspection,
    unpack_with_inspection, Error, Summary,
};
use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const USAGE: &str = "KryptoCore Container (alpha)

  kryptocore-container pack <out.kcc> <file-or-folder>...
  kryptocore-container check <in.kcc>
  kryptocore-container unpack <in.kcc> <new-folder> [--scan <absolute-clamscan-path>]
  kryptocore-container unpack-signed <in.kcc> <new-folder> <ssh-keygen> <allowed-signers> <principal> <signature> [--scan <absolute-clamscan-path>]
  kryptocore-container sign <in.kcc> <ssh-keygen> <private-key> <out.sig>
  kryptocore-container verify <in.kcc> <ssh-keygen> <allowed-signers> <principal> <signature>
  kryptocore-container generate-passphrase";

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

fn menu() -> Result<(), Error> {
    println!("KryptoCore Container");
    println!(
        "Relative Pfade beziehen sich auf: {}",
        std::env::current_dir()?.display()
    );
    println!("Du kannst einen Pfad eintippen oder eine Datei ins Fenster ziehen.");
    loop {
        println!("\n1  Container erstellen\n2  Container prüfen\n3  Container entpacken\n4  Passphrase erzeugen\n0  Beenden");
        let Some(choice) = ask("Auswahl: ")? else {
            return Ok(());
        };
        let result = match choice.as_str() {
            "1" => pack_from_menu(),
            "2" => open_from_menu("check"),
            "3" => open_from_menu("unpack"),
            "4" => run(&["generate-passphrase".into()]),
            "0" => return Ok(()),
            _ => {
                println!("Bitte wähle 0 bis 4.");
                continue;
            }
        };
        if let Err(error) = result {
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

fn ask_path(label: &str) -> io::Result<Option<OsString>> {
    Ok(ask(label)?.and_then(|path| {
        let path = unquote(&path);
        (!path.is_empty()).then(|| OsString::from(path))
    }))
}

fn unquote(path: &str) -> &str {
    path.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(path)
}

fn pack_from_menu() -> Result<(), Error> {
    let Some(output) = ask_path("Neue Containerdatei, z. B. paket.kcc (leer zum Abbrechen): ")?
    else {
        return Ok(());
    };
    let Some(source) = ask_path("Erste Datei oder erster Ordner (leer zum Abbrechen): ")? else {
        return Ok(());
    };
    let mut args = vec!["pack".into(), output, source];
    loop {
        match ask("Weitere Datei oder weiterer Ordner (Enter zum Fortfahren): ")? {
            Some(path) if unquote(&path).is_empty() => return run(&args),
            Some(path) => args.push(unquote(&path).into()),
            None => return Ok(()),
        }
    }
}

fn open_from_menu(command: &str) -> Result<(), Error> {
    let Some(input) = ask_path("Containerdatei (leer zum Abbrechen): ")? else {
        return Ok(());
    };
    let mut args = vec![command.into(), input];
    if command == "unpack" {
        let Some(output) = ask_path("Neuer Zielordner (leer zum Abbrechen): ")? else {
            return Ok(());
        };
        args.push(output);
    }
    run(&args)
}

fn password(prompt: &str) -> Result<Zeroizing<String>, Error> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn summary(action: &str, result: Summary) {
    println!(
        "{action}: {} entries, {} bytes.",
        result.entries, result.bytes
    );
}

fn trusted_tool(value: &OsString) -> Result<&Path, Error> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(Error::Format(
            "Provide the absolute path to a trusted executable.",
        ));
    }
    Ok(path)
}

fn verification(args: &[OsString]) -> Result<signature::Verification<'_>, Error> {
    Ok(signature::Verification {
        ssh_keygen: trusted_tool(&args[0])?,
        allowed_signers: Path::new(&args[1]),
        principal: args[2]
            .to_str()
            .filter(|name| !name.is_empty())
            .ok_or(Error::Format("Invalid signer identity."))?,
        signature: Path::new(&args[3]),
    })
}

fn scan_tool(args: &[OsString]) -> Result<Option<&Path>, Error> {
    match args {
        [] => Ok(None),
        [flag, tool] if flag == "--scan" => Ok(Some(trusted_tool(tool)?)),
        _ => Err(Error::Format(USAGE)),
    }
}

fn run(args: &[OsString]) -> Result<(), Error> {
    let command = args.first().and_then(|arg| arg.to_str());
    let args = args.get(1..).unwrap_or_default();
    match (command, args) {
        (None | Some("--help" | "-h"), []) => println!("{USAGE}"),
        (Some("--version" | "-V"), []) => {
            println!("kryptocore-container {}", env!("CARGO_PKG_VERSION"))
        }
        (Some("generate-passphrase"), []) => {
            if !std::io::stdout().is_terminal() {
                return Err(Error::Format(
                    "Display generated passphrases only in an interactive terminal.",
                ));
            }
            println!("{}", &*generate_passphrase()?);
        }
        (Some("pack"), [output, input @ ..]) if !input.is_empty() => {
            let first = password("New passphrase: ")?;
            let second = password("Repeat passphrase: ")?;
            if *first != *second {
                return Err(Error::Format("Passphrases do not match."));
            }
            drop(second);
            let sources: Vec<PathBuf> = input.iter().map(PathBuf::from).collect();
            summary(
                "Packed",
                pack(Path::new(output), &sources, first.as_bytes())?,
            );
        }
        (Some("check"), [input]) => {
            let key = password("Container passphrase: ")?;
            summary("Authenticated", check(Path::new(input), key.as_bytes())?);
        }
        (Some("sign"), [input, ssh, private, output]) => {
            signature::sign(
                trusted_tool(ssh)?,
                Path::new(private),
                Path::new(input),
                Path::new(output),
            )?;
            println!("Detached signature saved.");
        }
        (Some("verify"), [input, signer @ ..]) if signer.len() == 4 => {
            verification(signer)?.verify(Path::new(input))?;
            println!("Verified for the selected signer.");
        }
        (Some("unpack"), [input, output, options @ ..]) => {
            let scanner = scan_tool(options)?;
            let key = password("Container passphrase: ")?;
            summary(
                "Extracted",
                unpack_with_inspection(
                    Path::new(input),
                    Path::new(output),
                    key.as_bytes(),
                    |root| inspect(root, scanner),
                )?,
            );
        }
        (Some("unpack-signed"), [input, output, options @ ..]) if options.len() >= 4 => {
            let (signer, options) = options.split_at(4);
            let signer = verification(signer)?;
            let scanner = scan_tool(options)?;
            let key = password("Container passphrase: ")?;
            summary(
                "Verified and extracted",
                unpack_signed_with_inspection(
                    Path::new(input),
                    Path::new(output),
                    key.as_bytes(),
                    &signer,
                    |root| inspect(root, scanner),
                )?,
            );
        }
        _ => return Err(Error::Format(USAGE)),
    }
    Ok(())
}
