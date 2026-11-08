#![forbid(unsafe_code)]
use kryptocore_verify::{
    check, describe, keys, parse_public, public_code, publish, read_bounded, sign, Expected,
    ReleaseManifest,
};
use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const HELP: &str = "KryptoCore Verify 0.1.0-preview.1 (offline)\n\
check FILE MANIFEST SIGNATURE --key KCP1:HEX --product NAME --version VERSION --target PLATFORM [--min-sequence N]\n\
keygen ENCRYPTED_KEY_FILE\n\
sign FILE MANIFEST SIGNATURE --key-file ENCRYPTED_KEY_FILE --product NAME --version VERSION --target PLATFORM --sequence N --source COMMIT --expires UNIX_SECONDS\n\
Obtain the expected public key independently. Verification never executes the download.\n\
No official release key is bundled yet. Authenticode/notarization, malware safety,\n\
key revocation and automatic update protection are separate concerns.";

fn run() -> Result<(), &'static str> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next().unwrap_or_else(|| "--help".into());
    if command == "--help" || command == "-h" {
        println!("{HELP}");
        return Ok(());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Invalid system clock")?
        .as_secs();
    let mut positional = Vec::new();
    let mut options: HashMap<String, OsString> = HashMap::new();
    while let Some(arg) = args.next() {
        if arg.to_str().is_some_and(|s| s.starts_with("--")) {
            let flag = arg.into_string().map_err(|_| "Invalid option")?;
            let value = args.next().ok_or("Missing option value")?;
            if options.insert(flag, value).is_some() {
                return Err("Duplicate option");
            }
        } else {
            positional.push(PathBuf::from(arg));
        }
    }
    let mut option = |name: &str| options.remove(name).ok_or("Missing required option");
    if command == "keygen" && positional.len() == 1 {
        if !options.is_empty() {
            return Err("Unexpected option");
        }
        let password = Zeroizing::new(
            rpassword::prompt_password("New release-key password: ")
                .map_err(|_| "Password entry failed")?,
        );
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Repeat password: ").map_err(|_| "Password entry failed")?,
        );
        if *password != *confirm {
            return Err("Passwords do not match");
        }
        let key = keys::generate(&positional[0], password.as_bytes())?;
        println!(
            "Dedicated encrypted release key created. Public key:\n{}",
            public_code(key.verification_key())
        );
        return Ok(());
    }
    if positional.len() != 3 {
        return Err(HELP);
    }
    let text = |value: OsString| value.into_string().map_err(|_| "Option must be UTF-8");
    let product = text(option("--product")?)?;
    let version = text(option("--version")?)?;
    let target = text(option("--target")?)?;
    match command.to_str() {
        Some("check") => {
            let key = parse_public(&text(option("--key")?)?)?;
            let min_sequence = match options.remove("--min-sequence") {
                Some(v) => text(v)?.parse().map_err(|_| "Invalid minimum sequence")?,
                None => 1,
            };
            if !options.is_empty() {
                return Err("Unexpected option");
            }
            let expected = Expected {
                product: &product,
                version: &version,
                target: &target,
                min_sequence,
                now,
            };
            let bytes = read_bounded(&positional[1], kryptocore_verify::MAX_MANIFEST)?;
            let signature = read_bounded(&positional[2], 64)?;
            let manifest = check(&bytes, &signature, &key, &expected, &positional[0])?;
            println!("VERIFIED: {} {} · {} · sequence {}\nPublisher key: {}\nSignature, filename, platform, size and SHA-256 match. Download was not executed.", manifest.product, manifest.version, target, manifest.sequence, public_code(key));
        }
        Some("sign") => {
            let key_path = PathBuf::from(option("--key-file")?);
            let sequence = text(option("--sequence")?)?
                .parse()
                .map_err(|_| "Invalid release sequence")?;
            let source_commit = text(option("--source")?)?;
            let expires_at = text(option("--expires")?)?
                .parse()
                .map_err(|_| "Invalid expiry")?;
            if !options.is_empty() {
                return Err("Unexpected option");
            }
            if expires_at <= now {
                return Err("Expiry must be in the future");
            }
            for path in [&positional[1], &positional[2]] {
                if path.exists() {
                    return Err("Manifest/signature output already exists");
                }
                if same_file(path, &positional[0]) || same_file(path, &key_path) {
                    return Err("Output conflicts with input");
                }
            }
            if positional[1] == positional[2] {
                return Err("Manifest and signature need different output paths");
            }
            let artifact = describe(&positional[0], &target)?;
            let manifest = ReleaseManifest {
                schema: "kryptocore-release/v1".into(),
                product,
                version,
                sequence,
                issued_at: now,
                expires_at,
                source_commit,
                artifacts: vec![artifact],
            };
            manifest.validate()?;
            let password = Zeroizing::new(
                rpassword::prompt_password("Release-key password: ")
                    .map_err(|_| "Password entry failed")?,
            );
            let key = keys::open(&key_path, password.as_bytes())?;
            let (bytes, signature) = sign(&manifest, &key)?;
            publish(&positional[1], &bytes)?;
            publish(&positional[2], &signature)?;
            println!(
                "Release manifest and detached signature written. Publisher key: {}",
                public_code(key.verification_key())
            );
        }
        _ => return Err(HELP),
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    a == b
        || a.canonicalize()
            .ok()
            .zip(b.canonicalize().ok())
            .is_some_and(|(a, b)| a == b)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NOT VERIFIED: {error}");
            ExitCode::FAILURE
        }
    }
}
