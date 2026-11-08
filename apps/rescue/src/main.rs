#![forbid(unsafe_code)]

use kryptocore_rescue::{inspect, recover_with_options, CredentialRoute, RecoveryOptions};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Inspect {
        input: PathBuf,
    },
    Recover {
        input: PathBuf,
        output: PathBuf,
        credential: CredentialRoute,
        confirm_plaintext: bool,
        #[serde(default)]
        options: RecoveryOptions,
    },
}

fn request(reader: &mut impl Read) -> Result<(Request, Zeroizing<Vec<u8>>), &'static str> {
    let metadata = frame(reader, 64 * 1024)?;
    let secret = frame(reader, 1024)?;
    frame(reader, 0)?;
    let action: Request =
        serde_json::from_slice(&metadata).map_err(|_| "Invalid recovery request.")?;
    if matches!(action, Request::Inspect { .. }) && !secret.is_empty() {
        return Err("Inspection does not accept credentials.");
    }
    let mut trailing = [0];
    if reader
        .read(&mut trailing)
        .map_err(|_| "Incomplete request.")?
        != 0
    {
        return Err("Unexpected request data.");
    }
    Ok((action, secret))
}

fn frame(reader: &mut impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut length = [0; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| "Incomplete request.")?;
    let length = u32::from_le_bytes(length) as usize;
    if length > limit {
        return Err("Request exceeds the supported limit.");
    }
    // Own a zeroizing buffer before reading: partial credentials are also
    // cleared if an incomplete frame makes read_exact fail.
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "Incomplete request.")?;
    Ok(bytes)
}

fn run(action: Request, secret: &[u8]) -> Result<Value, String> {
    match action {
        Request::Inspect { input } => {
            let result = inspect(&input).map_err(|e| e.to_string())?;
            Ok(
                json!({"ok":true,"message":"Format marker inspected. Contents are not authenticated.",
                "text":serde_json::to_string(&result).expect("inspection metadata")}),
            )
        }
        Request::Recover {
            input,
            output,
            credential,
            confirm_plaintext,
            options,
        } => {
            let result = recover_with_options(
                &input,
                &output,
                credential,
                secret,
                confirm_plaintext,
                &options,
            )
            .map_err(|e| e.to_string())?;
            Ok(
                json!({"ok":true,"message":"Authenticated export completed. The output is unencrypted; the source is unchanged.",
                "text":serde_json::to_string(&result).expect("recovery summary")}),
            )
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let desktop_protocol = arguments.is_empty();
    let operation = if desktop_protocol {
        request(&mut io::stdin().lock()).map_err(str::to_owned)
    } else if arguments.len() == 2 && arguments[0] == "inspect" {
        Ok((
            Request::Inspect {
                input: PathBuf::from(&arguments[1]),
            },
            Zeroizing::new(Vec::new()),
        ))
    } else {
        Err("Usage: kryptocore-rescue inspect FILE. Recovery credentials are accepted only through the framed desktop protocol, never arguments.".into())
    };
    let reply = match operation.and_then(|(action, secret)| run(action, &secret)) {
        Ok(reply) => reply,
        Err(message) => json!({"ok":false,"message":message}),
    };
    let mut output = io::stdout().lock();
    if serde_json::to_writer(&mut output, &reply).is_err() || output.write_all(b"\n").is_err() {
        return ExitCode::FAILURE;
    }
    if !desktop_protocol && reply["ok"] == false {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(metadata: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        for part in [metadata, secret, &[]] {
            input.extend_from_slice(&(part.len() as u32).to_le_bytes());
            input.extend_from_slice(part);
        }
        input
    }
    #[test]
    fn bounded_requests_separate_credentials_from_metadata() {
        let inspect = br#"{"action":"inspect","input":"sample.kcv"}"#;
        assert!(request(&mut bytes(inspect, b"").as_slice()).is_ok());
        assert!(request(&mut bytes(inspect, b"secret").as_slice()).is_err());
        assert!(request(
            &mut bytes(br#"{"action":"decrypt","input":"sample.kcv"}"#, b"").as_slice()
        )
        .is_err());
        assert!(request(
            &mut bytes(
                br#"{"action":"inspect","input":"sample.kcv","password":"hidden"}"#,
                b""
            )
            .as_slice()
        )
        .is_err());
        assert!(request(&mut (65537_u32.to_le_bytes()).as_slice()).is_err());
        assert!(request(&mut [0_u8, 1].as_slice()).is_err());
        let mut trailing = bytes(inspect, b"");
        trailing.push(1);
        assert!(request(&mut trailing.as_slice()).is_err());
        let recover = br#"{"action":"recover","input":"sample.kcv","output":"new.json","credential":"recovery_key","confirm_plaintext":true}"#;
        assert!(request(&mut bytes(recover, b"secret").as_slice()).is_ok());
        assert!(request(&mut bytes(recover, &vec![0; 1025]).as_slice()).is_err());
        let mut incomplete = bytes(recover, b"");
        incomplete.truncate(4 + recover.len());
        incomplete.extend_from_slice(&32_u32.to_le_bytes());
        incomplete.extend_from_slice(b"partial credential");
        assert!(request(&mut incomplete.as_slice()).is_err());
    }
}
