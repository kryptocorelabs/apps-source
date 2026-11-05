//! Detached OpenSSH signatures over the exact SHA-256 digest of a container.
use crate::{open_container, output_location, Error, Result};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufReader, Read, Write},
    path::Path,
    process::{Command, Stdio},
};
use tempfile::NamedTempFile;

const NAMESPACE: &str = "kryptocore-container-v1-sha256";

pub(crate) struct HashReader<R>(R, Sha256);

impl<R> HashReader<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self(reader, Sha256::new())
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.1.finalize().into()
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.0.read(buffer)?;
        self.1.update(&buffer[..count]);
        Ok(count)
    }
}

fn hash_file(input: &Path) -> Result<[u8; 32]> {
    let mut reader = HashReader::new(BufReader::new(open_container(input)?));
    io::copy(&mut reader, &mut io::sink())?;
    Ok(reader.finish())
}

fn run(command: &mut Command, digest: &[u8; 32]) -> Result<Vec<u8>> {
    use std::fmt::Write as _;
    let mut message = String::with_capacity(64);
    for byte in digest {
        write!(message, "{byte:02x}").expect("writing to a String");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let wrote = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(message.as_bytes());
    let output = child.wait_with_output()?;
    wrote?;
    if !output.status.success() {
        return Err(Error::SignatureRejected);
    }
    Ok(output.stdout)
}

/// Sign the current file bytes with a trusted, explicitly selected OpenSSH tool.
pub fn sign(ssh_keygen: &Path, private_key: &Path, input: &Path, output: &Path) -> Result<()> {
    sign_with_tool(Command::new(ssh_keygen), private_key, input, output)
}

pub fn sign_noninteractive(
    ssh_keygen: &Path,
    key: &Path,
    input: &Path,
    output: &Path,
) -> Result<()> {
    sign_with_tool(background_tool(ssh_keygen), key, input, output)
}

fn background_tool(path: &Path) -> Command {
    let mut command = Command::new(path);
    command.env("SSH_ASKPASS_REQUIRE", "never");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    command
}

fn sign_with_tool(
    mut command: Command,
    private_key: &Path,
    input: &Path,
    output: &Path,
) -> Result<()> {
    let (parent, output) = output_location(output)?;
    let digest = hash_file(input)?;
    let signature = run(
        command
            .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
            .arg(private_key),
        &digest,
    )?;
    if !signature.starts_with(b"-----BEGIN SSH SIGNATURE-----") {
        return Err(Error::SignatureRejected);
    }
    let mut staged = NamedTempFile::new_in(parent)?;
    staged.write_all(&signature)?;
    staged.as_file().sync_all()?;
    staged.persist_noclobber(output).map_err(|err| err.error)?;
    Ok(())
}

pub struct Verification<'a> {
    pub ssh_keygen: &'a Path,
    pub allowed_signers: &'a Path,
    pub principal: &'a str,
    pub signature: &'a Path,
}

impl Verification<'_> {
    pub fn verify(&self, input: &Path) -> Result<()> {
        self.verify_digest(&hash_file(input)?)
    }

    pub(crate) fn verify_digest(&self, digest: &[u8; 32]) -> Result<()> {
        run(
            background_tool(self.ssh_keygen)
                .args(["-Y", "verify", "-n", NAMESPACE, "-f"])
                .arg(self.allowed_signers)
                .arg("-I")
                .arg(self.principal)
                .arg("-s")
                .arg(self.signature),
            digest,
        )?;
        Ok(())
    }
}
