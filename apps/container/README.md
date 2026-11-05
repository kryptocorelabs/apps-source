# KryptoCore Container

Container packages files and folders into a portable, read-only encrypted
archive. It runs offline. The recipient needs the app and the passphrase.
This is an alpha for testing with copies; keep the originals.

The Windows app source is in [`windows/`](windows/). Build it with
`./apps/container/build-windows.ps1` from the workspace root. See the
[desktop build instructions](../desktop/README.md) for prerequisites.

In Windows Explorer, right-click a `.kcc` file and choose **Open with**.
Select the portable `KryptoCore-Container.exe` and choose **Always** to
open future containers with a double-click. Enter the passphrase and press
Enter to extract into the suggested folder. You can change the destination
before extracting. You can also drop a `.kcc` file onto the executable.

To send a single file that opens itself, select **Selbstöffnende Windows-EXE**
before saving. The export includes the portable Windows x64 opener and the
encrypted KCC payload. The recipient double-clicks the EXE, enters the
passphrase and chooses where to extract. Share the passphrase separately.
The generated EXE is unsigned. Open an executable only if you trust its
source. Windows or a file-sharing service may restrict executable files.

After saving, choose **Prüfsumme kopieren** to copy the SHA-256 digest of the
complete file. Share the digest through a separate, trusted channel. The
recipient can compare it in PowerShell before opening the file.

```powershell
(Get-FileHash -LiteralPath '.\Delivery.exe' -Algorithm SHA256).Hash
```

Compare every character and open the file only if the digests match. A
digest sent alongside a file over the same untrusted channel can be replaced
with it. The encrypted KCC payload is authenticated during extraction.

The following examples use the command-line app.

```powershell
cargo build --locked --release -p kryptocore-container
$kcc = ".\target\release\kryptocore-container.exe"
& $kcc generate-passphrase
& $kcc pack transfer.kcc .\documents .\report.pdf
& $kcc check transfer.kcc
& $kcc unpack transfer.kcc .\received
```

On Linux and macOS use `./target/release/kryptocore-container`. The CLI asks
for passphrases without echoing them. Send a generated passphrase through a
separate trusted channel. Anyone with it can read or recreate a container;
there is no passphrase recovery. Avoid screen sharing or persistent terminal
logs when generating a passphrase.

### Verify the sender

Use a dedicated Ed25519 signing key with OpenSSH. The recipient adds the
sender's public key to their local `allowed_signers` file only after checking
its fingerprint through a trusted channel. A line starts with the chosen
identity, such as `alice`, followed by the contents of Alice's SSH public key.
Send the detached signature beside the container. Keep the private signing key
with the sender. See the [OpenSSH signature commands](https://man.openbsd.org/ssh-keygen.1).

```powershell
$ssh = (Get-Command ssh-keygen).Source
& $kcc sign transfer.kcc $ssh .\alice-signing-key transfer.sig
& $kcc verify transfer.kcc $ssh .\allowed_signers alice transfer.sig
& $kcc unpack-signed transfer.kcc .\received $ssh .\allowed_signers alice transfer.sig
```

`unpack-signed` verifies the exact bytes it decrypted before making the
destination available. Use it whenever sender authentication is required.
`check` authenticates the passphrase-protected contents; it does not identify
the sender. Signatures do not prove files are safe to open.

### Scan before extraction

Append `--scan <absolute path to clamscan>` to either unpack command to
inspect the authenticated files in staging before publishing them. Install
[ClamAV](https://docs.clamav.net/manual/Usage/Scanning.html) separately and keep
its signatures current. The option blocks publication on a scanner failure,
detection, timeout or a top-level file larger than 100 MiB. It does not run
or open extracted files. A clean scan is only a result from the scanner, not
a guarantee; support and detection vary by file type. The scanner is optional
and an alpha release must not advertise it as verified on a platform where
it has not been tested with a real ClamAV installation.

### Limits

Use private local folders you control for inputs and output. The output must
not already exist. Pack does not change its inputs. Keep source files stable
until packing finishes; this is not a filesystem snapshot. Extracted files
are ordinary plaintext. On Windows their access rules come from the chosen
parent directory. A crash, backup or filesystem journal can retain temporary
plaintext; removing a temporary directory is not secure erasure.

The format supports up to 1 TiB of plaintext and 10,000 entries, with fixed
memory per data chunk. This is a format limit, not a performance claim. Names
are encrypted; file structure and sizes can be inferred from frame sizes.
See [format and security boundaries](FORMAT.md).
