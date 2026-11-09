# KryptoCore Rescue

Offline file inspection and authenticated recovery exports. Built on the
open-source [KryptoCore](https://github.com/kryptocorelabs/kryptocore) library.

**Preview 0.1.0-preview.3.** Use working copies and retain independent backups.
The Windows executable is unsigned and has not received an independent audit.

Testing to date has been carried out by the KryptoCoreLabs maintainers, locally
and through automated CI. No independent security audit has been completed.
We welcome community testing, code reviews and scrutiny of our security
assumptions. Please use synthetic data and report suspected vulnerabilities
privately through the project's security-reporting channel.

[Security in 30 seconds](https://github.com/kryptocorelabs/kryptocore/blob/main/SECURITY-IN-BRIEF.md) · [Rescue-first guide](https://github.com/kryptocorelabs/kryptocore/blob/main/RESCUE-FIRST.md) · [Verify a download](https://github.com/kryptocorelabs/kryptocore/blob/main/VERIFY-DOWNLOADS.md)

## What works

| File | Available operation | Required access |
| --- | --- | --- |
| Vault KCV1 | Authenticate and export login records as a new JSON file. | Vault password. |
| Vault KCV2 | Same export, using either existing access slot. | Vault password or previously configured recovery key. |
| Vault KCV3 (unreleased) | Same read-only export; no claim that a backup is current. Published preview.3 lacks this reader. | Password or matching recovery key. |
| Vault KCV4 (development) | Authenticate, check or export through the same shared format crate as Vault. | Password or matching recovery key. |
| Container KCC v1 | Authenticate the complete archive and extract into a new folder. | Container passphrase. |
| Embedded KCC in an EXE | Read the payload as data and extract into a new folder. The EXE is never launched. | Container passphrase. |
| MSG identity/sidecar | Recognize the marker and size bounds only. | Authenticated MSG recovery is not implemented. |

A recognized marker is not authentication. Successful recovery verifies the
encrypted contents with the selected format reader. It does not verify a
human identity or make files safe to execute. Optional shared sender-signature
checks and local ClamAV scanning are separate choices; OpenSSH verification
is still handled by Container. Unknown formats and unsupported versions are rejected.

In current source builds, choose **Vault-Sicherung prüfen** after selecting a
Vault backup and entering its password or configured recovery key. Rescue
authenticates and parses the backup in memory, then shows the readable entry
count. This check creates no plaintext file and accepts authentic older copies.

## Windows quick start

1. Download and extract the [preview ZIP](https://github.com/kryptocorelabs/rescue/releases/tag/v0.1.0-preview.3).
2. Run **KryptoCore-Rescue.exe**. No separate Python or .NET installation is needed.
3. Choose **Datei auswählen …** and check the recognized format.
4. Select **Passwort** or **Wiederherstellungsschlüssel** where supported and enter the existing credential.
5. Choose **Speicherort wählen …**, confirm the plaintext warning and select **Entschlüsseln und exportieren**.

Vault exports contain plaintext website, username and password records.
Container exports contain plaintext files. Choose a protected local folder,
avoid shared/cloud-synced locations unless intended, and protect or remove
exports when finished. Existing files/folders are not overwritten. Sources
are opened read-only; no password reset, migration or repair is performed.

Recovery cannot repair missing ciphertext or bypass authentication. A recovery
key works only if that access was configured in the file already. MSG session
messages are not persisted by the current Messenger and cannot be recovered here.

**Diagnosebericht speichern …** saves marker metadata only, with no file paths,
passwords, decrypted records or ciphertext. It deliberately retains the
`not_verified` inspection status even when a separate export later succeeds.

See [architecture and limits](ARCHITECTURE.md), [security](SECURITY.md),
[release notes](RELEASE_NOTES.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
This repository hosts public documentation and downloads; application source
is open under MIT in the application workspace. KryptoCore and its optional
[signature companion](https://github.com/kryptocorelabs/kryptocore/tree/main/modules/signatures)
remain open source. Rescue uses the signature companion through the shared KCC reader.

## Sender and malware checks

Under **Absender & Malware-Prüfung**, choose a `.kcsig` and independently
confirm the expected `KCP1:` public code. Keys/signatures are created in
Container. Only Container inputs support this sender protocol; Vault
records retain their existing password/recovery authentication.

A trusted local ClamAV executable can scan authenticated plaintext before
output is published, including Vault JSON. Detection, errors, missing tools
or exceeded bounds block output. Keep its database current. The adapter
is tested with controlled scanner processes; real ClamAV detection quality
is not measured by those tests. See [signature protocol](SIGNATURES.md) and
[malware limits](MALWARE-PROTECTION.md). No file is automatically executed.


## Shared application appearance

The current development interface follows the Messenger design: a consistent
dark palette, mint focus accents, rounded cards and compact product branding.
Windows apps share their frame and controls; Vault keeps its compact Qt layout.
These interface changes do not replace released assets or change encrypted
formats. See the design review build notes for the exact build and test scope.
