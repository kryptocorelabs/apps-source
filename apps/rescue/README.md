# KryptoCore Rescue

Offline file inspection and authenticated recovery exports. Built on the
open-source [KryptoCore](https://github.com/kryptocorelabs/kryptocore) library.

**Preview 0.1.0-preview.2.** Use working copies and retain independent backups.
The Windows executable is unsigned and has not received an independent audit.

## What works

| File | Available operation | Required access |
| --- | --- | --- |
| Vault KCV1 | Authenticate and export login records as a new JSON file. | Vault password. |
| Vault KCV2 | Same export, using either existing access slot. | Vault password or previously configured recovery key. |
| Container KCC v1 | Authenticate the complete archive and extract into a new folder. | Container passphrase. |
| Embedded KCC in an EXE | Read the payload as data and extract into a new folder. The EXE is never launched. | Container passphrase. |
| MSG identity/sidecar | Recognize the marker and size bounds only. | Authenticated MSG recovery is not implemented. |

A recognized marker is not authentication. Successful recovery verifies the
encrypted contents with the selected format reader. It does not verify a
human sender, check an OpenSSH signature, scan for malware or make files safe
to execute. Unknown formats and unsupported versions are rejected.

## Windows quick start

1. Download and extract the [preview ZIP](https://github.com/kryptocorelabs/rescue/releases/tag/v0.1.0-preview.2).
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
is maintained in the private application workspace. KryptoCore and its optional
[signature companion](https://github.com/kryptocorelabs/kryptocore/tree/main/modules/signatures)
remain open source. This app does not yet use the signature companion.
