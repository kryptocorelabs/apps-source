# Rescue threat model

This document describes Rescue at this source revision. For the exact format
readers available in a public download, check the release notes. Work on copies
of originals and use a trusted OS and local source and destination directories.

| Threat | Protection and boundary |
| --- | --- |
| Forged markers or damaged encrypted data | Inspection recognizes a format and checks bounds. Recovery authenticates through the selected format reader and needs its matching password or recovery key. Missing credentials or failed authentication stop recovery. |
| Older authentic snapshots | A successful check establishes that the file decrypts and parses with those credentials. Rescue accepts authentic backups at older revisions and does not establish which backup is current. |
| Malicious executable wrapper or archive paths | Rescue treats embedded KCC as data and leaves the EXE unlaunched. The stream reader checks paths, links, collisions and bounds. The destination is new and the app reserves it only after the requested checks. |
| Plaintext output or interrupted publication | Recovery requires explicit confirmation before writing plaintext. It cleans up owned staging files on ordinary errors. A crash or interruption can leave staging data, and authenticated multi-root exports may be partially published. Filesystem journals and backups may retain data. |
| Compromised OS or a local race | Input leaves and output ancestors reject links and reparse points. This assumes the operator controls both folders. Rescue cannot create an immutable snapshot of a file being replaced concurrently. |

## Credential lifetime

The WPF UI clears the password field after use or a source change. It passes
credentials to the Rust child in separate stdin frames and clears owned byte
buffers after transfer. Rust uses zeroizing storage for the credential and
authenticated plaintext. Reply messages contain counts and status instead of
plaintext records or private keys. Managed copies, OS buffers, swap and dumps
can outlive app references. A process controlling the local session can inspect
an active recovery.

Optional sender verification requires a separately trusted public key.
Optional malware scanning runs on authenticated staged content. Both checks
have their own trust boundaries. Rescue has no independent security audit.

[Architecture and protocol](ARCHITECTURE.md) · [Sender signatures](SIGNATURES.md) ·
[Malware scan limits](MALWARE-PROTECTION.md) · [Security policy](../../SECURITY.md)
