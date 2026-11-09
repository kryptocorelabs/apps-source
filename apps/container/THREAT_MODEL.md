# Container threat model

This document describes KCC v1 and its optional executable wrapper at this
source revision. Container is an alpha without an independent security audit.

| Threat | Protection and boundary |
| --- | --- |
| Copied archive and offline guessing | Password-based key wrapping uses the fixed Argon2id profile. Passphrase entropy limits guessing resistance. The archive leaks information about frame sizes. |
| Manipulation, truncation or reordered frames | The stream authenticates frame metadata and position, requires an authenticated final frame and rejects trailing bytes. |
| Malicious entry paths | The reader rejects traversal, links, device names, case-folded duplicates and missing parents. Use local input and output directories you control. A source tree can change while packing. |
| Forged sender or unexpected file contents | The password authenticates contents. Sender verification needs a separate trusted public key. The optional scan gates extraction on its result. Authentication and a clean scan cannot establish that an extracted file is safe to run. |
| Resource exhaustion | The format bounds metadata, entries and chunk sizes. Sufficient disk and CPU remain necessary for large valid archives or concurrent operations. |

Extraction uses private staging and a new destination. Requested signature
verification and inspection must succeed before publication. Publishing several
authenticated roots uses several moves, so a crash can leave part of an
authenticated export. Extracted and staged files are plaintext. The filesystem,
backups or journals can retain copies after cleanup.

The WPF UI sends passwords to its Rust worker using redirected stdin and
clears owned byte buffers after sending. Generated passphrases appear as managed
strings in the dialog and can enter the clipboard. The OS, runtime and any
process able to inspect the user session remain trusted. Managed and OS copies
can remain after the UI clears its own references.

## Self-extracting EXE

Use `.kcc` with a trusted opener for normal transfers. The advanced Windows
EXE export appends encrypted data to an executable and runs that opener before
asking for a passphrase. Verify the complete EXE against a separately trusted
signature or digest before running it in a controlled workflow. Rescue can
inspect and extract the embedded KCC as data.

[File format](FORMAT.md) · [Sender signatures](SIGNATURES.md) ·
[Malware scan limits](MALWARE-PROTECTION.md) · [Security policy](../../SECURITY.md)
