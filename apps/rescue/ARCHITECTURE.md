# Rescue architecture and limits

## Implemented in 0.1.0-preview.3

An independent WPF Windows client embeds an offline Rust worker. It starts
no main application, Tor process, account service or browser pairing.
The worker recognizes formats from contents rather than extensions.

Vault and Rescue share `modules/vault-format`: the existing KCV1/KCV2
implementation and login schema were extracted without changing their
cryptographic profile or on-disk bytes. `open_with_recovery` is a read-only
slot-1 entry point; Rescue never calls the password-reset writer.
Decrypted records must match the existing deny-unknown-fields Login schema.

Vault JSON is written to a temporary file in the chosen trusted parent,
flushed, then published with `persist_noclobber`. Container recovery reuses
the application's existing authenticated stream reader and staged extractor,
including final-tag, path, collision, link and resource-limit checks.
Executable containers are bounded payload wrappers, never launched programs.
The optional KCCS v1 sender check uses the shared signature companion and
hashes the exact stream being decrypted. The independent ClamAV scan runs
only after content/signature authentication and before publication.
A selected KCC scan bounds plaintext to 400 MiB before oversized entries
are written. Vault scans run on the authenticated staged JSON.
See SIGNATURES.md and MALWARE-PROTECTION.md for complete boundaries.

Input leaves and output ancestors reject links/reparse points. This is not
an immutable snapshot or protection against a hostile local operating system.
Work from a stable copy and keep both source and destination under your control.
In-process failure paths clean up owned staging files. Forced termination,
power loss or cleanup failure may leave plaintext staging data in the chosen
parent; inspect that location after a failed operation. Secure erasure is not
guaranteed. Do not use an attacker-controlled/shared output parent.

## Credential boundary

Passwords are taken from a PasswordBox and sent through the private worker
stdin pipe, separately from JSON and process arguments. Rust owns the input
in Zeroizing storage and the format reader returns zeroizing plaintext.
The UI clears its input immediately after use or a source change. It does not
cache the credential or return plaintext records/private keys in diagnostics.
Registers, system copies, swap, dumps and compromised endpoints remain limits.

At most one UI operation runs at a time. Export is not offered as a cancellable
operation because force-killing a worker can prevent its staging cleanup.
Closing the window during an operation is blocked by the existing shell.
The current Vault bound is 4 MiB; Container retains its existing streamed
limits (up to 10,000 entries and 1 TiB plaintext). Disk capacity must suffice.

## Protocol

CLI: `kryptocore-rescue inspect FILE`; no credential arguments.
Desktop stdin: three u32 little-endian length-prefixed frames, then EOF.
Frame 1 contains request JSON (at most 64 KiB). Frame 2 is the credential
(at most 1,024 bytes); frame 3 must be empty. Inspection rejects credentials.
Unknown fields/actions, trailing bytes, invalid lengths and incomplete frames
are rejected. A recovery request must explicitly confirm plaintext output:

```json
{"action":"recover","input":"copy.kcv","output":"new-export.json","credential":"recovery_key","confirm_plaintext":true}
```

No credential belongs in that JSON. One reply reports success/failure and,
on recovery success, authenticated format, entry/byte counts and separate
signature/malware-scan states. Optional `options` contains `signature`,
`expected_public` and `scanner`; absent options retain the previous behavior.
Requested incomplete or failed protection options are never silently ignored.
Errors use fixed messages rather than echoing paths or input data.

## Remaining work

MSG identity/sidecar recovery requires read-only APIs with the existing
identity binding and explicit store domain. The current ContactBook reader
creates a lock file and is not called next to original evidence. Permanent
MSG message history does not exist today. These features remain unimplemented.
Compatibility with actual file versions must remain fixture-tested.
Independent audit, Windows code signing and manual tests on additional
machines are still required before broader production recommendations.
