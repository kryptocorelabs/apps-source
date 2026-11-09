# Messenger threat model

This document describes the experimental preview at this source revision.
Messenger has no independent security audit. Test with synthetic data.

## Frozen scope

Stabilize one-to-one chat, invitations, contact checks and authenticated file
transfer over Tor. Keep explicit direct-IP mode and existing CLI readers for
compatibility. Changes during the freeze should fix security, correctness or
compatibility issues and preserve the existing on-disk and wire profiles
where possible. The Windows onion key sidecar changes local key storage.
New Noise patterns, offline delivery, group chat, multi-device synchronization
and a permanent message archive are outside this preview scope.

| Existing profile | Role and compatibility |
| --- | --- |
| Noise KK | Authenticated chat uses fresh ephemeral keys, pins both peer keys and requires encrypted ready confirmations in both directions. Legacy CLI text and presence keep their own contexts. |
| Noise IKpsk1 | Invitations use their own protocol context and a random 32-byte invitation secret. |
| Noise XN | Address-only requests use their own context and onion port 49426. The recipient must approve each new request. Chat and invitations use port 49424, and legacy presence uses 49425. |
| KCMI v1 | The identity file protects the private key with password-based Argon2id and authenticated encryption. |
| KCMB v1 and v2 | The legacy reader authenticates v1 and attempts an atomic migration to v2. Current writes use only v2, with a separate HKDF key for each store. Older builds cannot read migrated stores. |
| KCMO v1 | The Windows onion key sidecar uses authenticated encryption and an identity-bound HKDF subkey. It can be moved with the unlocked identity's files. |

## Assets and trust boundaries

| Threat | Protection and boundary |
| --- | --- |
| Network interception, replay or reordering | The channel authenticates ordered Noise records. Known peer keys are pinned. A first contact still requires a separate key comparison to establish a person's identity. Direct IP exposes network addresses to peers. Tor traffic correlation and denial of service remain outside scope. |
| Unwanted requests or attachments | Address-only requests are opt-in for the unlocked session. Blocking binds to a public key. A sender can create a new identity. Attachment names and sizes are bounded, and writes do not replace files. Programs, scripts, shortcuts, macro-capable Office files and mountable disk images require confirmation before saving. Authenticating a peer does not establish file safety. |
| Copied local stores | Password strength determines resistance to offline guesses against a copied identity. Keep the identity, sidecars and Tor profile in a trusted user directory. The onion key, block and contact stores have no freshness guarantee against replacement with earlier authentic copies. |
| Local process, memory or compromised peer | The app assumes the user controls the OS, local account and process environment. Plaintext appears on both endpoints. A process able to inspect either endpoint can read the active conversation and credentials. |

## Windows unlocked session lifetime

The identity passphrase stays in a WPF `SecureString` while unlocked. Locking,
changing identity or closing disposes it, stops Tor, cancels active chat and
invitation work and clears session-owned message and draft references. The UI sends
temporary encoded credential bytes to its Rust child through redirected stdin
and zeroes those buffers after transfer and on failure. Rust uses zeroizing
storage for owned secret buffers. The UI also holds managed strings for visible
messages, drafts and codes. WPF, runtime, OS, clipboard, crash-dump and swap
copies can outlive these references. The app writes no persistent chat
history. A deliberately saved attachment is plaintext on disk.

## Windows onion service key storage

The onion service key is separate from the MSG identity key. The Rust worker
unlocks the identity with its passphrase and derives a dedicated subkey from
the random identity secret using HKDF-SHA-256. The context binds the subkey to
the MSG public key. KCMO v1 stores the Tor service key with XChaCha20-Poly1305
and authenticates the format header. A damaged or foreign sidecar stops Tor
startup for that identity. Rotation requires the previously authenticated key
before it atomically replaces the record.

Messenger provides the service key to Tor over its authenticated loopback
control connection using `ADD_ONION`. Tor holds the key in memory during that
session. The Windows UI clears owned key buffers. Tor, managed strings used
for control commands, crash dumps and swap can retain copies. An attacker with
access to either process during the unlocked session may recover the key.
[Tor control specification](https://spec.torproject.org/control-spec/commands.html#add_onion)

Messenger first protects any legacy plaintext keys with Windows DPAPI for the
current user. Import attaches the previously selected address to one unlocked
identity. It reads back and verifies the new identity sidecar before retiring
the old Windows-profile key. Processes running as the same Windows user can
request decryption of remaining DPAPI keys. Earlier backups, snapshots and
deleted-file remnants may still hold plaintext.
[Microsoft DPAPI documentation](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

## Dependencies and evidence

Snow implements the Noise profiles. Tor provides the onion route and local SOCKS
endpoint through `IOnionTransport` and `OnionTransport`. Replacing either
requires compatibility and failure-path tests for the existing profiles.
Direct IP is explicit. A failed onion route does not silently fall back to a
direct connection. KryptoCore protects local stores and invitation codes, and
key generation uses OS randomness.

Rust tests exercise unknown peer keys, missing ready confirmations, tampered,
reordered and truncated frames, and identity-bound store migration. Windows
tests cover connection indication, cancellation, locking and attachment
decisions. The offline packaged Tor check covers independent identity addresses,
restart, rotation, explicit legacy import and rejection of damaged or foreign keys.
It also checks restoration from both encrypted files and resuming an interrupted
import with the same identity.
Report suspected vulnerabilities through the [security policy](../../SECURITY.md).

[Noise specification](https://noiseprotocol.org/noise.html) ·
[Tor onion services](https://community.torproject.org/onion-services/overview/)
