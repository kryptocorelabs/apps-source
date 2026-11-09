# Messenger threat model

This document describes the experimental preview at this source revision.
Messenger has no independent security audit. Test with synthetic data.

## Frozen scope

Stabilize one-to-one chat, invitations, contact checks and authenticated file
transfer over Tor. Keep explicit direct-IP mode and existing CLI readers for
compatibility. Changes during the freeze should fix security, correctness or
compatibility issues and preserve the existing on-disk and wire profiles
where possible. New Noise patterns, identity or sidecar versions, offline
delivery, group chat, multi-device synchronization and a permanent message
archive are outside this preview scope.

| Existing profile | Role and compatibility |
| --- | --- |
| Noise KK | Authenticated chat uses fresh ephemeral keys, pins both peer keys and requires encrypted ready confirmations in both directions. Legacy CLI text and presence keep their own contexts. |
| Noise IKpsk1 | Invitations use their own protocol context and a random 32-byte invitation secret. |
| Noise XN | Address-only requests use their own context and onion port 49426. The recipient must approve each new request. Chat and invitations use port 49424, and legacy presence uses 49425. |
| KCMI v1 | The identity file protects the private key with password-based Argon2id and authenticated encryption. |
| KCMB v1 and v2 | The legacy reader authenticates v1 and attempts an atomic migration to v2. Current writes use only v2, with a separate HKDF key for each store. Older builds cannot read migrated stores. |

## Assets and trust boundaries

| Threat | Protection and boundary |
| --- | --- |
| Network interception, replay or reordering | The channel authenticates ordered Noise records. Known peer keys are pinned. A first contact still requires a separate key comparison to establish a person's identity. Direct IP exposes network addresses to peers. Tor traffic correlation and denial of service remain outside scope. |
| Unwanted requests or attachments | Address-only requests are opt-in for the unlocked session. Blocking binds to a public key. A sender can create a new identity. Attachment names and sizes are bounded, and writes do not replace files. Programs, scripts, shortcuts, macro-capable Office files and mountable disk images require confirmation before saving. Authenticating a peer does not establish file safety. |
| Copied local stores | Password strength determines resistance to offline guesses against a copied identity. Keep the identity, sidecars and Tor profile in a trusted user directory. The block and contact stores have no freshness guarantee against replacement with earlier authentic copies. |
| Local process, memory or compromised peer | The app assumes the user controls the OS, local account and process environment. Plaintext appears on both endpoints. A process able to inspect either endpoint can read the active conversation and credentials. |

## Windows unlocked session lifetime

The identity passphrase stays in a WPF `SecureString` while unlocked. Locking,
changing identity or closing disposes it, cancels active chat and invitation
work and clears session-owned message and draft references. The UI sends
temporary encoded credential bytes to its Rust child through redirected stdin
and zeroes those buffers after transfer and on failure. Rust uses zeroizing
storage for owned secret buffers. The UI also holds managed strings for visible
messages, drafts and codes. WPF, runtime, OS, clipboard, crash-dump and swap
copies can outlive these references. The app writes no persistent chat
history. A deliberately saved attachment is plaintext on disk.

## Windows onion service key storage

The onion service key is separate from the MSG identity key. Messenger uses
DPAPI with the current Windows user scope to protect the service key at rest.
It provides the key to Tor over the authenticated loopback control connection
using `ADD_ONION`. Tor holds the service key in memory for that session.
The public onion address and the service selection file can remain readable.
[Microsoft DPAPI documentation](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) ·
[Tor control specification](https://spec.torproject.org/control-spec/commands.html#add_onion)

Migration stores and verifies the protected copy before removing a legacy
plaintext key. A damaged protected copy stops startup for that address. Backups,
snapshots and deleted-file remnants may still hold earlier plaintext copies.
DPAPI raises the bar for someone who obtains only the key file. Processes
running as the same Windows user can request decryption. Privileged attackers,
memory inspection and restoring older valid profile data remain within the
existing local trust boundary.

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
decisions. The offline packaged Tor check covers fresh protected keys,
restart, rotation, legacy migration and rejection of a damaged key.
Report suspected vulnerabilities through the [security policy](../../SECURITY.md).

[Noise specification](https://noiseprotocol.org/noise.html) ·
[Tor onion services](https://community.torproject.org/onion-services/overview/)
