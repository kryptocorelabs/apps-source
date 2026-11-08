# KryptoCore Signatures

Optional Rust companion crate, `0.1.0-preview.1`. MIT licensed. The encryption
Core does not depend on this crate. Container and Rescue use this API through
the application-owned [KCC signature protocol](https://github.com/kryptocorelabs/container/blob/main/SIGNATURES.md).
Existing Vault files, MSG identities/pairings and Container OpenSSH signatures
retain their existing formats and verification paths.

This module signs application-defined bytes and verifies them against an
**expected public key**. It uses pure Ed25519 through `ed25519-dalek = 2.2.0`
with `std` and `zeroize`, without default features. The pinned 2.x implementation
reuses the workspace's curve25519-dalek 4.x and SHA-2 0.10 dependencies. Changes
to that pin require dependency, strict-validation and interoperability review.
This is a preview API, not an independently audited component or a new file format.

## Use

```rust
use kryptocore_signatures::{verify, Error, Purpose, SigningKey};

fn example() -> Result<(), Error> {
    let signer = SigningKey::generate()?;
    let expected = signer.verification_key(); // retain through a trusted route
    let signature = signer.sign(Purpose::ContainerManifest, b"canonical manifest")?;
    verify(&expected, Purpose::ContainerManifest, b"canonical manifest", &signature)
}
```

Applications opt in with a workspace path dependency or a Git dependency pinned
to a reviewed full commit from `kryptocorelabs/kryptocore` (package
`kryptocore-signatures`). Publication on crates.io is disabled.
Callers own serialization, signer trust, key storage, rotation,
revocation and recovery. Do not generate a new key on every application start if
the application needs a persistent identity. Store a dedicated signing seed in
an authenticated, encrypted key store and explicitly protect exported copies.
Never reuse a password, a Core encryption key or an MSG X25519 identity as a seed.

## Signed bytes: protocol version 1

Ed25519 signs this exact concatenation (no implicit text encoding or JSON):

| Field | Bytes |
| --- | --- |
| Domain and protocol version | ASCII `KryptoCore/signatures`, followed by `00 01` |
| Purpose length | unsigned 16-bit big-endian byte length |
| Purpose | one exact ASCII label below |
| Message length | unsigned 64-bit big-endian byte length |
| Message | exact application bytes, from zero to 1,048,576 bytes |

Purposes: `container-manifest/v1`, `release-manifest/v1`, `contact-binding/v1`.
The typed API selects the label; there is no raw signing entry point. Purpose
and version changes require an explicit protocol decision, new tests and
application migration. Public keys are 32 bytes; detached signatures are 64 bytes.
These bytes are **not** OpenSSH signatures, Ed25519ctx or Ed25519ph. No new
container envelope, certificate or trust store is defined here.

For large files, a future application manifest must explicitly bind a defined
hash algorithm, exact file digest/length, format version and relevant metadata.
Do not silently pass an unspecified digest in place of the intended message.
Canonical serialization belongs to that manifest protocol. Release/contact
authorizations also need an application-defined audience, identifier and
freshness/replay policy. A valid old signature remains valid cryptographically.

## Validation and memory boundaries

Imported public keys must use a canonical point encoding, be non-identity and
belong to the prime-order subgroup. Verification uses `verify_strict`, rejecting
noncanonical signature scalars and low-order points. Parsing a 64-byte signature
does not mean it is valid. All verification failures return fixed messages
without including key material or message contents.

Signing keys have no public `Debug`, `Clone`, serialization trait or conversion
from encryption keys. The upstream key has zeroize-on-drop enabled; temporary
seed and framed-message buffers use `Zeroizing`. Explicit seed import/export
uses `Zeroizing<[u8; 32]>`. This reduces lingering copies in owned buffers; it
does not guarantee erasure of registers, allocator/system copies, caller data,
swap, crash dumps or memory read by a compromised process/operating system.
The crate performs no file/network I/O and does not log secrets.

The message limit bounds each operation's framing allocation. Applications
must still bound concurrent requests and rate-limit untrusted verification.
A valid signature does not encrypt data, identify a human, prevent replay,
prove a program is uncompromised, or establish that a file is malware-free.

## Tests

```sh
cargo test --locked --release -p kryptocore-signatures
# Requires the project's Python test dependencies (including PyNaCl):
cargo test --locked --release -p kryptocore-signatures --test interop -- --ignored
```

The suite includes two published RFC 8032 primitive vectors, exact framing,
all purposes, binary/empty/boundary-size messages, wrong keys/purposes,
every byte position in a modified message/signature, malformed lengths,
low-order and mixed-torsion keys, noncanonical key/scalar encodings, raw versus
framed signatures, and protocol-version substitution. The explicit Python
test independently constructs the framing: PyNaCl verifies Rust signatures,
then Rust verifies a PyNaCl signature from a different public test key.
The existing CI matrix runs unit tests and adds that reference check to its
Python jobs. Remote results require a push and successful CI runs.

See [local validation](VALIDATION.md), [third-party notices](THIRD_PARTY_NOTICES.md)
and the workspace's [verification boundaries](../../VERIFICATION.md).

References: [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032),
[ed25519-dalek 2.2.0 validation API](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html).
