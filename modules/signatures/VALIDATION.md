# Signatures preview validation

Date: 2026-11-07. Local Windows x64, Rust 1.99.1 (MSVC), Python 3.9,
PyNaCl 1.5.0. Component: `kryptocore-signatures 0.1.0-preview.1`.
This records local implementation checks, not an independent security audit.

## Results

| Check | Result |
| --- | --- |
| `cargo test --offline --locked --release -p kryptocore-signatures` | 10 unit tests and 3 documentation tests passed. The optional Python test is explicitly run separately. |
| `cargo test --offline --locked --release -p kryptocore-signatures --test interop -- --ignored` | Passed: Rust-to-PyNaCl and PyNaCl-to-Rust signatures for all three purposes, with distinct RFC test keys and binary message bytes. |
| `cargo test --offline --locked --release --workspace` | Passed, including Core, Container, MSG, Rescue, Vault and Firefox channel tests. Existing opt-in Python interoperability and 1 GiB Container tests remain excluded from this command. The two additional secret-key compile-fail documentation checks were subsequently run with the module suite. |
| `cargo-deny 0.19.9 --locked check --config deny.toml licenses` | `licenses ok` for the workspace. |
| `cargo-audit 0.22.2 audit --deny warnings` | Successful after fetching the RustSec advisory database; 1,422 advisories loaded, 110 lockfile dependencies scanned. An initial run lacked Cargo on PATH for index refresh; the final `--no-fetch --deny warnings` run with Cargo on PATH also passed. |
| Dependency/notice comparison | All 100 existing lockfile package versions, sources and checksums preserved. Nine registry packages plus the new workspace package added. Forty-one reachable all-target dependency entries inventoried; copied notices match cached upstream source bytes. |
| Formatting | Module Rust files formatted with rustfmt. Clippy was not run: its component is not installed in this local MSVC toolchain. |

The first sandboxed workspace run failed because existing Container/OpenSSH
tests could not access temporary files. The same unchanged tests passed when
run outside the sandbox. No production checks were weakened to make them pass.

The lockfile has two additional resolved dependency edges: curve25519-dalek
to `digest 0.10.7`, and rand_core 0.6.4 to `getrandom 0.2.17`. Existing
application dependency references gained version qualifiers where the new
graph made names ambiguous. No existing package version was upgraded.

Cargo.lock SHA-256 at review:
`bc518fc26cfdaab96c940a4a87bf474ef234506b0feab67ae5f576449a92a04a`.

## Test coverage

- Two published RFC 8032 vectors check the pinned primitive.
- An exact framing assertion and independent PyNaCl framing check the wrapper.
- Wrong keys, wrong purposes, message append/truncation, each modified message
  byte and each modified signature byte are rejected.
- Invalid lengths, all eight low-order public points, a mixed-torsion point,
  noncanonical key encodings, an S+L signature and low-order R are rejected.
- Raw Ed25519 and other framing-version signatures cannot verify as version 1.
- Empty, binary and exactly 1 MiB messages pass; larger messages are rejected
  before framing allocation. Seed import/export round-trips and OS key generation work.
- Compile-fail documentation checks prevent accidental public Debug/Clone
  support for secret signing keys. The pinned upstream key implements ZeroizeOnDrop.

## Compatibility and remaining work

Core's encryption API and all application formats, pairings, identities and
existing OpenSSH signatures are unchanged. The companion is a new workspace
member; **no application currently uses it**. No application executable or
published release was replaced as part of this change.

The CI definitions now include companion tests and the Python reference
check. No remote run or Linux/macOS execution is claimed here; those require
publishing the reviewed source and checking the resulting CI runs.

Application adoption needs an explicitly versioned manifest/envelope, encrypted
storage for dedicated signing keys, trusted-key selection, rotation/revocation
and replay policy. It must preserve the existing Container OpenSSH path.
Signing cannot certify malware absence or the identity of an unknown person.
Memory clearing is limited to owned buffers and upstream guarantees. Concurrent
request limits, UI trust decisions, key compromise and independent review
remain outside this module's test result.
