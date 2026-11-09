# KryptoCore Verify

Offline release-manifest verifier, `0.1.0-preview.1`. A small native Rust tool for
Windows, Linux and macOS. First-party code is MIT licensed. Testing so far is by
KryptoCoreLabs maintainers and CI; independent review and community testing are
welcome. There has been no independent security audit.

Verify uses the project's optional signature module with
`Purpose::ReleaseManifest`. It authenticates the exact manifest bytes against
an independently trusted Ed25519 public key, then checks the selected download's
filename, platform, byte length and SHA-256. Expected product and version are
explicit inputs. It never executes the file, extracts archives, follows download
URLs or imports a publisher key from the manifest.

[Security in 30 seconds](https://github.com/kryptocorelabs/kryptocore/blob/main/SECURITY-IN-BRIEF.md) · [Rescue-first guide](https://github.com/kryptocorelabs/kryptocore/blob/main/RESCUE-FIRST.md) · [Verify a download](https://github.com/kryptocorelabs/kryptocore/blob/main/VERIFY-DOWNLOADS.md)

## Build and check

```sh
cargo build --locked --release -p kryptocore-verify
cargo test --locked --release -p kryptocore-verify -- --test-threads=1

kryptocore-verify check KryptoCore-Vault.zip release.json release.sig \
  --key KCP1:YOUR_INDEPENDENTLY_VERIFIED_PUBLIC_KEY \
  --product vault --version YOUR_EXPECTED_VERSION --target windows-x86_64
```

`--help` lists all commands. On Windows use `kryptocore-verify.exe`.
Success exits with 0 and prints `VERIFIED`; a rejected check exits with 1 and
prints `NOT VERIFIED`. The public key is mandatory. A key downloaded beside a
possibly substituted executable does not establish trust. The verifier itself
also needs a trusted distribution/bootstrap route.

KryptoCoreLabs publishes its [release verification key](https://github.com/kryptocorelabs/kryptocore/blob/main/PUBLIC_RELEASE_KEY.txt).
Use the release's matching detached manifest and signature and confirm the key
through a trusted route. The [download guide](https://github.com/kryptocorelabs/kryptocore/blob/main/VERIFY-DOWNLOADS.md)
covers available checks and the trust limits of older archives.

## Maintainer signing

Generate a **dedicated release key locally**; passwords are entered at the hidden
terminal prompt, never in command arguments or Git. Keep the private `.kcsk` file
offline with an independently protected backup. Do not reuse container or MSG keys.

```sh
kryptocore-verify keygen release-key.kcsk
kryptocore-verify sign KryptoCore-Vault.zip release.json release.sig \
  --key-file release-key.kcsk --product vault --version YOUR_VERSION \
  --target windows-x86_64 --sequence 1 --source FULL_GIT_COMMIT \
  --expires FUTURE_UNIX_TIMESTAMP
```

Signing computes the file digest and length. Output files are created without
overwriting existing files. Check the resulting pair before publishing it.
Never publish private keys or passwords. KCSK v1 encrypts the signing seed with
the Core's existing Argon2id/XChaCha20-Poly1305 envelope. Encryption limits exposure
at rest; it does not make a compromised signing machine trustworthy.

## Protocol and limits

[Manifest protocol](PROTOCOL.md) defines exact bytes and validation rules.
Manifest validity depends on the local clock. `--min-sequence` accepts a minimum
learned through a trusted route; this tool does not maintain an automatic update
database, revocation service or threshold trust root. It is not an implementation
of [TUF](https://theupdateframework.github.io/specification/latest/).

See the [Verify threat model](THREAT_MODEL.md) for what a successful check
establishes and where trust in the publisher, verifier and local machine enters.
Report suspected vulnerabilities through the [security policy](../../SECURITY.md).
