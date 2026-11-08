# ReleaseManifest v1

The manifest is a UTF-8 JSON object no larger than 131,072 bytes. Signing emits
compact JSON in the Rust struct's documented field order below. Verification
authenticates the **exact input bytes** before JSON decoding; whitespace changes
invalidate the signature. This does not rely on JSON reserialization or an
unspecified canonical-JSON algorithm. External signers must sign the same bytes.
Unknown and duplicate object fields are rejected.

```json
{
  "schema": "kryptocore-release/v1",
  "product": "vault",
  "version": "0.1.0-example",
  "sequence": 1,
  "issued_at": 1800000000,
  "expires_at": 1802592000,
  "source_commit": "0000000000000000000000000000000000000000",
  "artifacts": [{
    "file": "KryptoCore-Vault.zip",
    "target": "windows-x86_64",
    "length": 123,
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }]
}
```

The example has placeholder values, no valid publisher signature and no official
release authorization. `release.sig` is exactly 64 binary bytes produced by the
existing `kryptocore-signatures` protocol with `Purpose::ReleaseManifest`, not
raw Ed25519 over JSON, OpenSSH, Ed25519ctx or a container-purpose signature.

- Product/version/target are nonempty ASCII labels (letters, digits, `.`, `_`,
  `-`, `+`), at most 64 bytes; product/version are matched to caller expectations.
- Sequence is a positive u64. Verification rejects values below the caller's
  trusted minimum. No latest-release claim follows from sequence alone.
- Times are Unix seconds. Require `issued_at <= now < expires_at` and a positive
  validity interval of at most 366 days. A trustworthy local clock is assumed.
- Source commit is 40 or 64 lowercase hex characters. It is signed provenance
  metadata; Verify does not rebuild binaries to prove that source produced them.
- One to 64 artifacts. Each filename is unique, a single ASCII component using
  the same label alphabet, at most 180 bytes, excluding `.` and `..`.
- Artifacts are nonempty regular files up to 4 GiB. SHA-256 is 64 lowercase hex
  characters. Filename and target must match the selected artifact exactly.
- Signer identity is external: a required, structurally validated `KCP1:` key.
  No embedded manifest key, URL or certificate is accepted as a trust anchor.

Hashing streams one file handle in 128 KiB blocks, checks the expected length,
and rejects observable length/mtime changes during hashing. Symlinks/directories
are rejected. A hostile local process/filesystem may still race path selection
or replace the file after verification. Verification does not execute anything
or provide a protected installation transaction.

Signing-key files reuse the existing 96-byte KCSK v1 layout: eight-byte magic,
16-byte random salt, 24-byte nonce and 48-byte encrypted seed/tag. The complete
24-byte prefix is AAD. Key passwords use the unchanged Core KDF. Secret buffers
use zeroizing owners where implemented; OS/runtime copies remain out of scope.
Keys must be dedicated to release signing despite the shared envelope format.
