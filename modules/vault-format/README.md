# Shared Vault format implementation

Internal application-format crate for Vault and Rescue. This is separate from
the minimal cryptographic Core. KCV1/KCV2 bytes, KDF parameters, slot roles,
associated data and validation are unchanged.

The existing `apps/vault/src/container.rs` implementation and its tests
were moved here. Vault re-exports this API and uses the same zeroizing Login
schema. Rescue calls `open` or the new read-only `open_with_recovery`; it never
calls `reset_password`, `save` or a migration routine on an input file.

```sh
cargo test --locked --release -p kryptocore-vault-format
```

This crate is maintained with the open-source application workspaces. It is not a new
public encryption primitive or a replacement format. No general recovery key,
back door or bypass is provided.

## Optional epoch profile

[KCV3](KCV3.md) is an explicit opt-in copy with authenticated ID/epoch and
caller-supplied freshness minima. KCV1/KCV2 remain unchanged; old readers reject
KCV3. Rescue reads all three without claiming backup freshness.

## Recovery reset boundary

In the unreleased recovery hardening, `reset_password` authenticates the source
and parses the login records before creating a fresh random 32-byte seed.
Both slots wrap the new seed with fresh salts/nonces, using the new password
and the existing recovery secret. The payload is encrypted under the new key,
with the complete new header as AAD, then atomically replaces the selected file.
KCV2 bytes, readers and recovery-secret compatibility remain unchanged.

Earlier resets retained the seed. Ordinary `save` still retains it. Rekeying
protects updated files from a key recovered from a pre-reset snapshot; it cannot
revoke that snapshot or any plaintext already disclosed. A current recovery
secret still opens the updated file. Complete-file rollback is not detected.

The KCV2 `payload_key` derivation still uses the fixed Argon2id profile and
`KCV2 payload key` salt. A memory-hard password KDF adds unnecessary cost to a
uniformly random seed; a domain-separated HKDF is a candidate for a future
profile ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)). Changing the
derivation in place would break existing KCV2 readers. Any replacement requires
explicit format versioning, compatibility tests and a migration design.
