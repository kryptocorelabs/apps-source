# Shared Vault format implementation

Internal application-format crate for Vault and Rescue. This is separate from
the minimal cryptographic Core. KCV1/KCV2 bytes, KDF parameters, slot roles,
associated data and validation are unchanged.

The existing `apps/vault/src/container.rs` implementation and its six tests
were moved here. Vault re-exports this API and uses the same zeroizing Login
schema. Rescue calls `open` or the new read-only `open_with_recovery`; it never
calls `reset_password`, `save` or a migration routine on an input file.

```sh
cargo test --locked --release -p kryptocore-vault-format
```

This crate is maintained with the open-source application workspaces. It is not a new
public encryption primitive or a replacement format. No general recovery key,
back door or bypass is provided.
