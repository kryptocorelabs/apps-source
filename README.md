# KryptoCore application source

Private implementation workspace for MSG, Container, Rescue and the shared
Windows worker. Public documentation/downloads live in their separate
[MSG](https://github.com/kryptocorelabs/msg),
[Container](https://github.com/kryptocorelabs/container) and
[Rescue](https://github.com/kryptocorelabs/rescue) repositories.

Current implementation: MSG 0.1.0-alpha.2-preview.4, Rescue 0.1.0-preview.2.
The shared Vault format reader preserves KCV1/KCV2 compatibility. The optional
signature companion is mirrored from the public Core workspace; no app uses
its signature protocol yet. The encryption Core and signature companion are
MIT licensed. Application source remains private; upstream terms still apply.

Run `cargo test --workspace --locked --release`. See `apps/desktop/README.md`
for Windows prerequisites and the verified Tor bundle. Rescue is offline and
has its own build script. Never commit real identities, contact codes,
archives, runtime stores, credentials or generated test/build output.
