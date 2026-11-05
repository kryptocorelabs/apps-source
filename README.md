# KryptoCore application source

Private implementation repository for MSG, Container, the Windows apps and
their shared Rust worker. Public documentation and downloads are maintained
in the separate msg and container repositories.

KryptoCore remains MIT licensed. Application code is maintained privately.
Third-party components retain their respective terms.

Run cargo test --workspace --locked --release. Windows builds require the
.NET 10 SDK and a Rust Windows x64 toolchain. See apps/desktop/README.md.
MSG packaging requires the verified Tor Expert Bundle documented there.

Keep private identities, contact codes, archives, runtime directories and
built binaries out of Git. Use synthetic data for tests.
