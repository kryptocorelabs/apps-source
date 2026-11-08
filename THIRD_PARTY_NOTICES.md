# Third-party components

First-party source is MIT licensed under [LICENSE](LICENSE). This does not
relicense dependencies or their copyright notices. Cargo manifests/lockfiles
record the Rust dependency versions; CI checks their licenses and advisories.

The [signature companion](modules/signatures/THIRD_PARTY_NOTICES.md) has its
own locked inventory. Windows release packages include the .NET/Rust runtime
notices and application-specific inventories in the public
[MSG](https://github.com/kryptocorelabs/msg),
[Container](https://github.com/kryptocorelabs/container) and
[Rescue](https://github.com/kryptocorelabs/rescue) release repositories.
MSG packages include the pinned Tor runtime and its notices. Optional OpenSSH
and ClamAV are external tools with their own distribution terms.

Changing dependencies requires updating the relevant inventory and preserving
the required texts. A source license is not a certification of a binary package's
complete redistribution compliance. See each packaging guide for its scope.
