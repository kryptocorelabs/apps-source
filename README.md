# KryptoCore application source

[Security in 30 seconds](SECURITY-IN-BRIEF.md) · [Recover without the main app](RESCUE-FIRST.md) · [Check a download](VERIFY-DOWNLOADS.md)

[![Applications CI](https://github.com/kryptocorelabs/apps-source/actions/workflows/apps-ci.yml/badge.svg)](https://github.com/kryptocorelabs/apps-source/actions/workflows/apps-ci.yml)
[MIT](LICENSE) · [Contribute](CONTRIBUTING.md) · [Security](SECURITY.md) · [Project charter](https://github.com/kryptocorelabs/kryptocore/blob/main/PROJECT_CHARTER.md)

Open-source implementation workspace for Messenger, Container, Rescue, Verify and the
shared Windows worker. First-party code is MIT licensed; dependencies retain
their own terms. All applications remain development previews without an
independent security audit.

Testing to date has been carried out by the KryptoCoreLabs maintainers, locally
and through automated CI. No independent security audit has been completed.
We welcome community testing, code reviews and scrutiny of our security
assumptions. Please use synthetic data and report suspected vulnerabilities
privately through the project's security-reporting channel.

| Project | Source and build guide | User downloads |
| --- | --- | --- |
| MSG | [apps/msg](apps/msg/README.md) | [MSG](https://github.com/kryptocorelabs/msg) |
| Container | [apps/container](apps/container/README.md) | [Container](https://github.com/kryptocorelabs/container) |
| Rescue | [apps/rescue](apps/rescue/README.md) | [Rescue](https://github.com/kryptocorelabs/rescue) |
| Verify | [apps/verify](apps/verify/README.md) | Native CI artifacts; no official release key provisioned yet |
| Shared Windows UI/worker | [apps/desktop](apps/desktop/README.md) | Included in the app packages |

Vault and Firefox sources are in the separate
[vault-source](https://github.com/kryptocorelabs/vault-source) workspace.
The [Core](https://github.com/kryptocorelabs/kryptocore) and its optional signature
companion are the canonical upstream security components. This workspace keeps
MIT-licensed copies for self-contained application builds. Changes to mirrored
components should be coordinated with their upstream rather than silently diverge.

## Build and test

```sh
git clone https://github.com/kryptocorelabs/apps-source.git
cd apps-source
cargo test --workspace --locked --release
```

Install stable Rust first; Windows MSVC needs C++ build tools and the Windows SDK.
Rust tests run on Windows, Linux and macOS. The WPF graphical apps and single-file
packaging require Windows x64, the .NET 10 SDK and the desktop targeting pack.
See [desktop builds](apps/desktop/README.md) and
[executable-only checks](apps/desktop/PORTABLE.md). MSG packaging needs the pinned
Tor bundle described there; application users do not install Tor separately.
Rescue has its own [build script](apps/rescue/build-windows.ps1).

Current development versions: MSG 0.1.0-alpha.2-preview.4,
Container 0.1.0-alpha.2-preview.1 and Rescue 0.1.0-preview.3.
Source visibility does not turn previews into supported production releases.
Never commit real identities, keys, contact codes, vaults, archives or runtime
stores. Use synthetic fixtures and the private security-reporting route.
