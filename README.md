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

| Project | Source and build guide | Threat model | User downloads |
| --- | --- | --- | --- |
| MSG (experimental) | [apps/msg](apps/msg/README.md) | [Messenger](apps/msg/THREAT_MODEL.md) | [MSG](https://github.com/kryptocorelabs/msg) |
| Container | [apps/container](apps/container/README.md) | [Container](apps/container/THREAT_MODEL.md) | [Container](https://github.com/kryptocorelabs/container) |
| Rescue | [apps/rescue](apps/rescue/README.md) | [Rescue](apps/rescue/THREAT_MODEL.md) | [Rescue](https://github.com/kryptocorelabs/rescue) |
| Verify | [apps/verify](apps/verify/README.md) | [Verify](apps/verify/THREAT_MODEL.md) | Native CI artifacts and a published release-verification key |

The [shared Windows UI and worker](apps/desktop/README.md) are included in the app packages.

Vault and Firefox sources are in the separate
[vault-source](https://github.com/kryptocorelabs/vault-source) workspace.
Cargo resolves the [Core](https://github.com/kryptocorelabs/kryptocore) and
[Vault format](https://github.com/kryptocorelabs/vault-source/tree/main/modules/vault-format)
from exact public Git revisions recorded in the workspace manifest and lockfile.
Update both pins together when the format crate changes its Core revision.
The optional signature companion has its own crate in this workspace.

## Build and test

```sh
git clone https://github.com/kryptocorelabs/apps-source.git
cd apps-source
cargo test --workspace --locked --release
```

Install stable Rust first. A first build fetches the locked dependencies. Windows
MSVC needs C++ build tools and the Windows SDK.
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
