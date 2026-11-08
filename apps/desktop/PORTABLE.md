# Standalone Windows applications

The Windows x64 packaging target is one executable per desktop application.
End users do not install the development tools or launch a `.cmd` script.

| Application | Executable | Included runtime |
| --- | --- | --- |
| Vault | `KryptoCore-Vault-Portable.exe` | Python, Qt, password estimator, Rust backend and Firefox host/channel |
| Messenger | `KryptoCore-MSG.exe` | .NET, Rust worker and the pinned Tor runtime |
| Container | `KryptoCore-Container.exe` | .NET and Rust worker |
| Rescue | `KryptoCore-Rescue.exe` | .NET and Rust recovery worker |

Builds use the existing one-file packaging scripts. Each script runs
`apps/desktop/tests/check-portable.ps1` after packaging. The check copies only
the EXE into a fresh directory, checks its x64 GUI PE header and launches its
embedded-worker checks with an OS-only PATH, no Python/Qt overrides and an
isolated .NET extraction location. Messenger also starts its embedded Tor with
networking disabled, checking address persistence and rotation. Vault's bundle
check does not construct the normal Vault window or alter Firefox registration.
Hashes and exit codes are retained; temporary copies are removed only on success.

```powershell
./apps/desktop/tests/check-portable.ps1 -Product Container `
  -Executable ./dist/apps/container/windows-x64/KryptoCore-Container.exe
```

This is an executable-only test on the Windows build machine. It does not
simulate a pristine Windows VM, prove public Tor connectivity or test every
supported Windows version. A clean-machine GUI smoke test remains a release
check. Keep signing and license review separate from successful startup.

## Files and optional tools

- Vault files, identities, backups, signing keys and encrypted containers remain
  separate from the application. Replacing an EXE must not replace user data.
- One-file apps extract runtime components into temporary storage. Vault's
  Firefox integration also provisions a stable native host under the current
  user's settings directory. Messenger retains its Tor identity/settings there.
  A single executable does not mean the app leaves no local state.
- ClamAV and its current database are optional external tools. The existing
  OpenSSH workflow also uses a separately installed tool. The native shared
  signature workflow does not require OpenSSH.
- The Firefox companion is a separate browser extension: a signed XPI for
  normal installation, or a temporary ZIP for development. It is not an EXE.
  KryptoCore itself is a library rather than a standalone desktop application.
- Ship applicable license texts and notices alongside downloadable EXEs or in
  a release ZIP. In particular, Vault's Qt source/library replacement obligations
  still need review before a one-file build is distributed publicly.

The current development builds are unsigned. Existing historical downloads can
still use an older setup workflow; release pages must identify the exact
standalone artifact instead of implying that every old ZIP is self-contained.
