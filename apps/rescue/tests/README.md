# Rescue inspection and recovery checks

Run from the workspace root:

```powershell
cargo test --locked --release -p kryptocore-rescue
cargo build --locked --release -p kryptocore-rescue
python apps/rescue/tests/probe_cli.py
```

The Rust tests cover current markers and credential-route metadata,
unsupported versions, truncation, size limits, wrapper length arithmetic,
unchanged sources, absence of adjacent files, bounded requests and refusal
of credential frames. Unix builds additionally check a leaf symlink.

The CLI test uses deliberately invalid synthetic ciphertext with plausible
headers. Recognition must always remain unauthenticated. It also checks
CLI failure exit status, no credential echo and source preservation.

For Windows, build the prototype first, then:

```powershell
./apps/rescue/build-windows.ps1
dotnet build apps/rescue/tests/windows/Check.csproj -o dist/rescue-ui-check
dotnet dist/rescue-ui-check/Check.dll apps/rescue/windows/bin/Release/net10.0-windows/win-x64/KryptoCore-Rescue.dll
```

The WPF check uses a synthetic header-only file. It verifies the visible
unauthenticated state, strict metadata report fields, unchanged sources,
no overwrite, cancellation cleanup and removal of stale report state after
a failed probe. It renders `rescue.png` in the test output directory.
Native file pickers are bypassed by setting the selected test path and
invoking the application's real recheck action. No main application, Tor,
browser or network access is involved. Synthetic fixtures remain in the
test output's `fixtures` directory and must not be included in distributions.

The recovery tests also validate real KCV1/KCV2 password and recovery-slot
exports, unchanged original ciphertext, wrong credentials, malformed records,
tampering, mandatory plaintext confirmation and refusal to overwrite.
Ordinary and executable-wrapped KCC extraction uses the existing reader and
tests final-tag failure cleanup. Vault's six original format tests remain in
the [canonical Vault workspace](https://github.com/kryptocorelabs/vault-source).
Run them there with `-p kryptocore-vault-format`.

The Windows check uses a synthetic KCV1 fixture generated with the Python
reference/PyNaCl, with password `synthetic rescue fixture password`. It checks
wrong-password rejection, a real authenticated plaintext export, explicit
consent, secret input clearing and clearing consent/destination on source changes.
No production credentials are included. MSG authentication/recovery is not
implemented or validated by this suite.
