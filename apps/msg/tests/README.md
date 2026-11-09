# MSG workflow regression checks

Run from the workspace root. These checks use synthetic identities and files.

## Core and storage

```powershell
cargo test --locked --release -p kryptocore-msg -p kryptocore-desktop-engine
cargo build --locked --release -p kryptocore-desktop-engine
python apps/msg/tests/chat_downloads.py
```

The Python test currently targets the Windows engine at
`target/release/kryptocore-desktop-engine.exe`. It starts two loopback peers
and checks replies, a missing receive folder, save-as, filename collisions,
stale download decisions, rejection, confirmation for executables, macro-capable
Office files and mountable images with a selected folder, remembered folders
and empty files.

## Windows interface and live Tor

Build the MSG Windows app with its verified Tor bundle first, then:

```powershell
dotnet build apps/msg/tests/windows/Check.csproj -o dist/msg-ui-check
dotnet dist/msg-ui-check/Check.dll apps/msg/windows/bin/Release/net10.0-windows/win-x64/KryptoCore-MSG.dll
```

This is an opt-in network integration test, not an offline unit test. It
starts two WPF windows with isolated Tor profiles and synthetic identities.
Do not run another MSG listener on the same Windows account during it.
Tor bootstrap and onion publication can take several minutes.

For a deterministic interface/engine regression run without public Tor:

```powershell
dotnet dist/msg-ui-check/Check.dll apps/msg/windows/bin/Release/net10.0-windows/win-x64/KryptoCore-MSG.dll --loopback
```

This mode generates real onion service identities with Tor networking
disabled, then injects a loopback-only SOCKS bridge into the test instances.
The production Rust workers still perform their usual authentication,
encryption and protocol checks. The bridge accepts only the two test host
names and the local MSG chat/request ports. It is test code and is not
compiled into the application. It does not test public Tor connectivity,
anonymity, circuit behavior or latency.

It exercises request popups, decline, persisted block/unblock, automatic
chat opening, contact saving without claiming a personal key comparison,
messages in both directions, download prompts, decline/save and locking.
It also checks sidebar search, selecting an active chat without reconnecting,
draft and message separation between contacts, restoring a conversation,
reconnecting from the sidebar, reloading contacts after unlocking and
separating identities. Native Windows picker interaction is not automated.
The encryption indicator is checked with Tor available but no chat,
a mismatched saved key, an unconfirmed connection, a confirmed channel,
local cancellation, remote closure and locking. A temporarily unavailable
synthetic identity file also exercises the failed-connection marker.
The file picker selection is supplied through the same engine input used
by the interface; native Windows file-picker interaction is not automated.
It also checks the custom frame's caption controls and selected navigation
state, and verifies that writing and sending stay within a 960×700 window.
It renders `request.png`, `chat.png`, `chat-compact.png`, `profile.png`,
`download.png` and `chat-file.png` in
the test output directory. Test identity data stays in its `fixtures`
subdirectory and can be removed after the test.

The bounded in-memory model can be tested without Tor or windows opening:

```powershell
dotnet dist/msg-ui-check/Check.dll --session-only
```

This checks contact isolation, case-insensitive key matching, message and
conversation bounds, least-recently-used eviction, forgetting and clearing.
