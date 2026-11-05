# KryptoCore Windows desktop

Build the graphical apps with the .NET 10 SDK, the Windows Desktop
targeting pack and a Rust toolchain targeting Windows x64. Each app has its
own Windows project and build script.

| App | Windows source | Build from the workspace root | Executable |
| --- | --- | --- | --- |
| Container | [`apps/container/windows/`](../container/windows/) | `./apps/container/build-windows.ps1` | `dist/apps/container/windows-x64/KryptoCore-Container.exe` |
| MSG | [`apps/msg/windows/`](../msg/windows/) | `./apps/msg/build-windows.ps1 -TorBundleRoot <path>` | `dist/apps/msg/windows-x64/KryptoCore-MSG.exe` |

For MSG, use the extracted official Windows x64 Tor Expert Bundle 16.0.
The default path is `dist/msg-tor-setup`. The build verifies the Tor executable
against the pinned SHA-256 hash. To build both apps, run
`./apps/desktop/build-windows.ps1`.

Each Windows x64 executable
contains its own .NET Desktop Runtime and Rust engine. You can copy either
executable to another directory on its own. The runtime extracts native
libraries to the user's temporary area. The app extracts its Rust engine
into a new temporary directory for each operation and removes it afterwards.

Run either executable with `--verify-package` to check that the window
loads and the bundled engine answers a test request.

Container starts with two tiles. Use **Dateien verschlüsseln** to add files or
folders, then enter or generate a passphrase. The app suggests a new file next
to your selection. Use **Container öffnen** to select an archive, enter the
passphrase, and extract into a new folder. You can change either destination
before proceeding. Dropping a single `.kcc` file on the start page opens it
for extraction. Dropping other files or folders starts encryption.

**Erweitert** contains the OpenSSH signature tools. The extraction options
also offer a standalone integrity check, sender verification, and an
optional ClamAV scan. For a protected signing key in the GUI, load it into
your SSH agent and select its public key file.

In MSG, create or load an identity first. In
[Tor mode](../msg/README.md#tor-and-direct-connections), MSG starts its bundled Tor process
and fills in the Onion address automatically.
For a test on one computer, open two windows, create a different identity in
each, and enable direct IP under **Einstellungen → Erweiterte
Verbindungseinstellungen**. Use different local ports, such as
`127.0.0.1:49424` and `127.0.0.1:49427`. Create and exchange protected
contact codes under **Mein Profil** and open them under **Kontakte**.
Both windows select **Chatkanal öffnen** under **Nachrichten**. Either
person can then write or send a file through the same channel. For incoming
files, choose **Empfangsordner wählen** first. See the
[MSG usage instructions](../msg/README.md) for invitations, optional
address-only contact requests, and the settings for each identity.

The apps invoke a local Rust worker without a console. Passwords and
messages are sent through a private process pipe, separate from arguments
and diagnostics. The same Rust libraries implement the CLI and GUI
operations and read the same on-disk formats.
