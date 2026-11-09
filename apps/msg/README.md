# KryptoCore MSG

MSG opens an encrypted chat channel for messages and files. Both people must
be online. The Windows app includes Tor and starts it when needed.

The Windows development interface follows the supplied GetMusic 3.11 Aura
visual reference: muted blue surfaces, mint accents, rounded panels and a
compact borderless window. Navigation sits in a left rail, with contacts
beside the conversation and a fixed message composer. Use **+** beside the
composer to attach a file. Profile and connection options remain available
in the navigation rail.

Testing to date has been carried out by the KryptoCoreLabs maintainers, locally
and through automated CI. No independent security audit has been completed.
We welcome community testing, code reviews and scrutiny of our security
assumptions. Please use synthetic data and report suspected vulnerabilities
privately through the project's security-reporting channel.

[Security in 30 seconds](https://github.com/kryptocorelabs/kryptocore/blob/main/SECURITY-IN-BRIEF.md) · [Rescue-first guide](https://github.com/kryptocorelabs/kryptocore/blob/main/RESCUE-FIRST.md) · [Verify a download](https://github.com/kryptocorelabs/kryptocore/blob/main/VERIFY-DOWNLOADS.md)

## Start a conversation

1. Open or create an identity under **Mein Profil**. Enter your passphrase
   once to unlock MSG for the session.
2. In the left-hand **Chats** panel, choose **Meine Adresse** to copy your
   Tor address and enable incoming requests for the session. Choose
   **Neuer Kontakt** to enter someone else's address.
3. The recipient chooses **Annehmen** in the request popup. The chat opens
   on both devices automatically. Once **Verbunden** appears, either person
   can write or send a file. Invitations remain available under **Kontakte**
   and **Mein Profil**.
4. Use **Mein Profil → MSG sperren** to close the channel and lock the app.

The Windows development preview has a searchable chat sidebar. Saved
contacts load when an identity opens. Selecting a contact requests a chat;
selecting the already active contact keeps its connection. One conversation
can be connected at a time. Changing contacts closes the previous connection.

Messages and drafts are separated by contact key in memory. The 20 most
recently opened conversations retain up to 50 messages each for the current
unlocked session; older cached conversations, including drafts, may be
evicted. The app does not write these contents to disk. Locking, changing
identity or closing clears the session cache. This is not a permanent chat
archive. **Dateien & Privatsphäre → Verlauf leeren** clears the selected
conversation's cached messages. Enter sends a message. The current protocol
accepts single-line messages; visual wrapping does not insert line breaks.

## Invitations

A Tor invitation can pair both people using a single code. The issuer
selects **Auf Annahme warten**. The recipient opens the code under
**Kontakte** and selects **Einladung annehmen**.

Create a separate invitation for each person. An optional local label helps
recognize it when it is accepted. Up to eight invitations can be open.
The accepted invitation is removed and the remaining ones can be used in
the next listening window. You can withdraw a selected invitation.

Open invitations belong to the unlocked session. Locking MSG, changing
the Tor address or changing the invitation policy clears them. Cancelling
an active invitation wait withdraws that batch. A listening window lasts
five minutes and can be restarted if no invitation was accepted.

**Mit Code-Passphrase schützen** is enabled by default. It protects the
invitation with Argon2id and XChaCha20-Poly1305 through KryptoCore. Share
the passphrase separately. An unprotected code can be redeemed by anyone
who obtains it. The optional label stays local and does not establish who
is using a code.

Copy the selected invitation or save it as TXT. The TXT contains only the
code. Private identity files and identity passphrases stay with their owner.

## Contact requests using a Tor address

Choose **Neuer Kontakt**, enter the other person's bare .onion address
or their address with port and select **Verbindung anfragen**. The recipient
must enable incoming requests. A popup offers **Annehmen**, **Ablehnen** and
**Blockieren**. An unanswered request expires after 45 seconds.

Incoming requests are off by default. **Keine neuen Anfragen**, locking
MSG, switching to direct IP or changing the Tor address stops the listener.
Acceptance exchanges the keys and routes and opens the encrypted chat on
both devices. Accepting another request switches away from the current
chat; the popup explains this before acceptance. It does not automatically
save the contact or an incoming file.

Blocking saves the requesting identity's public key in an encrypted
identity-bound list. Further requests using that key are rejected without
a popup. Remove a block under **Einstellungen → Blockierte Kontakte**.
Someone can create a different identity, so this is not a way to block a
person across all possible identities.

Sending a request shares your MSG public key and your Tor return address
with the destination. The request uses Noise XN over the Tor onion service.
The receiver releases their MSG public key only after approval. Tor
authenticates the destination onion service. Compare the MSG keys through
a trusted channel if you need to confirm the person's identity.

The listener handles one pending request at a time with a bounded
handshake, a decision deadline and a short delay between connections.
Someone who knows the address can still cause unwanted requests while
this feature is enabled.

## Contacts and settings

**Kontakte → Meine Kontakte** loads automatically when you open the tab.
In a chat, choose **Kontakt übernehmen**, enter a name and save. A personal
key comparison is optional and is recorded separately; saving a contact
does not claim that a comparison happened. A saved Tor contact requests a
new chat and checks that the returned key matches the saved key.

Use the **Chats** search field to filter saved contacts without changing
the active connection or draft. The active row shows the connection state;
other saved rows do not claim that the other person is online. Presence
sharing remains an explicit choice for both participants.

The encrypted contact list is stored beside the identity as `.kcmi.contacts`.
The `.kcmi.verification` and `.kcmi.blocked` sidecars hold comparison metadata
and blocked keys. Back up the identity and its sidecars together. Missing
comparison metadata displays contacts as not compared. Existing contact
records retain their file format. Lock files coordinate edits.

Under **Einstellungen → Kontakte & Freigaben**, you can require a mutual
exchange of two codes. This setting is saved for the identity and disables
address-only requests. Incoming request permission is limited to the
current unlocked session.

In an open chat, each person can agree to show online status. The indicator
appears after both agree. Either can withdraw permission and reconnecting
resets it. This indicator describes the current open chat.

## Files

Use **Datei senden** for a regular file up to 16 MiB. Without a selected
receive folder, a popup offers **Speichern unter …**, **Ordner wählen …**
or **Ablehnen**. Choosing a folder also sets it for subsequent files in the
current chat; these use an `MSG-` filename prefix. Save-as uses the selected
name. Existing files are never replaced.

While waiting for a decision, one incoming attachment remains in bounded
memory and the chat can receive and answer messages. Closing the popup or
cancelling a save picker leaves an inline save offer. A failed save retains
the offer for retry. Closing or locking the chat discards unsaved data.
A receipt confirms that the other app accepted the message or saved the
attachment. An unconfirmed transfer may have arrived. Automatic saving to
a chosen folder does not scan files for malware or open them.

## Tor and direct connections

The single-file Windows build includes Tor. Its service keys are kept
under `%LOCALAPPDATA%\KryptoCore\MSG`. The active onion address survives
restarts and public IP changes. **Einstellungen → Neue Tor-Adresse
erstellen** rotates it. Contacts then need the updated address or a fresh
invitation. Protect this folder and your backups.

Use one Tor-mode MSG window per Windows user profile. Tor needs outbound
network access. Use **Tor starten und prüfen** under **Einstellungen** to
check startup.

Direct IP is available under **Einstellungen → Erweiterte
Verbindungseinstellungen**. Both peers configure a local listening address
and exchange codes with reachable public addresses. MSG compares the two
public keys to choose the listening side. That side needs inbound TCP
access. Use Tor if your networks block incoming connections. Legacy KCM1
codes can be read in direct mode and contain their route in plaintext.

## Security boundaries

The connection marker is tied to the authenticated chat state:

- Grey: no confirmed active channel.
- Amber: connecting or awaiting cryptographic confirmation.
- Green with a steady soft glow: the selected peer key passed the Noise
  handshake and both encrypted ready confirmations completed.
- Red: the connection attempt failed; no confirmed channel is active.

Starting Tor, accepting a request or marking a key as personally compared
does not turn this marker green. Local cancellation and locking disable it
when the session is canceled; a detected remote close also clears it.
An idle or broken network link can take time to report failure. The marker
describes the established cryptographic channel, not a continuous online
probe or a guarantee about the peer's device or real-world identity.

The Rust tests reject unknown peer keys, absent or corrupt encrypted ready
confirmations and tampered message ciphertext. Windows integration checks
also reject a saved-key mismatch and verify the marker before connection,
after confirmation and after local cancellation/locking.

- Chat uses Noise KK through Snow with fresh ephemeral keys and the
  `KryptoCore MSG chat v1` context. Both peers pin the selected MSG key.
  An encrypted confirmation in each direction precedes the connected state.
- Invitations use Noise IKpsk1, a random 32-byte secret and their own
  protocol context. No invitation secret is required for address-only
  requests because the receiver approves each new request.
- Address-only requests use a separate Noise XN context and onion port
  49426. Normal chat and invitations use port 49424. The command-line
  presence protocol remains on 49425.
- Identity files retain the KCMI v1 format. Argon2id and authenticated
  encryption protect the private identity key. Rust uses zeroizing storage
  for key material. Windows holds the unlock passphrase in a SecureString
  during the unlocked session and disposes it on lock or close.
- Plaintext exists on both devices while in use. A compromised endpoint
  can expose messages and credentials. Traffic analysis, denial of service,
  the local operating system and identity verification remain security
  boundaries. There is no independent security audit.
- There is no offline delivery, multi-device synchronization or group chat.
  Both participants need a compatible desktop build.

Protocol references are the [Noise specification](https://noiseprotocol.org/noise.html)
and the [Tor onion-service overview](https://community.torproject.org/onion-services/overview/).

### External dependencies

| Dependency | Why MSG uses it | Possible alternative or trade-off |
| --- | --- | --- |
| Bundled Tor Expert Bundle and the Tor network | Tor publishes the onion service and routes connections without resolving onion addresses through local DNS. Relay availability and traffic correlation remain external risks. | [Arti](https://tpo.pages.torproject.net/onion-services/ecosystem/dev/implementations/) could provide the Tor implementation after testing service-key persistence, local proxy behavior and feature parity. Explicit direct IP mode avoids Tor and exposes network addresses to peers. |
| Snow and its RustCrypto primitives | Snow implements the Noise handshakes that establish the encrypted MSG sessions and bind them to the expected keys. | Another maintained Noise implementation would need to pass interoperability and negative tests for the exact protocol contexts, framing and key handling. |
| KryptoCore and OS randomness | KryptoCore protects local identity data and invitation codes. Key and invitation generation need the OS random source. | An independent implementation could reproduce the existing Argon2id and XChaCha20-Poly1305 profiles after compatibility testing. It would still need trustworthy randomness. |

The desktop window uses `IOnionTransport` for startup, address rotation and
shutdown. `TorRuntime` owns the bundled process, authenticated control channel
and service profile. The Rust worker receives a loopback SOCKS endpoint and
dials validated onion addresses through `OnionTransport`; peer authentication
stays in the MSG protocols. A replacement must preserve the local-only handoff,
support the onion service ports and fail closed if the onion route is unavailable.
Direct IP remains an explicit mode.

## Build

From the workspace root, run `./apps/msg/build-windows.ps1`. The
[desktop instructions](../desktop/README.md) cover the prerequisites and
the Tor bundle. Source lives in `windows/` and `src/`.

## Command line

The command-line interface retains the one-message protocol. It is
separate from the persistent Windows chat.

```powershell
cargo build --locked --release -p kryptocore-msg
.\target\release\kryptocore-msg.exe keygen alice.kcmi
.\target\release\kryptocore-msg.exe keygen bob.kcmi
# Start reception, substituting the verified public key.
.\target\release\kryptocore-msg.exe receive bob.kcmi ALICE_PUBLIC_KEY 127.0.0.1:49424
# From the other terminal, send one line.
.\target\release\kryptocore-msg.exe send alice.kcmi BOB_PUBLIC_KEY 127.0.0.1:49424
```

On Linux and macOS use `./target/release/kryptocore-msg`. Both processes
exit after one message and its encrypted receipt.
