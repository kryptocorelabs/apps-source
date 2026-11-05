# KryptoCore MSG

MSG opens an encrypted chat channel for messages and files. Both people must
be online. The Windows app includes Tor and starts it when needed.

## Start a conversation

1. Open or create an identity under **Mein Profil**. Enter your passphrase
   once to unlock MSG for the session.
2. Under **Kontakte**, open an invitation or choose a saved contact. Create
   your own invitations under **Mein Profil**.
3. Both people select **Chatkanal öffnen** under **Nachrichten**. Once
   **Chatkanal offen** appears, either person can write or send a file.
4. Use **Mein Profil → MSG sperren** to close the channel and lock the app.

The app keeps up to 50 message bubbles in memory and does not save chat
history. Copy anything you need before closing or changing contacts.

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

Under **Kontakte → Kontakt per Tor-Adresse**, enter the other person's
bare .onion address or their address with port and select **Anfrage senden**.
The other person must enable **Anfragen erlauben** and explicitly choose
**Annehmen** or **Ablehnen**. An unanswered request expires after 45 seconds.

Incoming requests are off by default. **Anfragen ausschalten**, locking
MSG, switching to direct IP or changing the Tor address stops the listener.
Acceptance exchanges the keys and routes for a later chat. It does not
automatically open a chat or accept files.

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
Save a compared contact under a name, select an existing contact or remove
one. The encrypted contact list is stored beside the identity as
`.kcmi.contacts`. Back up both files. A lock file coordinates edits.

Under **Einstellungen → Kontakte & Freigaben**, you can require a mutual
exchange of two codes. This setting is saved for the identity and disables
address-only requests. Incoming request permission is limited to the
current unlocked session.

In an open chat, each person can agree to show online status. The indicator
appears after both agree. Either can withdraw permission and reconnecting
resets it. This indicator describes the current open chat.

## Files

Use **Datei senden** for a regular file up to 16 MiB. The recipient first
selects **Empfangsordner wählen** in the open chat. Files are stored with
an `MSG-` prefix after complete receipt. Existing files with the same name
are preserved. A receipt confirms that the other app accepted the message
or saved the attachment. An unconfirmed transfer may have arrived.

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
