# KryptoCore Bridge design

**Status — PROPOSED.** Design review dated 2026-11-27. This document defines a
possible local handoff between applications. A production Bridge, shared unlock
service and Bridge permission store have not been implemented.

The companion [hardening audit](SECURITY_HARDENING_AUDIT.md) records the examined
source revisions, current interfaces, tests and remaining evidence gaps.

## Purpose and boundaries

One Core. Many Apps. Separate Data. Explicit Permissions.

Each application owns its encrypted files, keys, unlocked session and approval
UI. Using the same Rust library grants no access to another application's
records. The Bridge would authorize one identified operation on one selected
object, for one receiving application, within an existing unlocked session.

Examples include opening a selected encrypted KCC copy in Rescue, or delivering
one selected Vault login to a user-approved destination. Transferring an
encrypted file should preserve its exact bytes wherever the receiving app
already supports that format. A format marker alone establishes neither its
integrity nor its sender.

Bulk Vault exports, arbitrary filesystem access, remote connections, a universal
master key, background password requests and unlocking another application are
outside the initial scope. No app gets an implicit grant when another starts.

## Existing interfaces

| Path | Current use and trust assumption |
| --- | --- |
| Rust library calls | In-process opaque keys and cryptographic operations. Inputs and copies remain owned by the calling app. There is no interprocess authentication boundary here. |
| Desktop UI to bundled worker | Parent-created redirected stdin/stdout pipes. Passwords use separate bounded frames. The parent, its worker binary and their process environment are trusted. |
| Vault to Firefox | Extension to registered native host, then the Vault local pipe. Pairing and the encrypted v5 channel supplement OS access controls. Per-origin desktop approval controls credential fills. |
| MSG to Tor | An authenticated loopback Tor control connection and a local SOCKS endpoint. Tor has its own process and service key. |
| App to Rescue | A user selects a file and supplies its credential. Rescue authenticates a copy with the existing format reader. |

None of these implements a general grant for arbitrary applications. The
Firefox channel remains a separate product-specific protocol.

## Attacker model

| Attacker | Intended protection and limit |
| --- | --- |
| Another OS user or remote process | Restrict local endpoint access to the expected local account and logon session. Reject remote pipe connections and unexpected OS credentials. |
| A process claiming a familiar app name | Ignore self-reported app names and PIDs as authentication. Bind the connection to OS-reported peer credentials and an approved launch or installation record. |
| A same-user process | Treat it as a separate threat. Standard desktop accounts can often inspect, modify or impersonate other processes. Filesystem permissions, DPAPI, executable hashes and a saved app secret do not provide complete isolation against it. |
| A compromised permitted app | Limit access granted through the Bridge to the operation and data that the owner has approved. The process retains its existing OS permissions. Once delivered, plaintext cannot be recalled. |
| A captured or modified request | Validate framing, operation, object binding and current session before use. Reject expired, consumed, foreign-connection and replayed grants. |
| An administrator or compromised OS | Outside the confidentiality guarantee. Kernel credentials and UI prompts depend on the OS. |

## Connection establishment

Prefer an operation-scoped connection created by the owning app when the user
chooses a receiving application. A parent-created channel with only the intended
handles inherited avoids discovery of a permanent shared service. The exact
launch and handle-inheritance mechanism needs platform tests before adoption.
Do not inherit handles into unrelated child processes.

For independently running applications, registration must bind an installation
to a verified executable or bundle and an explicit user approval. Read identity
information from an opened OS process object and the actual image, rather than
trusting a pathname in a request. PID reuse, writable installation directories,
process injection and executable replacement must be considered. If a platform
cannot establish the required identity, deny the automatic handoff and offer an
explicit file-based workflow. Do not label that connection as verified.

An installation signature or digest can help identify expected software. It
does not establish a new isolation boundary for unrestricted processes under
the same user. Higher assurance requires an OS-enforced app sandbox or other
separate principal, which is an additional deployment design.

### Windows adapter

- Use a random local Named Pipe name created by the owner. Apply an explicit
  DACL for the intended user/logon SID with the minimum required access rights.
- Request `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`.
  Fail if another process already owns the endpoint. Never fall back to default
  pipe security or a TCP listener.
- Inspect peer token, user and logon session in both directions. Obtain peer
  PID from the kernel, then validate its process object against the approved
  launch. A PID or session ID alone identifies no application.
- Use bounded asynchronous I/O and close every pipe/process/token handle on
  completion, denial, timeout, lock or error. Avoid privileged impersonation
  as a side effect of parsing an untrusted request.

Windows evaluates Named Pipe DACLs, and default permissions may be broader than
this design requires. Kernel peer IDs provide process identifiers that still
need an application trust decision. [Microsoft pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[creation flags](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew),
[client process ID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid).

### Linux adapter

- Prefer an inherited Unix socket pair for an owner-launched receiver.
- If discovery is required, use a pathname Unix Domain Socket under a verified,
  user-owned `XDG_RUNTIME_DIR` and a private app directory with mode `0700`.
  Restrict the socket to `0600`, verify ownership/type, and reject symlink
  ancestors. Avoid the abstract namespace for the initial design.
- Obtain peer UID/GID/PID from `SO_PEERCRED` and validate against the expected
  local principal and launch. Hold a stable process reference where supported.
  Same UID does not establish app identity.
- Restrict descriptor passing to an explicitly chosen read-only file handle.
  Set close-on-exec and never accept arbitrary caller-controlled filesystem
  paths as instructions to open files.

Linux pathname and abstract sockets have different permission behavior.
`XDG_RUNTIME_DIR` must belong to the user and have mode `0700`.
[Linux Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html),
[XDG runtime specification](https://specifications.freedesktop.org/basedir/).

macOS requires its own peer-credential and code-identity adapter. Linux socket
permission assumptions must not be carried over without verification.

## Approval and capability lifecycle

1. The owner validates connection identity and framing before showing a prompt.
   No record is decrypted merely to populate a discovery response.
2. The receiver requests a typed operation. The owner lets the user select the
   object, destination and exact fields through its own UI.
3. The owner displays the verified receiving app, operation, selected object,
   plaintext/encrypted status and destination. No passwords appear in the prompt.
4. An approval creates a random 32-byte opaque capability in owner memory. Bind
   it to the live connection, local unlock-session generation, operation,
   selected object ID and authenticated revision/digest, receiver and byte limit.
5. Use monotonic time for a proposed 30-second grant lifetime and a maximum of
   one use. No persistent grants are issued in the first version.
6. Immediately before disclosure, recheck expiry, lock state, object revision and
   receiver. Reserve/consume the grant atomically so simultaneous requests
   cannot both succeed. If disclosure fails, require a fresh approval to retry.
7. Lock, identity change, pairing change, receiver exit, connection close and
   owner restart invalidate every outstanding grant. Revocation cancels pending
   work and removes remaining owner-held buffers where possible.

Use a serialized grant state transition such as `Pending -> Reserved -> Consumed`
or `Pending -> Revoked`. A failure after reservation never returns it to Pending.
Do not implement a hand-written cryptographic token format. The opaque value is
looked up in owner memory and is valid only on its original authenticated
connection. Authentication precedes capability lookup. Token values never enter
URLs, command lines, environment variables, clipboard history or logs.

Revocation can prevent pending delivery. It cannot erase data already received,
undo a saved export or defeat a receiver that retains authorized plaintext.

## Message and payload design

The proposed control API has versioned operations such as `request_transfer`,
`approve`, `perform` and `cancel`. Exact names and encoding are provisional.
The owner alone issues approval. A receiver-supplied `approved=true` is ignored
as authorization and rejected by the typed schema.

Use a documented length-prefixed bounded schema with a protocol version,
session identifier, request identifier and typed operation. Reject unknown
versions, duplicated fields, invalid lengths, excess nesting and unexpected
fields before processing. Proposed limits are 16 KiB per control frame, one
in-flight operation per connection and a five-second handshake deadline.
Object IDs refer to owner-selected records, never arbitrary filesystem paths.

For bulk encrypted handoffs, pass a restricted read-only descriptor/handle or
an immutable owned copy plus expected digest and size. Authenticate the actual
bytes that the receiver consumes. Check file type, reparse/link state, size and
identity before use and after any operation where replacement matters.
Path checks alone cannot prevent a concurrent writer from replacing a file.

Plaintext delivery requires a separate explicit grant and a size limit chosen
for the specific operation. It stays in short-lived buffers where practical.
Streaming plaintext is staged privately and becomes a final result only after
the authenticated final record and required policy checks. Reject partial
success. Existing destinations and source ciphertext remain intact on failure.

Encrypted file forwarding needs no master key at the Bridge. If a receiver must
decrypt, use that format's established credential entry or an independently
reviewed key-wrapping profile. Never forward the owner's master password,
payload root, identity secret or arbitrary key export through a generic API.

## Encryption decision

For an authenticated, owner-created local channel with enforced access and
intended handle inheritance, an additional encrypted session is not part of
the first proposal. The concrete boundary is the OS channel and its approved
operation. Adding encryption would not isolate peers from malware already able
to inspect either endpoint or obtain their credentials under the same account.

The existing Firefox v5 encrypted protocol retains its own documented purpose,
pairing model and tests. It must not be replaced by this proposal. A future
Bridge transport requiring cryptographic peer authentication must identify the
additional threat, secure enrollment/trust root and revocation process first,
then reuse a maintained protocol implementation with independent review.

## UX and failure behavior

Present one owner-controlled prompt such as “Send this selected login to MSG
for this operation?” with destination, data fields, “Allow once” and “Cancel”.
Encrypted forwarding should say that the receiver still needs the corresponding
credential. Keep technical identities in expandable details.

Decline, expiry, cancellation, lock and unavailable receiver receive distinct
fixed error codes. Authentication failures reveal no matching record count or
content. Logs may retain operation class, generic outcome and duration, with
no secrets, capabilities, object names or full paths. Diagnostic collection is
deliberate and redacted. No automatic crash-dump upload is introduced.

DPAPI, Windows Hello and platform key stores may protect optional local
credentials after separate review. They do not grant another application
access to the owner's data and do not replace operation approval or recovery.

## Required evidence before implementation

| Gate | Required tests and review |
| --- | --- |
| OS identity | Cross-user and cross-logon rejection, pipe squatting, unsafe default ACL, abstract socket rejection, UID/PID spoof/reuse and descriptor inheritance. |
| Grants | Default deny, exact object/receiver/operation binding, simultaneous reuse, expiry, restart, revoke during work and lock before delivery. |
| Files | Links/reparse points, traversal, replacement races, changed size/digest, source preservation, incomplete stream, full disk and staging cleanup failures. |
| Memory and errors | Secret-free diagnostics, bounded buffers, cancellation paths and documented runtime/OS copy limits. |
| UX | User can identify the actual recipient, approve once, cancel and understand plaintext output. No permission appears from starting another app. |
| Compatibility | Existing apps work with Bridge absent, disabled or failed. Current vault files, identities, recovery and Firefox pairings remain readable. |

All gates are PROPOSED and NOT VERIFIED for a Bridge implementation. Linux,
Windows and macOS implementations require platform-specific execution evidence.
After those gates and review of same-user attacker assumptions, propose a small
file-forwarding pilot as a separate change.
