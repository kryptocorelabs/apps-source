# Ecosystem security hardening review

Review date 2026-11-27. Maintainer review with synthetic data. This records
source inspection, reproduced behavior and targeted hardening. It is not an
independent audit or a certification. Passing tests establish their tested
properties within the recorded environment.

## Scope and source identity

All four requested repositories were present locally. Read-only `git ls-remote`
confirmed that their local baseline commits matched GitHub `main` on the review
date. The three implementation repositories were clean before the review and
were switched to `codex/ecosystem-security-hardening-20261127` before editing.

| Repository | Examined baseline commit | Treatment |
| --- | --- | --- |
| kryptocore | `85aaa981be9732869a060fa54a57657e185e66c9` | Branch changes to provider minimum, tests, CI and architecture notes. |
| vault-source | `72f43175656b1e4b5e271242eab0148add3895a6` | Branch changes to the URL dependency and origin regression. |
| apps-source | `1f49b842814e1bd4fd8d38c8706e40ccaaeedff0` | Branch changes to MSG storage, worker buffer lifecycle, tests and this review. |
| vault | `bea3d97e2a9ef4382088f17f02f62827d2553498` | Release documentation inspected read-only. |

The app workspaces pin Core at `89abb9bdf8cf4751f718343920abf70c0af8d2eb`.
Apps also pins the shared Vault format at
`778b7e22c959b5e209a5b97c35f797c6c47faa9f`. Tests of those apps therefore
exercise their pinned implementations rather than silently replacing them with
the current Core branch. The local review changes have not been released.

The source tree at the outer workspace root contains historical snapshots.
Implementation work uses `publishing/` checkouts. No real vault, identity,
pairing, recovery sheet or publisher private key was opened for this review.

## Evidence labels

| Label | Meaning |
| --- | --- |
| VERIFIED | The named narrow property was established by source inspection or a specified observation. |
| IMPLEMENTED | A mechanism exists in the inspected source, including a new branch change. |
| TESTED | The listed executable test ran successfully in this review. |
| PROPOSED | Design or follow-up requiring separate implementation and review. |
| BLOCKED | A concrete tool, permission or environment constraint prevented execution. |
| NOT VERIFIED | Evidence was not obtained in this review. |

Implementation state is reported separately as implemented, partially
implemented, not implemented or not verified. A mechanism can be IMPLEMENTED
with platform behavior still NOT VERIFIED.

## Data flows and trust boundaries

| Component | Input, derivation and cryptographic processing | Storage, output and authorization |
| --- | --- | --- |
| Rust Core | Caller bytes enter local Rust functions. OS randomness generates keys/salts/nonces. Argon2id derives password keys. Opaque `Key` owns selected zeroizing memory. HKDF contexts derive purpose-specific subkeys. XChaCha20-Poly1305 authenticates AAD and ciphertext. | Returns nonce/ciphertext or authenticated zeroizing plaintext. It owns no app files, unlock policy, account, IPC service or recovery UI. Stream output may contain an authenticated prefix before final verification, requiring caller-owned staging. |
| Python reference | Independent argon2-cffi and PyNaCl/libsodium implementation. It does not call Rust through an FFI. Passwords, keys and plaintext are immutable Python byte objects. | Functions return ordinary bytes. Explicit AAD is recommended, with a visible compatibility warning for omission. No persistent store, app discovery or cross-app key access exists. Complete clearing of Python copies is not guaranteed. |
| Vault | Qt credential fields send bounded JSON commands to a Rust child over redirected pipes. The Rust session owns the credential and reads a bounded KCV file. Password/recovery slots authenticate a random seed, then the payload authenticates before JSON parsing. | KCV1–KCV4 dispatch to known readers. Current GUI creation uses KCV4. Saves stage encrypted bytes before replacement. Lock terminates the worker and invalidates browser state. Deliberate JSON export and recovery-sheet output are plaintext operations. |
| Firefox | A permitted content document supplies a request to the extension background. Background checks origin, tab/frame/document and session. The registered native host relays bounded messages to the local Vault pipe. Pairing and Noise v5 authenticate/encrypt the channel. | A fill needs a desktop approval for the exact origin/action in the current unlock session, valid once for 30 seconds. Standard mode allows session-bound save. Strict mode narrows operations. Default global host permission is off. A filled page receives its chosen login in plaintext. |
| Container | OS-random data key is password-wrapped with Core AEAD and context including the stream header. Existing KCC v1 uses RustCrypto STREAM-BE32 records and a bounded entry/path parser. | `.kcc-*` staging receives authenticated chunks. Final record, EOF and requested sender/scan checks precede creation of a new output directory. Multiple root moves can partially complete after a crash. Staged/extracted files are plaintext. |
| MSG | Password unlocks a random X25519 identity in KCMI. KCMB v2 sidecars and KCMO onion key use different HKDF contexts. Noise KK, IKpsk1 and XN use separate protocol roles for chat, invitations and new requests. | WPF keeps a SecureString during unlock and sends short-lived byte buffers to its Rust worker. Lock/profile switch cancels sessions and stops Tor. Contacts and optional sidecars remain encrypted. No persistent chat archive exists. Received attachments are explicitly/policy-authorized plaintext outputs. |
| Rescue | The user selects a source copy and a credential route. Inspection checks markers/bounds only. Recovery uses the pinned Vault reader or the existing Container extractor and authenticates before parsing. | Plaintext export requires confirmation. New output is staged, optionally scanned and published without overwriting existing data. It never invokes the Vault password-reset writer or launches an embedded container EXE. |
| Verify | User supplies a separately trusted publisher key and expected product/version/target. Signature verification uses `Purpose::ReleaseManifest` over exact bytes, followed by metadata, time/sequence, digest and size checks. | Downloads remain data and are not executed. Signing uses a separate encrypted KCSK key file and explicit credential entry. Verification does not establish that an approved binary is harmless or immune to later replacement. |

Primary implementation locations are `kryptocore/rust/{lib,context,wrapping,stream}.rs`,
`kryptocore/src/kryptocore/_crypto.py`, `vault-source/modules/vault-format/src/`,
`vault-source/apps/vault/{src,desktop,extension,firefox-channel}/`, and this
repository's `apps/{container,msg,rescue,verify,desktop}/` directories.

Current Firefox packages use `extension/manifest.firefox.json`. The generic
`extension/manifest.json` is a historical loopback prototype. It must not be
treated as the supported Firefox package. Rust retains a separate legacy
CLI/worker one-entry HTTP share route with loopback binding, a 90-second random
one-use token and exact host/site checks. The current Qt Firefox path uses the
native host and encrypted channel.

### State of lifecycle protections

| Control | Implementation state | Evidence and limit |
| --- | --- | --- |
| Independent app key roots and purpose binding | Implemented | VERIFIED by key generation, HKDF/AAD and format readers. Wrong-key and foreign-context tests exercise rejection. Sharing Core code supplies no credential to another app. |
| Authenticated full results and source preservation | Implemented | TESTED for Core/Container stream errors, Container publication and Rescue recovery. Core streaming itself is not transactional. |
| Selected Rust memory clearing | Implemented | `Zeroizing`/`zeroize` cover owned keys, plaintext and Argon2 work memory. Type and failure-path regression tests pass. Allocator/OS/managed-runtime copies remain outside this property. |
| GUI lock and local session cancellation | Implemented within the documented process boundary | Source ends workers, cancels sessions and clears owned state. Final permitted Qt and Messenger integration runs pass, including lock and profile switch. A real signed Firefox installation remains NOT VERIFIED in this review. |
| Windows DPAPI legacy Onion/pairing protection | Implemented | Source inspection. DPAPI is scoped to the Windows user and does not isolate that user's unrestricted processes. Existing MSG import remains a deliberate operation. |
| Hardware-backed optional unlock providers | Not implemented as a general ecosystem mechanism | PROPOSED. Windows Hello, TPM, CTAP and Linux secret stores need separate provider, recovery and UX designs. |
| Local rollback protection | Partially implemented | KCV3/KCV4 track authenticated revision/fingerprint against local history. Replacing both file and history, first use, and old authentic backups remain outside it. MSG stores have no monotonic external anchor. |
| General app-to-app grants | Not implemented | PROPOSED in [Bridge design](KRYPTOCORE_BRIDGE_DESIGN.md). File-based Rescue is the existing deliberate handoff. |
| Private crash-dump/OS memory protection | Not verified | No new crash upload or telemetry was introduced. Swap, dumps, clipboard managers, OS backups and endpoint compromise can retain secrets. |

### Domain-separation convention

For new uses of an existing high-entropy root, use `Key::derive_subkey` with
`Context::new(application_namespace, format_version, purpose, metadata)`.
Namespaces are app-owned lower-case labels, purposes name the operation, and
metadata uses a documented fixed-width or length-framed encoding. Context v1
metadata occupies the entire tail. Frame the complete context before appending
outer fields. Choose version/purpose from the expected protocol rather than
accepting an attacker's claim as authorization.

Keep passwords on the existing Argon2id path and retain existing legacy
contexts. Keep wrapping keys independent of data keys. A shared origin root
such as one MSG identity intentionally grants access to that identity's derived
stores when compromised. It does not grant access to an independently generated
Vault or Container key. This review changes no existing context or file marker.

## Findings and targeted changes

Severity describes this project's observed impact and attacker requirements.
Dependency advisories are distinguished from demonstrated app exploits.

| ID | Finding, impact and required access | Severity | Branch result |
| --- | --- | --- | --- |
| EH-01 | Vault allowed and locked `url` 2.5.8, affected by RUSTSEC-2026-0592. A consumer calling `Url::origin()` on a deeply nested attacker-supplied `blob:` URL can abort its process. Vault's examined origin helper checks HTTP(S) first, so no app exploit was demonstrated. | Medium dependency availability risk | IMPLEMENTED minimum `url=2.5.9`, lock `url 2.5.9` and required `form_urlencoded 1.2.3`. Added rejection regression. Final RustSec check passes. |
| EH-02 | Python allowed PyNaCl 1.5.0 and the baseline test environment used it. Its bundled libsodium has CVE-2025-69277 point-validation behavior. Two pip-audit IDs alias the same issue. The affected atypical Ed25519 low-level use was not demonstrated through the reference's XChaCha20 path. | Medium dependency hardening | IMPLEMENTED `PyNaCl>=1.6.2`, provider note and isolated-runtime audit CI. TESTED 17 Python cases and both Rust/Python interop cases with 1.6.2. Final runtime audit passes. |
| EH-03 | MSG sidecar and lock paths could follow static links or accept unsuitable file types before open. A local actor controlling selected directories could redirect reads or block a process. AEAD still binds key and store roles. No decryption bypass was demonstrated. | Low local availability/integrity hardening | IMPLEMENTED regular-file, symlink and Windows reparse checks for contact/policy/trust/block/onion stores and locks, plus post-open metadata checks. Contact writes refuse an existing link. TESTED portable cases locally and Unix symlink rejection in Linux/macOS CI. |
| EH-04 | Shared C# worker request serialization retained its owned JSON byte buffer until collection. Some requests can contain an invitation capability. An attacker inspecting local process memory could encounter an additional copy. | Low memory defense | IMPLEMENTED immediate clearing after the frame is sent and finally-path clearing on failure, plus pre-cancellation before worker setup. TESTED cancelled/rejected credential cleanup and actual embedded-worker request. Immutable CLR strings remain outside this clearing guarantee. |
| EH-05 | Windows did not exercise the Core's existing allocation-rejection regression in CI. Argon2id needs 256 MiB per active derivation. | Low assurance/resource gap | IMPLEMENTED a test-only isolated Windows Job Object runner and CI step. TESTED 192 MiB process commitment limit and the separate two-derivation test. |

Additional regression coverage checks the Firefox channel ABI's failure state.
Oversized input, an invalid operation and unauthenticated input must clear the
owned channel buffer and prevent reuse of the invalidated channel. It adds
tests without changing the protocol. The Vault threat model also replaces an
outdated “unreleased” recovery description with a reference to its existing
build-specific lifecycle table.

EH-01 is in `vault-source/apps/vault/Cargo.toml`, `Cargo.lock` and
`apps/vault/src/main.rs`. EH-02 and EH-05 are in `kryptocore/pyproject.toml`,
`.github/workflows/ci.yml`, `ARCHITECTURE.md` and
`tests/check_argon2_memory_windows.py`.
EH-03 changes [MSG file handling](apps/msg/src/lib.rs),
[contact stores](apps/msg/src/contact_book.rs), [onion storage](apps/msg/src/onion_store.rs)
and [storage regressions](apps/msg/src/storage_tests.rs).
EH-04 changes [the shared worker client](apps/desktop/windows/Shared/Engine.cs),
[Windows lifecycle tests](apps/msg/tests/windows/Program.cs) and
[Applications CI](.github/workflows/apps-ci.yml).

### Reproduction and verification

- EH-01 baseline `cargo audit --deny warnings` reports RUSTSEC-2026-0592.
  The added test supplies one `blob:` prefix and 4,096 prefixes followed by a
  synthetic HTTPS site and requires rejection. The upstream advisory describes
  a separate direct-library crash reproduction. No production file is involved.
- EH-02 auditing the recorded baseline runtime inventory reports both aliases.
  Auditing the upgraded five-package runtime inventory reports no known
  vulnerability. System-linked libsodium needs its own patched-library check.
- EH-03 create synthetic sidecar/lock directories and require read/write/open
  failure without changing them. The Unix-only regression links a store to a
  valid encrypted fixture and requires rejection while preserving link and
  target. It is present in the existing Linux CI suite, pending execution.
- EH-04 the Windows test supplies a pre-cancelled request whose serializer
  would throw if reached, then a rejected oversized credential. Both must
  clear owned credential arrays. Source review establishes the metadata clear
  immediately after its frame and in `finally`. Memory-forensic proof of every
  transient managed copy was not attempted.
- EH-05 the Windows helper checks that the compiled binary lists the exact
  ignored allocation test, creates its process suspended, applies a 192 MiB
  Job Object commitment limit and then starts it. The Rust test checks both
  detailed `MemoryUnavailable` and the compatible legacy error mapping.

[RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0592.html),
[upstream URL fix](https://github.com/servo/rust-url/releases/tag/v2.5.9),
[PyNaCl fix and supported Python versions](https://pypi.org/project/PyNaCl/1.6.2/).

## Firefox-specific assessment

The examined v5 channel uses Noise with pairing-derived secrets, fresh
handshakes and distinct protocol contexts. The native host and channel bound
request/reply sizes. The Qt local server restricts connections to the same user
and verifies Windows logon session. It does not thereby identify Firefox.
The extension verifies the active origin/document and targets the allowed
frame. Navigation, tab changes and lock/session change invalidate stale work.

Unlocking alone gives no blanket credential-read authorization. Passive lookup
returns availability, then each fill needs its one-use desktop approval. A
process under the same account that obtains the pairing key can still
authenticate as a paired peer and race for an already-approved exact request.
A compromised permitted page receives its own filled credentials. These are
existing boundaries, not resolved by extra same-process encryption.

Default global website permission is disabled. Permission-granted content
scripts remain a browser boundary. Mocked browser tests provide execution
evidence for their cases. The final permitted Qt workflow checks live local-pipe
session enforcement and desktop approval/locking behavior. A real signed
Firefox install and races across actual browser processes require a separate
integration run.

Pending submitted-login capture can hold credential data in Firefox
`storage.session` for up to 120 seconds. Expiry, tab/permission changes and
session mismatch trigger cleanup. This is a separate managed-memory copy, and
already filled page fields cannot be cleared retrospectively by locking Vault.

## Test results and environment

Tests use Windows x64, Rust/Cargo 1.99.1 MSVC and .NET 10. Python 3.9.4 was
used for the baseline. The final reference-provider tests use an isolated
Python 3.13.18 environment with PyNaCl 1.6.2, argon2-cffi 23.1.0,
argon2-cffi-bindings 26.2.0, cffi 2.1.1 and pycparser 3.12.

| Suite | Result | Scope and qualification |
| --- | --- | --- |
| Core unit and signature tests | PASS 25 | Includes two new streaming I/O error cases. |
| Core and signature doctests | PASS 5 | Includes Key Debug/Clone compile-fail checks. |
| Final Python reference | PASS 17 | Explicit FutureWarning handling, AEAD negative cases and reference vectors. |
| Final independent interop | PASS 2 | AEAD Rust/Python in both directions and Ed25519 Rust/PyNaCl. |
| Concurrent Argon2 and reservation failure | PASS 2 | Explicitly executed normally ignored tests. Two work buffers and isolated Windows commitment rejection. |
| MSG complete Rust suite | PASS 26 locally | Includes both new portable storage cases, wrong keys, distinct roles, authenticated legacy migration, rotation, complete attachment framing, ready confirmation and socket replay/tamper tests. Linux/macOS CI also executes the additional Unix-only symlink case. |
| Desktop engine Rust tests | PASS 2 | Includes identity-pinned onion key requests and exact input-size checks. |
| Container | PASS 14 | Includes the normally ignored large-file stream test, final-tag/truncation, malicious paths, scan/signature gates and no publication after failure. |
| Rescue | PASS 12 | Legacy and KCV4 password/recovery-slot export, wrong credentials, explicit plaintext confirmation, no overwrite and input preservation. |
| Verify | PASS 6 | Signature/metadata/time/rollback policy and changed file rejection using synthetic artifacts. |
| App-local signature companion | PASS 11 | Ten unit tests plus independent PyNaCl interoperability. |
| App signature doctests | PASS 3 | Includes seed/key type compile-fail contracts. |
| Shared Windows apps build | PASS 3 | MSG, Container and Rescue compile with zero warnings/errors. |
| WPF session model | PASS | Contact/message isolation, bounds and clearing. |
| C# worker lifecycle and embedded-worker probe | PASS | Cancellation before serialization, size rejection, owned-buffer cleanup and real framed request. |
| Vault origins, roundtrip and legacy share | PASS 4 | Includes nested `blob:` rejection and the final permitted loopback authorization test. |
| Vault stdio bounds integration | PASS 1 | Oversized framed desktop input is rejected. |
| Vault format | PASS 22 | Current and legacy profiles, recovery/re-key, revision/migration, tampering, truncation and source preservation. |
| Firefox channel native unit tests | PASS 3 | Includes the new ABI buffer clearing and invalidation regression. |
| Firefox mocked browser sessions | PASS 6 | Origin, session, navigation and autofill behavior in the existing harness. |
| Local revision cache | PASS 3 | High-water mark, copy/fingerprint and invalid state handling. |
| Mozilla submission adapter | PASS 5 | Existing signing handoff adapter tests. |
| Vault Qt workflow | PASS final run | Pinned Python 3.13.18/Qt 6.10.3. Recovery, migration/re-key, PDF, checksums, browser approvals and the actual local-pipe session probe. Initial sandbox runs exited 1 and are retained as environment failures. |
| Vault to Rescue real-worker interoperability | PASS | All supported profiles, migration/health, key rotation, old snapshots, digest receipts and negative cases using freshly built workers. Sources remain intact. |
| Bundled Tor offline integration | PASS | Identity-bound key creation, rotation, explicit legacy import, cancellation and corruption rejection using temporary test profiles. |
| Messenger WPF with loopback SOCKS | PASS | Actual Rust peers exchange messages/files, reject/block requests, require dangerous-file approval, and close/reopen sessions on locking and identity change. This tests encrypted application traffic locally and does not measure public Tor anonymity. |
| Rust dependency audits | PASS | Core, Core fuzz lock, Apps and fixed Vault lock. RustSec DB revision `c9f6c91a44dbad9d71742329e9df061279f9c4be`. |
| Python dependency audits | PASS | Fixed reference runtime and three pinned Vault GUI requirements. |
| License checks | PASS 4 | Final Core, Vault, Apps and Core fuzz locked graphs. |
| Redacted source/history scans | PASS 6 | Gitleaks 8.30.1 reports zero matches across the three histories and final reviewed source snapshots. A scan finding no known patterns does not prove absence of secrets. |
| Instrumented AEAD and stream fuzzing | PASS on Linux CI | Core review commit `28a4c1d91728516cbd84e5de42f212a5b16f37ce`, job `fuzz`, run `45983294116`. Local WSL/nightly remain unavailable. |
| New Python dependency CI | PASS | The `python-audit` job passed on that same Core review commit. |
| Complete Core CI | PASS | Run `45983294116` completed with 14 successful jobs across Rust/Python, Windows/Linux/macOS, audits, fuzz and artifact comparison. The main-only attestation job is SKIPPED on this review branch. The separate license workflow also passed. |
| Complete Apps CI and native Verify matrix | PASS | Source commit `a035ee3668c06afb6a5c3cee6c1f746db5bc6d63`. Applications CI run `45985145976`, Verify run `45985146038` and source scan `45985146004` completed successfully. |
| Complete Vault CI and desktop matrix | PASS | Source commit `3fd1fe9b2f612757cba0277fb920710b6869e6dc`. Vault CI run `45984534523`, desktop matrix `45984534242` and source scan `45984534225` completed successfully. Main-only Firefox attestation is SKIPPED on this branch. |

Recorded initial failures are not hidden. Sandbox full suites encountered
socket `PermissionDenied`/Windows error 10013, including the legacy Vault
loopback test and MSG socket tests. A blocked run can hang waiting for its peer.
Those runs were stopped and do not establish a product regression or a pass.
After the user resumed work, a separately approved final Windows run executed
the full Apps/Vault Rust suites, the pinned Qt workflow, bundled Tor offline
check and Messenger WPF loopback workflow successfully. The initially
vulnerable dependency audits failed as recorded before the fixes.

Commands and redacted dependency/source reports are retained locally under
`dist/ecosystem-hardening-20261127/` in the outer workspace. Core execution
notes are in `dist/eco-core-security-results-20261127.txt`. Those baseline notes
include the old provider environment. The final Python provider results above
supersede that environment for the changed-source assessment.

## Compatibility and recovery

No encrypted marker, AAD encoding, derivation context, crypto profile or
browser protocol was changed. No automatic data migration or user-data deletion
was performed by this review. Existing KCV1–KCV4, KCC v1, KCMI/KCMB/KCMO and
v5 pairing readers remain selected through their existing paths.

The stricter file checks intentionally reject linked or unsuitable MSG store
leaves that earlier code could accept. A user relying on links needs regular
copies of the identity and encrypted sidecars in a trusted directory. This is
a filesystem policy change, with no rewriting of the encrypted bytes.

Password-only rewrapping does not revoke old snapshots. Existing recovery and
re-key operations retain their documented key lifecycle. Rescue tests confirm
password and recovery-key access to synthetic legacy and KCV4 copies without
modifying originals. Recovery after actual hardware loss and restored OS
profiles remains NOT VERIFIED in this review.

## Remaining risks and next actions

| Priority | Remaining boundary or action | Status |
| --- | --- | --- |
| High | Review branch diffs and run a real signed Firefox installation against the final desktop build. Recheck pairing/navigation and concurrent exact-fill approval across browser processes. Windows Qt, Tor-offline and Messenger loopback checks have passed. | PROPOSED remaining browser installation check |
| High | Review and merge the tested branches only after maintainer approval. Core, Vault and Apps CI have completed, including the new Unix link case and instrumented Core fuzzing. | TESTED source, PROPOSED merge |
| High | Arrange an independent review of Core, format readers, Firefox channel and app memory boundaries before expanding safety claims. | PROPOSED |
| Medium | Treat user-selected output parents as private. Windows staging inherits parent ACLs. Static path checks do not defeat an actor concurrently replacing user-controlled paths. Evaluate handle-relative filesystem operations as a separate platform change. | VERIFIED boundary, PROPOSED follow-up |
| Medium | Managed strings, Qt/.NET/Python buffers, Tor memory, OS swap, dumps, clipboard history, journals and backups can retain plaintext or keys. A Rust-worker session handle could reduce password lifetime but needs its own replacement/recovery tests. | VERIFIED boundary, PROPOSED architecture work |
| Medium | Bound Argon2 concurrency according to process memory. A recoverable reservation failure does not guarantee survival of every OS overcommit or out-of-memory kill. | TESTED narrow cases, VERIFIED boundary |
| Medium | Local revision histories do not provide a trusted monotonic hardware/server counter. Old backups remain readable with their old credentials. | VERIFIED boundary |
| Medium | Keep dependency checks current. Audit tools only find known published advisories. System-linked crypto providers require their own update evidence. | IMPLEMENTED CI, ongoing work |
| Medium | Apps carries a local copy of the optional signature companion. Its implementation matches the current Core companion in this review, apart from comments. Consolidating that companion to an exact shared Git revision would reduce future update drift. | VERIFIED current comparison, PROPOSED consolidation |
| Medium | Validate released bytes, publisher trust and OS code signing separately. Synthetic Verify tests do not attest existing installed executables. | NOT VERIFIED for installed artifacts |
| Medium | Hardware unlock and any general Bridge remain separate opt-in proposals with user approval and recovery. | PROPOSED |

Existing product threat models remain the maintained sources for their own
boundaries. This dated review records evidence and changes, and links to the
separate [Bridge proposal](KRYPTOCORE_BRIDGE_DESIGN.md).

## Final validation

Local final validation passed the full permitted Windows suites, dependency
checks, four license graphs and six redacted source/history scans. The standalone
large-container test and ignored interop/memory cases were run explicitly.
Evidence logs distinguish initial sandbox failures from the later permitted
successful runs.

Review branches use the same name in each source repository. The Core and
Vault commits and the tested Apps source commit are GitHub-verified. Main and
release repositories are unchanged. All eight recorded source workflows have
completed successfully, with 38 successful jobs and two expected main-only
attestation skips. The report-only follow-up does not change the tested source.

- [Core changes](https://github.com/kryptocorelabs/kryptocore/compare/main...codex/ecosystem-security-hardening-20261127)
  and [observed Core CI run](https://github.com/kryptocorelabs/kryptocore/actions/runs/45983294116).
- [Vault changes](https://github.com/kryptocorelabs/vault-source/compare/main...codex/ecosystem-security-hardening-20261127)
  and [observed Vault CI](https://github.com/kryptocorelabs/vault-source/actions/runs/45984534523).
- [Apps changes](https://github.com/kryptocorelabs/apps-source/compare/main...codex/ecosystem-security-hardening-20261127)
  and [observed Apps CI](https://github.com/kryptocorelabs/apps-source/actions/runs/45985145976).

Only the observed per-job outcomes above are evidence of completed remote
execution. Future report-only or other branch runs are separate observations.
