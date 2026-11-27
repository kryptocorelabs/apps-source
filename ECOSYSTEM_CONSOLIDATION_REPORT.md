# Ecosystem consolidation report

Review date 2026-11-27. Work continues on
`codex/ecosystem-security-hardening-20261127`. This is a maintainer review of
source, tests and available artifacts. Successful automation is not an
independent security audit.

## Mission and scope

One Core. Many Apps. One Community.

KryptoCoreLabs builds an open-source ecosystem around a small Rust cryptographic
library. Applications retain their own formats, storage, permission decisions,
networking and recovery. Local access to a user's data does not require a cloud
account, telemetry or a subscription. Changes must preserve existing data and
make their actual protection boundaries understandable.

| Phase | Result |
| --- | --- |
| A — hardening integration | PARTIAL — reviewed source/regressions passed; real signed-Firefox integration and latest macOS ARM runner gates remain. |
| B — Core security contract | DONE — documented APIs, duties, app matrix and justified profile exceptions. |
| C — everyday Vault use | PARTIAL — extended real-dialog automation passed; clean-PC, second-system, novice and accessibility acceptance remain. |
| D — portable Container | PARTIAL — fresh local EXE, packaged-worker and actual extraction GUI passed; clean-PC and OS-fault tests remain. |
| E — ecosystem presentation | DONE for reviewed branch documentation; public main publication awaits controlled merge. |

The implementation sequence is A, B, C, D, E. Each phase below records completed
evidence and unresolved gates before the next phase is assessed. Missing clean
machines or novice participants cannot be replaced with simulated evidence.

## A. Finish the existing hardening review

**Status — PARTIAL. Source review and existing regression checks passed.
The installed-artifact Firefox gate and latest macOS ARM CI are BLOCKED.**

### Repository and plugin verification

The GitHub plugin is installed and its authenticated login is `kryptocorelabs`.
The connected account can read the repositories and review branches. The
source workspaces were clean at the beginning of this continuation.

| Repository | Remote main | Local and remote review head at start |
| --- | --- | --- |
| kryptocore | `85aaa981be9732869a060fa54a57657e185e66c9` | `28a4c1d91728516cbd84e5de42f212a5b16f37ce` |
| vault-source | `72f43175656b1e4b5e271242eab0148add3895a6` | `3fd1fe9b2f612757cba0277fb920710b6869e6dc` |
| apps-source | `1f49b842814e1bd4fd8d38c8706e40ccaaeedff0` | `bdee6de24b18eb14749c268768d10a8716dc3060` |
| vault | `bea3d97e2a9ef4382088f17f02f62827d2553498` | Release repository, main inspected |
| container | `dc22e7a8a8720ac3824a5bb7c9de7ad255ba0055` | Release repository, main inspected |
| msg | `9e5c96759139006987ae075acb7067b0b0107b1c` | Release repository, main inspected |
| rescue | `0d594d0f52a09ef591a949c35a80ba8d0938cfb4` | Release repository, main inspected |
| kryptocorelabs | `fe8d070270ae523f039a405249d3f3fdcbb5d9ea` | Profile README, main inspected |

Live GitHub comparisons establish that the source review branches are ahead
of main with no commits behind. Core and Vault each contain one review commit.
Apps contains source hardening `a035ee3668c06afb6a5c3cee6c1f746db5bc6d63`
and a report-only follow-up. The hardening is available on GitHub for review,
and has not been merged into main or adopted by an end-user release merely
because the branch exists.

### Technical re-review

| Change | Actual review result | Evidence label |
| --- | --- | --- |
| Core provider/dependency floor | PyNaCl minimum 1.6.2, with isolated dependency audit. Rust cryptographic production behavior is unchanged by the hardening diff. | VERIFIED |
| Argon2 memory behavior | Existing fallible reservation and zeroizing work memory are tested under an isolated Windows commitment limit. Other allocations do not imply universal OOM recovery. | TESTED |
| Vault URL dependency | Minimum and lock use url 2.5.9. Non-HTTP(S) input is rejected before origin lookup. No app-specific nested-blob exploit was demonstrated. | VERIFIED, TESTED |
| Firefox channel ABI | Invalid operations and malformed lengths/frames invalidate channel state and clear the owned buffer. Existing valid frames cannot revive an invalidated channel. | TESTED |
| MSG filesystem hardening | Static link/reparse/non-file rejection and opened-file checks preserve existing encrypted bytes. Trusted parent directories remain necessary because pathname checks do not eliminate races. | VERIFIED, TESTED |
| C# worker metadata | Clearing follows the awaited frame write and also runs on failure. It therefore preserves correct transmission and shortens the owned buffer's lifetime. Managed request strings remain a separate limitation. | VERIFIED, TESTED |

No new source regression was found in the examined hardening diffs. No
encrypted format, context, key schedule or pairing protocol was changed.

Both application workspaces still pin Core
`89abb9bdf8cf4751f718343920abf70c0af8d2eb`, and Apps pins Vault format
`778b7e22c959b5e209a5b97c35f797c6c47faa9f`. The newer Core tests, docs and
Python dependency floor are not silently included in either app by that pin.
Changing those pins needs its own tested, approved target revision.
The direct diff from the pinned Core revision to reviewed `28a4c1d` in
`rust/lib.rs`, `rust/context.rs`, `rust/stream.rs` and the signature
implementation contains documentation and tests, with no Rust production
algorithm/API behavior change. There is no demonstrated need to move the
application pins for this continuation. The Python dependency floor applies
to the separate reference implementation.

### Current CI status

Latest inspected main runs are successful for Core, Apps and the four release
repositories. The profile repository has no Actions workflow. Vault main's
`45984533921` fails `cargo audit --deny warnings` in its dependency job; its
runtime matrix passes. The URL dependency fix is on the reviewed Vault branch,
whose complete `45984534523` run passed. Main does not yet contain that fix.

The connected GitHub tools confirmed completed successful Core and Vault
review runs. The initial Apps source commit also passed its full matrix.
The later report-only Apps commit had two macOS jobs cancelled before any
step ran, with no runner assigned. Other jobs passed. The failed-job retry
was requested through the GitHub plugin without changing the test matrix or
the source. Attempt 2 again cancelled only the macOS ARM jobs before any step
ran. GitHub reports that a hosted runner could not acquire the job after
multiple attempts, with a macOS ARM capacity notice. The latest commit's CI
is therefore **not all green**. It is an infrastructure gate, not a demonstrated
test failure. Windows, Linux, macOS Intel Verify, dependency and Windows GUI
jobs in that attempt passed.

Historical source evidence is the
[hardening report](SECURITY_HARDENING_AUDIT.md). Exact reviewed-source workflow
runs include Core `45983294116`, Vault `45984534523`, Apps `45985145976` and
Verify `45985146038`. Latest Apps retry runs are `45986565718` and
`45986565685` for report commit `bdee6de`.

### Real Firefox integration

**BLOCKED, not run.** Installed Firefox 161 and the local Mozilla-signed 0.1.16
XPI are available. The exact compatible portable Vault EXE is retained in
[Windows build run 42687190479](https://github.com/kryptocorelabs/vault-source/actions/runs/42687190479),
artifact `13703944372`, with expected EXE SHA-256
`92b8e4d7e45cb5291cd8811445488cee0b341acb8ad78c8c0973e7c0c14537d7`.
Its source revision is `890060edc380aaf340c835e16bac7508d0732279` and the
recorded artifact ZIP digest is
`eeadc9875b18479ae18bb28bd79f4cd7261779b9939ca566c027671d5faa5796`.
The signed XPI digest is
`c7b14f08a86aeb84028a3d3e870489fe39876f2c08c095384dbce595532a4df9`.
The local candidate EXEs did not match that digest. Sandbox DNS blocked the
artifact download and the elevated download was aborted. No further download
was attempted. No browser/Vault test process or registry change was made for
this test. Artifact availability online is not a successful installed test.

`vault-source/apps/vault/tests/firefox-release-e2e.py` is the existing real
browser harness for permanent signed installation, pairing, selected-login
approval, origin binding, navigation/tab changes, locking and re-unlocking.
It has **not been executed in this continuation**. Expiry, replay, concurrent
requests and malformed inputs have native/mocked tests, and remain **NOT
VERIFIED through the signed installed artifact**. None of those source tests
is relabelled as live-browser evidence.

### Merge recommendation

Core's reviewed source changes and documentation are candidates for controlled
merge based on their successful source checks. Vault and Apps source hardening
also passed their relevant regression tests, but final integration approval
retains the explicit Firefox and latest macOS ARM gates above. Do not describe
these branches as a newly tested end-user release. Independent documentation
and developer-machine workflow checks continue with those gates recorded.
No automatic merge or release is authorized by this report.

## B. Core security contract

**Status — DONE for the source integration assessment and documented contract.**

[CORE_SECURITY_CONTRACT.md](https://github.com/kryptocorelabs/kryptocore/blob/codex/ecosystem-security-hardening-20261127/CORE_SECURITY_CONTRACT.md)
documents actual API inputs/results, ownership, typed errors, nonce/salt
generation, expected contexts, key separation, wrapping, streaming publication,
Rust and managed-memory limits, process trust and optional signatures. Core's
README and profile specification link to it.

The contract's matrix assesses Vault, Firefox, Container, MSG, Rescue, Verify
and the Python reference against actual code and existing tests. Compatible
legacy derivations and context bytes remain explicit exceptions. Source
mechanisms and installed artifact verification are separate evidence. The
existing tests cited in Phase A exercise the relevant success and negative
paths. The documentation adds no runtime change or dependency.

No additional proven contract deviation requiring a production patch was
found in this review. Core's optional APIs are not all implemented by the
Python reference, which is an interoperability reference, not a Rust memory
ownership substitute. Apps still contains its own signature companion copy.
These limits are recorded rather than disguised as full uniformity.

An app-owned format using established RustCrypto streaming or Snow transport
is not a reason to move those responsibilities into Core. No demonstrated
need for another common cryptographic envelope was found. Local Markdown
links and `git diff --check` passed. Artifact-specific and clean-platform
checks remain in their own phases.

## C. Vault everyday workflow

**Status — PARTIAL. Developer-machine workflow passed; clean-system and
inexperienced-participant acceptance remain BLOCKED.**

`vault-source/apps/vault/tests/desktop-workflow.py` now exercises the actual
create/edit dialogs rather than inserting its first login directly through
the worker. The added regression checks generated-password reveal/hide,
saved-login creation and editing, retaining a password when its replacement
is empty, case-insensitive host/username search, no-match feedback and
cancellation preserving the file. No production UI or cryptographic behavior
was changed.

The complete updated harness passed on this Windows developer machine with
Python 3.13.18 and PySide6/Qt 6.10.3. Its native worker SHA-256 is
`5eaaad96ce51fdd8835183fe51f3d432430b5bc3476ee7aaca6de5e60aee32f7`.
The sandbox attempt reached the final Named-Pipe test but was denied OS access.
The same isolated harness was then completed outside that restriction with
exit 0. Local evidence is
`dist/ecosystem-hardening-20261127/vault-workflow-phase-c-root.log`.

Passing checks also include setup cancellation without creating files,
recovery-sheet save/recovery, epochs and rollback warnings, migration and
health, backup/source preservation, password/key rotation, PDF recovery-sheet
replacement, SHA-256 comparison/no-clobber and exact-origin one-use desktop
bridge approvals including denial, expiry, key change and lock. These bridge
tests are not the installed Firefox test blocked in A3.

`vault-source/apps/vault/USAGE.md` now starts with the real German control
labels in an English walkthrough and uses matching labels for migration,
status and password/file checks. The documentation avoids calling the preview
a release candidate.

The harness uses offscreen Qt, synthetic data, controlled file-dialog replies
and an isolated profile. It does not prove clean-PC download/start usability,
keyboard-only completion, real screen-reader announcements, contrast/DPI
acceptance, second-machine restoration or novice independence. Error labels
and password-strength changes have no verified screen-reader announcement.
These are explicit remaining acceptance checks, not reasons to remove security
approvals or redesign the app without evidence.

## D. Container self-extracting EXE

**Status — PARTIAL. Current local build, isolated packaging check and real
self-extracting GUI workflow passed. Clean Windows, disk-full and forced
termination acceptance remain NOT VERIFIED.**

The optional EXE is an existing requested function. `pack_executable` appends
an unchanged KCC payload and a bounded length/marker footer to the opener.
The ordinary `.kcc` format remains supported. No format or production code
change was required.

A fresh offline SingleFile build from Apps baseline `bdee6de` used cached
.NET SDK 10.0.301/runtime 10.0.9 and the current Rust worker. This is a local
validation build, not the release-pinned CI toolchain or a reproducible-build
claim. The existing `apps/desktop/tests/check-portable.ps1` passed with exit 0.
It copied the EXE alone, checked its x64 GUI subsystem, isolated writable
directories, removed developer runtimes from PATH and exercised its embedded
worker. Its report explicitly keeps `clean_windows_vm_tested=false`.

| Local validation artifact | SHA-256 |
| --- | --- |
| Container opener EXE | `07f5b91476681107ab8ae7b91ed9072892e7c9b48e94cd45be036c931130aec0` |
| Rust desktop worker | `f24a9329bfd5b0229c03567d1396244d9eb6a89cb8e32ae3e7d0a0bf7e95d153` |
| Generated synthetic self-extracting EXE | `4de8cfc5f8f7989decbbcceb8b7b6b9b49e151cff8df1f0e9257ffcd2744a374` |
| Normal synthetic KCC archive | `5459f22a993d5a64e7a78c5b83f52a5fedf4e8dd2dd4009f3058e9592621a0a2` |

The actual generated EXE was opened through its Windows interface. Wrong
credentials produced the generic passphrase/damage error and no output
directory. The correct synthetic passphrase and Enter extracted seven entries,
2,816,233 bytes. All five file digests, including an empty file, a Unicode path
and a multi-chunk file, matched the originals. A harmless contained `.cmd`
was not executed. The EXE bytes stayed unchanged and its window was closed.

Worker-level checks also passed for ordinary KCC, wrong password, existing
output preservation, existing EXE preservation, truncated footer/payload,
invalid footer length/marker and modified authentication tag. Failed checks
did not publish a destination. These complement the existing Rust
`executable_payload_round_trip_rejects_modified_content_and_footer` and
staging/no-clobber tests rather than claiming an exhaustive OS-failure test.

Local evidence is under `dist/consolidation-container-20261127/` in
`build/verification/container.json`, `sfx-worker-report.json` and
`sfx-gui-report.json`. No artifact was copied into a release directory or
uploaded as a new download.

### Distribution boundary

The KCC authentication check protects the encrypted payload under its key. A
publisher/sender signature or independently obtained digest authenticates
specific file bytes only when the expected signer/digest is trusted. The
generated EXE differs from the published opener, so the opener's digest alone
does not verify the generated file. Verify the entire generated EXE before
launch in a separate trusted tool/channel. Its own later checks cannot undo
already executing an untrusted program. Neither encryption nor a signature
establishes malware freedom or Windows Authenticode trust.

The EXE remains a supported optional Windows convenience, with `.kcc` retained
for data-only exchange. A second clean Windows machine, storage exhaustion,
forced termination, real malware-scanner behavior and SmartScreen/enterprise
policy acceptance were not tested. No global policy, runtime installation or
security approval was weakened to obtain the passing local results.

Extraction currently has no cooperative cancel control and prevents closing
the window while it runs. That observed UI limit is recorded in
[the portable review](apps/container/tests/PORTABLE_REVIEW_2026-11-27.md).
Forced process termination is not a tested substitute. A cancellation change
would need worker/staging cleanup tests before adoption.

## E. Ecosystem presentation

**Status — DONE for review-ready English documentation. Public main publication
awaits controlled merge.**

The Labs profile now introduces the entire ecosystem with **One Core. Many
Apps. One Community.**, followed by a seven-project table, actual platform/setup
requirements, previews/experimental status, synthetic demos and contribution
routes. It distinguishes the Core from app formats, Snow and Tor. The current
Vault ZIP still requires Python setup, Firefox pairing is Windows-only, MSG
requires both peers online and Verify requires an independently trusted key.

Core's README and `PROJECT_CHARTER.md`, the Vault source README and Apps source
README use the same mission. User control, optional funding and the absence of
mandatory cloud/accounts/subscriptions/telemetry do not become unsupported
security guarantees. Testing remains maintainer/CI evidence, with no independent
audit completed. Authenticode, publisher manifests and Mozilla signing are
described as separate distribution checks.

Apps now lists Rescue preview.4 and distinguishes MSG's desktop package version
from its older Rust CLI crate version. Container's source and release READMEs
explain its supported optional EXE and whole-file pre-execution trust boundary.
`.kcc` remains supported. Existing build/contribution/security guides remain
the starting points, with private vulnerability reporting separated from public
synthetic bug reports. No new app, envelope, service or Bridge was introduced.

Local Markdown destination/whitespace checks passed. The Container release
repository's existing `python tools/check_release.py` also passed without a
new download. Link inspection includes local mirrors; it is not a fresh
download/installation test of every release asset.

Profile and Apps repository descriptions were updated and re-read through
GitHub (**VERIFIED**): the former introduces the ecosystem, and the latter
includes Verify. Core and the other descriptions/topics were already accurate
and were preserved. Main refs were checked before and after and did not move.
The metadata record is `dist/ecosystem-hardening-20261127/consolidation-metadata.json`.

## Overall handoff

### Changes and actual execution

This continuation adds the Core contract, three dated review/report documents,
the bounded Vault editor/search regression and targeted English documentation.
There is no new production-code change beyond the previously reviewed hardening
in Phase A. No cryptographic algorithm, AAD, key schedule, file format or pairing
protocol changed. No dependency pin was moved and no recovery path was removed.

| Environment | Evidence and limit |
| --- | --- |
| Local Windows x64 | Updated offscreen Qt workflow, actual Rust worker, fresh self-contained Container build, isolated packaged-worker probe and real generated-EXE extraction GUI passed. This is the developer host. |
| GitHub Windows/Linux/macOS | The exact Phase-A source runs cited above passed the applicable Rust/interop/platform matrices. Latest doc/test follow-ups trigger new checks; their live status must be consulted before merge. |
| Latest macOS ARM jobs | The Apps report follow-up failed twice before steps ran because no hosted runner acquired the jobs. No test was disabled or runner target removed. New follow-ups may also remain queued. |
| Real signed Firefox/Desktop pair | BLOCKED on obtaining the exact matching local artifact; mocked/native tests retain their own narrower labels. |
| Clean Windows and second recovery PC | NOT VERIFIED; no separate clean system was established. Isolating PATH on a developer host is not a clean-system test. |
| Novice and accessibility acceptance | NOT VERIFIED; no real novice study, keyboard-only/assistive-technology acceptance or measured contrast/DPI evaluation was performed. |

The documentation records the start-of-review source commits and exact local
artifact digests. Subsequent GitHub-signed commits keep those code baselines
traceable. Commit identity for this report is its containing Git commit; final
branch heads and live workflow checks are exposed by the review PRs. CI facts
above are observations at the review cutoff, not a claim that an unobserved
future run has succeeded.

### Remaining risks and acceptance work

- Complete A3 using the exact matched desktop artifact and signed XPI. Add
  installed-artifact expiry/reuse/concurrency/malformed-message coverage before
  claiming those properties as live-browser verified.
- Resolve the macOS runner gate and require actual successful final checks.
  Core and Vault source follow-ups also have macOS ARM checks queued at the
  current observation; successful earlier source runs do not make them green.
- Run the documented first-use, backup/recovery and portable-extraction paths
  on clean target systems and with available novice/assistive-technology users.
  Exercise storage exhaustion and interrupted extraction without risking real
  user data. Cooperative extraction cancellation remains proposed.
- Managed GUI/runtime copies cannot be reliably zeroized. Unlocked endpoint
  compromise, local same-user bridge/key access and already delivered plaintext
  remain threat-model limits. Local revision history is not a global rollback
  authority, and old authenticated snapshots retain their old credentials.
- Windows Authenticode and independent external audit remain outstanding.
  Local Container bytes are not a reproducible or newly signed release.
  Existing publisher manifests and build attestations have their own documented
  scope. Apps' signature-companion source copy still needs coordinated review.

No newly demonstrated production vulnerability was found in this continuation.
Missing evidence is not reported as a proven exploit or a successful test.

### Controlled integration recommendation

1. Review the existing source hardening together with these contract/test/docs
   additions. Merge Core before the profile, because the profile links to its
   new contract on main. Keep pinned application Core/format dependencies until
   a distinct dependency change has its own reviewed target and tests.
2. Treat Vault/Apps source checks as passed only at their recorded revisions.
   Require the final branch checks and retain the installed-Firefox gate in the
   integration decision. Metadata/doc cleanup is independently reviewable.
3. Preserve the current previews and exact distributed hashes. A future release
   needs the matched installed-browser test, clean-target acceptance, the pinned
   build/provenance process and explicit signing scope. No release is created
   by publishing these review branches.

All changes are prepared on isolated `codex/` branches. Main refs and public
download assets remain unchanged. This handoff does not authorize an automatic
merge, destructive migration or new release.
