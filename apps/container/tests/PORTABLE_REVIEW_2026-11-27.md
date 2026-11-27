# Container portable and self-extracting EXE review

Status: **PARTIAL**. The current source build and the actual self-extracting GUI
passed the checks below on the development Windows host. A second, clean Windows
system was not available. This is a maintainer test, not an independent audit or
a novice-user study.

## Tested source and build

- Apps source revision: `bdee6de24b18eb14749c268768d10a8716dc3060`.
- Container package version: `0.1.0-alpha.2-preview.1`.
- Local SDK: .NET `10.0.301`; cached Windows x64 runtime packs: `10.0.9`.
- Build: `apps/container/build-windows.ps1 -Offline -OutputDirectory <fresh-output>`.
- Output was kept separately under the workspace's
  `dist/consolidation-container-20261127`; published release files were unchanged.
- This used the existing local toolchain. It was not the separately pinned
  release-build environment and does not establish binary reproducibility.
- `Get-AuthenticodeSignature` on the local opener returned `NotSigned`.

| Artifact | SHA-256 |
| --- | --- |
| Built `KryptoCore-Container.exe` opener, 68,143,647 bytes | `07f5b91476681107ab8ae7b91ed9072892e7c9b48e94cd45be036c931130aec0` |
| Embedded Rust desktop worker | `f24a9329bfd5b0229c03567d1396244d9eb6a89cb8e32ae3e7d0a0bf7e95d153` |
| Generated synthetic `Delivery.exe` | `4de8cfc5f8f7989decbbcceb8b7b6b9b49e151cff8df1f0e9257ffcd2744a374` |
| Generated ordinary `Delivery.kcc` | `5459f22a993d5a64e7a78c5b83f52a5fedf4e8dd2dd4009f3058e9592621a0a2` |

The generated archive and EXE have independent random encryption material, so a
repeat of this test produces different archive hashes. These are test evidence,
not release hashes or a public trust anchor.

## Checks executed

`apps/desktop/tests/check-portable.ps1` ran automatically after publishing and
returned **PASS**, exit 0. It copied the EXE alone into a fresh directory,
verified its x64 GUI PE header, masked installed runtime/tool locations, isolated
temporary and app-data directories, and executed `--verify-package`. The packaged
Rust worker generated a passphrase successfully. No sidecar appeared beside the
EXE and its hash remained unchanged. Its JSON explicitly records
`clean_windows_vm_tested: false`.

The local synthetic worker harness exercised the same pack/unpack requests used
by the GUI. All recorded checks passed:

- Create an executable container using the freshly built opener.
- Refuse to overwrite an existing executable and preserve its hash.
- Create and authenticate an ordinary `.kcc` file.
- Reject a wrong password without publishing a destination.
- Preserve an existing destination and its sentinel file.
- Reject truncated footer, truncated payload, invalid footer length, modified
  footer marker, and modified payload tag without publishing a destination.
- Preserve the source EXE and avoid executing an archived script.

An actual Windows GUI test then launched the generated `Delivery.exe` through
Computer Use. It recognized its embedded archive and displayed the extraction
screen with a focused password field. A wrong synthetic password produced
`Passphrase falsch oder Container beschädigt.`; no destination existed afterward.
After entering the correct password, the Enter key initiated extraction. The GUI
reported seven entries and 2,816,233 bytes, with sender verification and malware
scanning explicitly identified as not requested.

SHA-256 comparison confirmed all five files: a text file, an empty file, nested
Unicode text, a file spanning several encryption chunks, and a harmless script.
The script's execution marker was absent. The source EXE remained unchanged and
the test window was closed. No contained file was opened through the GUI.

The file-selection and EXE-creation steps used the real Rust worker rather than
automating native file dialogs. The ordinary `.kcc` GUI path was not repeated in
this run. Local evidence is in `sfx-worker-report.json`, `sfx-gui-report.json`, and
`build/verification/container.json` under the separate test-output directory.
Those local fixtures include only synthetic data and were not added to Git.

## Implementation examined

- `apps/container/windows/ExecutableContainer.cs` recognizes the existing
  `KCC-WIN64-EXE-v1` footer; `apps/container/src/lib.rs` bounds its payload length
  and reads the existing KCC payload format. No format change was introduced.
- Packing writes a same-directory temporary file, flushes and syncs it, and uses
  `persist_noclobber`. Extraction stages authenticated contents privately and
  checks the final authenticated record and EOF before publication. Existing
  destination paths are refused. Windows staging inherits parent permissions;
  Unix staging uses mode 0700.
- Embedded mode exposes extraction and checking. It never automatically starts
  an archived document or program. Opening the resulting folder is a separate
  explicit action.
- `Shell.Run` disables navigation during extraction and prevents closing the
  window while the operation runs. This extraction path has no cancel button.
  External termination and I/O-failure behavior require the separate tests below.
- The existing Rust regression
  `executable_payload_round_trip_rejects_modified_content_and_footer` covers the
  same SFX compatibility boundary. Other container regressions cover authenticated
  staging, reordered chunks and scan failure. This review's worker checks add
  current-build evidence without changing production code.

## Trust boundaries and remaining gates

The EXE must be trusted **before it is executed**. Archive authentication detects
incorrect credentials or encrypted-payload manipulation; it does not establish
that the executable opener is safe. A sender signature or a trusted digest can
identify exact EXE bytes. Neither is a malware guarantee or an Authenticode
signature. A verification option inside an already running EXE cannot establish
the safety of the code that has already started.

The ordinary `.kcc` file remains supported. The self-extracting EXE remains an
optional Windows convenience path with the same encrypted KCC payload.

The following are **NOT VERIFIED** by this review:

- Transfer and full operation on a separate clean Windows installation without
  preinstalled developer tools or runtimes.
- Real disk-full and quota-exhaustion faults, abrupt termination during packing
  or extraction, and cleanup after those faults.
- Native file-dialog usability, inexperienced-user completion, screen readers,
  and all display-scaling combinations.
- SmartScreen reputation, Authenticode signing, sender-signature workflow, and
  external malware-scanner integration in this particular generated EXE.
- Reproducibility of the local single-file bytes.

The bounded host tests passed and found no production-code change necessary.
The outstanding environment and fault-injection gates prevent a general claim
that all portable Windows targets have been validated.
