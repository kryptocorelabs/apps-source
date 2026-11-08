# Check a download before opening it

A checksum detects a mismatch. A **signed release manifest** also binds those
bytes to a publisher key you already trust. It does not prove that the program
is bug-free, malware-free or the latest release.

**Current status:** Verify is implemented and tested. KryptoCoreLabs has not yet
provisioned its permanent public release-signing key or published matching
ReleaseManifest signatures. Existing `SHA256SUMS.txt` and `RELEASE_MANIFEST.json`
files are not automatically signed. A Mozilla-signed Firefox XPI is a separate
mechanism. Do not treat these files as KryptoCore release signatures until the
key and signature pairs below have actually been published.

## The short version

1. Obtain [KryptoCore Verify](https://github.com/kryptocorelabs/apps-source/tree/main/apps/verify)
   through a trusted route, or build it from a reviewed source revision.
2. On the chosen GitHub release, download the archive and its matching
   **`<archive-name>.release.json`** and **`<archive-name>.release.sig`** files.
   Keep the download's original filename. If either signature file is missing,
   this verification route is not available for that asset.
3. Confirm the publisher's full `KCP1:` public key through an independently
   trusted route. A key bundled with an untrusted download does not establish
   whose key it is. Never supply a password or private signing key to check a file.
4. Run the check below using the product, version and target you intended to
   download. Continue only if Verify exits successfully and prints `VERIFIED`.
   A rejected check means stop, preserve the files for diagnosis and recheck the
   source; do not disable the check to make the download open.

### Windows PowerShell example

From the folder containing Verify and the three downloaded files:

```powershell
$KryptoReleaseArchive = 'KryptoCore-Rescue-0.1.0-preview.3-windows-x64.zip'
$KryptoPublisherKey = 'KCP1:REPLACE_WITH_THE_FULL_TRUSTED_PUBLIC_KEY'
.\kryptocore-verify.exe check $KryptoReleaseArchive "$KryptoReleaseArchive.release.json" "$KryptoReleaseArchive.release.sig" --key $KryptoPublisherKey --product rescue --version 0.1.0-preview.3 --target windows-x86_64
```

This is a command template, not a claim that the signature files already exist.
Replace the placeholder with the complete trusted public code. For another
download, use its exact three filenames and expected metadata. Do not choose
the expected version merely by copying an untrusted manifest's contents.

On Linux/macOS, use `./kryptocore-verify` with the same arguments and ordinary
relative paths. Target names are `linux-x86_64`, `macos-x86_64`,
`macos-aarch64` or `windows-x86_64`; Firefox XPI manifests use `firefox`.
Verify can check an archive for another OS without running it.

## What the result means

Verify checks the purpose-bound signature, expected product/version/platform,
filename, exact size and SHA-256, plus the signed validity period. Keep the
system clock correct. `--min-sequence` can enforce a minimum learned through a
trusted route; it does not automatically discover the latest release.

`VERIFIED` means the checked bytes match the selected key and metadata. It does
not replace Windows Authenticode, SmartScreen, Apple notarization or an audit.
Files can still be replaced after checking. A signature added to a historical
preview does not patch it or remove its documented security limits.

[Detailed protocol](https://github.com/kryptocorelabs/apps-source/blob/main/apps/verify/PROTOCOL.md)
· [Security in 30 seconds](https://github.com/kryptocorelabs/kryptocore/blob/main/SECURITY-IN-BRIEF.md)
