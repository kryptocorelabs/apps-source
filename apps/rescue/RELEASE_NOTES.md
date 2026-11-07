# KryptoCore Rescue 0.1.0-preview.2

First downloadable recovery preview, extending the earlier marker-only prototype.

- Authenticate KCV1/KCV2 Vaults and export validated records to a new JSON file.
- Use the original password or an existing KCV2 recovery slot without resetting the source password.
- Extract ordinary and executable-wrapped KCC containers using the existing stream reader.
- Require plaintext-output confirmation and a fresh destination; clear credential input after use.
- Keep diagnostic reports metadata-only and clearly unauthenticated.

The output is unencrypted. Existing files and directories are not overwritten.
MSG files can only be recognized; MSG decryption and recovery are not implemented.
No sender-signature verification or malware scan is performed. The executable
is unsigned; independent review is pending. Use copies and retain backups.

SHA256SUMS.txt identifies the published bytes. RELEASE_MANIFEST.json records
the private source revision, toolchain and test scope. Checksums are not a
substitute for obtaining software and expected hashes through a trusted route.
