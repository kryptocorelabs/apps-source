# KryptoCore Container 0.1.0-alpha.2-preview.1

- Add the shared signature companion through a versioned detached KCCS v1 manifest.
- Create password-encrypted `.kcsk` signing keys, share public `KCP1:` codes and produce `.kcsig` files without external OpenSSH tooling.
- Verify signatures in the Windows interface, CLI and protected extraction. Existing OpenSSH options remain available and unchanged.
- Hash the exact stream being decrypted; validate the executable wrapper/footer before scanning or publishing.
- Enforce selected ClamAV scan budgets during extraction and refuse requested scan failures without fallback.

Existing KCC ciphertext remains compatible. Never run an executable wrapper
to establish its own trust: check it with a separate trusted app before
execution, or extract it as data with Rescue. A valid signer can still send
malware. No scanner result certifies safety. The Windows app is unsigned and
has no independent security audit. Use copies and retain backups.
