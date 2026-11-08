# KryptoCore Rescue 0.1.0-preview.3

- Verify shared KryptoCore `.kcsig` sender signatures for ordinary and wrapped KCC files with a separately trusted `KCP1:` public code.
- Hash the same stream being decrypted, including the executable wrapper/footer. Invalid requested signatures block both scanning and publication.
- Add optional local ClamAV scanning before export, including Vault JSON. Detection, scanner errors, timeout and unsupported bounds block output.
- Bound KCC plaintext to 400 MiB when scanning is requested; scan limits are 100 MiB per file and 400 MiB total.
- Display content authentication, selected-key signature verification and scan state separately. No automatic opening or execution.

KCV1/KCV2 and KCC bytes remain unchanged. Sources and existing destinations
are preserved. Vault password/recovery exports continue to work. Output is
plaintext; choose a protected destination and retain backups. MSG recovery
remains unimplemented. The app is unsigned and independently unaudited.
Scanner process-control tests use deterministic surrogates and do not measure
real ClamAV detection efficacy. ClamAV and its current database are external.
