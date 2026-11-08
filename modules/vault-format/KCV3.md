# KCV3 epoch profile — unreleased

This opt-in application format is separate from the minimal Core. Existing
KCV1/KCV2 interpretation and default creation are unchanged. Older readers
reject KCV3; they cannot transparently read a header extension to fixed KCV2.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 5 | ASCII `KCV3` followed by NUL |
| 5 | 16 | Random vault ID, public |
| 21 | 8 | Epoch, unsigned big-endian u64, 1 through u64::MAX |
| 29 | 88 | Existing KCV2 password slot: salt 16, nonce 24, wrapped seed/tag 48 |
| 117 | 88 | Existing KCV2 recovery slot, same layout |
| 205 | 24 | Fresh XChaCha20-Poly1305 payload nonce |
| 229 | remaining | Encrypted payload followed by its 16-byte tag |

The first 205 bytes are payload AAD. Minimum physical size is 245 bytes; the
existing total 4 MiB bound includes the extended header. Entries remain the
same validated JSON login array. No new dependency or primitive was introduced.

Slot wrapping deliberately retains KCV2's exact `KCV2\0 || role` AAD, password
KDF and seed length. The existing `KCV2 payload key` derivation profile is also
retained. This lets a password-authorized upgrade reuse both encrypted seed
slots without knowing/replacing the recovery secret. The new payload binds the
entire new header, including magic, ID, epoch and both slots. It cannot be
reinterpreted as KCV2 without failing authentication.

`enable_epoch_copy` authenticates KCV2 and validates entries, generates a new
ID at epoch 1, then creates a no-clobber destination. It leaves its source
unchanged and retains the seed. It does not make data safe after seed exposure.
Normal writes advance the counter; recovery renewal and password reset preserve
the ID and advance too. Reset also generates a fresh seed and both wrapping
slots. Overflow fails before replacing the source. Backups preserve bytes.

`open_with_revision` returns metadata only after payload authentication. The
caller may supply a remembered `Revision` to checked writes/reset/backup paths;
a different ID, lower epoch or missing revision fails closed. Existing wrapper
APIs remain available without an external minimum. CLI/library callers do not
automatically gain the GUI's local persistent policy.

A counter inside a replayed file cannot establish freshness on its own.
The GUI's separate per-ID high-water mark and path binding detect simple local
rollback/downgrade only while that state is retained and trustworthy. The
read-only Rescue reader intentionally accepts authentic older snapshots.
See [user-facing boundaries](../../apps/vault/EPOCHS.md).
