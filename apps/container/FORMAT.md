# KCC v1 format (alpha)

All numbers are unsigned and big endian. Readers reject other versions.
This version is separate from KCV2 and the KryptoCore library version.

| Header field | Bytes |
| --- | ---: |
| Magic and version: `4b 43 43 00 00 00 00 01` | 8 |
| Random Argon2 salt | 16 |
| Random STREAM nonce prefix | 19 |
| Random key-wrap nonce | 24 |
| Encrypted 32-byte content key and Poly1305 tag | 48 |

The key-wrap key is KryptoCore Argon2id v19, 256 MiB, three iterations, one
lane, 32-byte output. The password is the UTF-8 byte sequence as supplied
without normalization. KryptoCore wraps a fresh random content key with
XChaCha20-Poly1305 and authenticates the first 43 header bytes as associated
data. The nonce and the wrapped value are validated by AEAD decryption.
The profile is fixed; the file cannot request larger Argon2 allocations.

The payload uses RustCrypto [STREAM BE32](https://docs.rs/aead/0.5.2/aead/stream/).
Each frame starts with a one-byte type and a four-byte plaintext length.
These five bytes are associated data, followed by ciphertext with a 16-byte
tag. The per-frame nonce is the 19-byte prefix, zero-based 32-bit counter,
and a one-byte last-frame flag. Frame types:

- `01`: Entry. Plaintext is one byte for kind (0 file, 1 directory), eight
  bytes for file size (zero for a directory), then the UTF-8 relative path.
  Parents must be explicit and precede their children.
- `02`: File data. Each file has as many 64 KiB chunks as needed, with one
  shorter chunk if needed. No chunks are emitted for an empty file.
- `03`: Final authenticated frame. Length zero. EOF must immediately
  follow its tag; trailing data, truncated streams and empty archives fail.

The reader validates sizes before allocating or writing and rejects links,
device names, traversal, unsafe path characters, and case-folded duplicates.
The output filesystem can reject further aliases. No ownership, permissions,
timestamps or executable bits are restored. Archive totals are capped at
10,000 entries, 1 TiB of content, 32 path components and 512 UTF-8 bytes per path.

The optional detached OpenSSH signature uses namespace
`kryptocore-container-v1-sha256`. The signed message is exactly the 64
lowercase ASCII hexadecimal digits of SHA-256 over the entire KCC file,
without a newline. Signer trust is configured independently of the archive.
The same bytes are hashed and decrypted during signed extraction.

Threats in scope include copied archives, offline guessing, malicious file
paths, truncation and modification in transit. Passphrase entropy determines
resistance to offline guessing. The tool assumes a trusted OS, tools, and
private local directories. It does not prevent resource exhaustion from
large valid archives or many concurrent operations. Extraction uses a
private staging folder and reserves a new destination only after
authentication, optional signature verification and optional inspection.
Moving multiple authenticated roots is not a single atomic operation: a
crash at this stage may leave part of an authenticated export. No
independent security audit or stable compatibility promise exists yet.
