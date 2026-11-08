# KryptoCore Container signatures, version 1

Container 0.1.0-alpha.2-preview.1 and Rescue 0.1.0-preview.3 use the optional
KryptoCore Signatures companion for detached sender checks. KCC v1 ciphertext
and legacy OpenSSH signatures are unchanged. The companion is independent
of the encryption Core. Existing files can still open without a sender check;
an explicitly requested failed check never falls back to unchecked extraction.

## Use on Windows

1. In Container, open **Signaturen** and create a password-protected `.kcsk` key.
   Keep that file and its password private, with a separate protected backup.
2. Share the displayed `KCP1:` public code through an independently trusted
   channel. The recipient must confirm whose key it is. A bundled public code
   must not automatically become trusted.
3. Sign the completed `.kcc` or executable export, producing a new `.kcsig`.
   Transfer the container, detached signature and separately shared passphrase.
4. In Container's extraction options or Rescue's **Absender & Malware-Prüfung**,
   enable the sender check, select the signature and paste the expected code.
5. Optionally select a trusted local `clamscan` executable for a separate scan.

A self-opening EXE has already executed by the time its own window appears.
Verify EXE signatures with a separate trusted app **before starting the EXE**,
or extract it as data using Rescue. A signature does not prove the recipient
program is genuine, the signer is a particular person, or the contents are
free of malware. A signer or compromised signing key can sign harmful files.

## Public code

`KCP1:` followed by the hex encoding of a 32-byte Ed25519 verification key.
The formatter emits lowercase hex; the parser accepts either hex case and
trims surrounding whitespace. The prefix is case-sensitive. Only canonical,
non-identity prime-subgroup keys accepted by the companion are supported.
Signing keys are independent of encryption keys and MSG X25519 identities.

## Password-protected key file (.kcsk)

| Field | Bytes |
| --- | ---: |
| `KCSK 00 00 00 01` | 8 |
| Fresh random salt | 16 |
| XChaCha20-Poly1305 nonce | 24 |
| Encrypted 32-byte Ed25519 seed, including 16-byte tag | 48 |

Exactly 96 bytes. Argon2id v19 uses the existing Core profile: 256 MiB, three
passes, one lane, 32-byte output. Passwords are exact UTF-8 without normalization.
Key generation requires at least 15 characters and at most 1,024 UTF-8 bytes.
The 24-byte magic/version-plus-salt prefix is authenticated associated data.
Seed and derived-key buffers use the existing zeroizing types. A lost key or
password cannot be bypassed. Owned-buffer clearing does not guarantee erasure
of caller copies, registers, swap, crash dumps or compromised process memory.

## Detached signature (.kcsig)

| Field | Bytes |
| --- | ---: |
| `KCCS 00 00 00 01` | 8 |
| Kind: `01` ordinary KCC, `02` executable wrapper | 1 |
| Exact complete source-file length, u64 big-endian | 8 |
| SHA-256 of every byte of that source file | 32 |
| Detached Ed25519 signature | 64 |

Exactly 113 bytes. The 49-byte prefix is passed as the message to the shared
companion with `Purpose::ContainerManifest` (`container-manifest/v1`). Its
versioned framing is defined in the public companion README. This is pure
Ed25519 over that framing, not Ed25519ph, OpenSSH, arbitrary JSON or a signature
over unspecified digest text. The signature contains **no trusted public key**.

Ordinary files and wrapped executables are bounded to 2 TiB of encrypted input.
For executable exports, the digest includes the opener, encrypted payload and
footer. Changing any part invalidates the check. During protected extraction,
the reader hashes the same stream it decrypts and validates the hashed footer;
it does not verify one path and later reopen that path for decryption. Only
after all content and signature checks succeed does the scan callback run,
followed by publication to a new destination. Use stable sources and trusted
input/output directories; this is not an immutable filesystem snapshot.

The public test vector `native-v1.txt` uses RFC 8032 TEST 1's published key and
independent PyNaCl framing. It signs deliberately invalid marker-only ciphertext:
signature verification succeeds, while password-based opening must fail.
Never use this public test key as an application signing identity.

## CLI

```text
kryptocore-container keygen new.kcsk
kryptocore-container key-public new.kcsk
kryptocore-container sign-native archive.kcc new.kcsk archive.kcsig
kryptocore-container verify-native archive.kcc KCP1:EXPECTED_HEX archive.kcsig
kryptocore-container unpack-native archive.kcc new-folder KCP1:EXPECTED_HEX archive.kcsig --scan /absolute/path/to/clamscan
```

Passwords are prompted, never command-line arguments. Omit `--scan` only when
you deliberately choose not to request a malware scan. Local signing/encryption
does not provide revocation, expiry, global identity verification or replay policy.
