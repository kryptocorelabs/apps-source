# Verify threat model

This document describes the verifier at this source revision. The verifier
requires an independently trusted release key, a trusted copy of the verifier
and an accurate local clock.

| Threat | Protection and boundary |
| --- | --- |
| Changed download, manifest or product selection | Verify authenticates the exact manifest bytes under the selected key and checks the expected product, version, target, filename, length and SHA-256. It treats the file as data. |
| Substituted trust root or compromised release key | The publisher key is supplied separately. A party with that private key can authorize bytes under it. Use the project's separately authenticated key records and incident instructions. |
| Older valid release or expired metadata | Verify checks the signed validity interval. A trusted minimum sequence can reject earlier entries. The caller must learn current policy separately. |
| Hostile executable or local replacement | A valid manifest identifies bytes the selected publisher authorized. Malware detection, OS code signing and replacement after verification are separate concerns. |

The signing command uses a dedicated password-protected key file. A signing
machine that is already compromised can expose the unlocked key. Verify has
no independent security audit.

[ReleaseManifest wire protocol](PROTOCOL.md) · [Security policy](../../SECURITY.md)
