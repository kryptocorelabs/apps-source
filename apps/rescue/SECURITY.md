# Security

This is a development preview with no independent security audit. Use working
copies, synthetic data when evaluating changes, and independent backups.
Exports are plaintext and may contain every password in a Vault.

Testing to date has been carried out by the KryptoCoreLabs maintainers, locally
and through automated CI. No independent security audit has been completed.
We welcome community testing, code reviews and scrutiny of our security
assumptions. Please use synthetic data and report suspected vulnerabilities
privately through the project's security-reporting channel.

For vulnerabilities use Security → Report a vulnerability in this repository.
If private reporting is unavailable, open an issue requesting a private contact
without disclosing the vulnerability. Include versions, impact and a synthetic
reproduction. Never attach real vaults, identities, credentials or recovery sheets.

See the [Rescue threat model](THREAT_MODEL.md) for credential handling, plaintext
output and the limits of recovery. The [architecture](ARCHITECTURE.md) documents
the worker protocol.
