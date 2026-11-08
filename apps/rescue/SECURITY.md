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

Successful password authentication does not verify a person's identity or prove
file safety. Rescue does not offer a universal recovery key or damaged-tag bypass.
See [architecture and limits](ARCHITECTURE.md). Independent audit and Windows
code signing remain pending; no absolute security or recovery promise is made.
