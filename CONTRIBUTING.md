# Contributing

Code, tests, documentation, accessibility work and independent review are welcome.
Read the [project charter](https://github.com/kryptocorelabs/kryptocore/blob/main/PROJECT_CHARTER.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

1. Open an issue for a reproducible bug or discuss a proposed design change.
   Use synthetic data; vulnerabilities go through [SECURITY.md](SECURITY.md).
2. Fork this repository, clone your fork and create a focused branch.
3. Follow the root README to build and test. Keep lockfiles and notices consistent
   with any dependency changes. Windows UI changes also need normal/minimum-size
   and keyboard checks.
4. Open a pull request explaining the problem, change, verification and any
   compatibility/security impact. Do not claim checks you did not perform.

Changes to cryptographic integration, keys, file formats or browser/session
authorization need a documented threat analysis, failure tests and a compatibility
plan. Seek independent review; disclose when it is still missing. Coordinate
changes to mirrored Core/shared modules with their canonical upstream.

Contributions to first-party code are provided under the repository's existing
MIT license. Retain third-party copyright and license notices. Do not add private
credentials, real user files or production signing material.
