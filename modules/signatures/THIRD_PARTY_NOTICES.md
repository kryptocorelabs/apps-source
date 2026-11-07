# Signatures companion third-party notices

Snapshot: 2026-11-07, `kryptocore-signatures 0.1.0-preview.1`.
The KryptoCore companion's own source is covered by the workspace's
[MIT license](../../LICENSE).

[DEPENDENCIES.tsv](third-party/DEPENDENCIES.tsv) records the exact resolved
direct and transitive versions, registry checksums, license expressions,
upstream URLs and original notice files. It includes all-target, build and
development dependencies reachable from the companion in the workspace's
locked Cargo metadata, with workspace feature unification. Target-only and
development packages are recorded for completeness; they are not necessarily
linked into a particular release binary.

`ed25519-dalek 2.2.0` is BSD-3-Clause, copyright 2017–2019 isis agora
lovecruft. Its original notice is in
[LICENSE](third-party/licenses/ed25519-dalek-2.2.0/LICENSE).
Other components and their notices are listed in the inventory; preserve
those original files when distributing a binary that incorporates them.
Choose a permitted option for OR expressions; retain all required notices for
AND expressions. The current graph uses permissive options allowed by the
workspace `deny.toml`; this snapshot does not introduce a copyleft source-offer
requirement. This is a dependency review, not legal advice for every distribution.

Build toolchains and linked system runtimes are separate from this crate
inventory. Applications must include their applicable runtime notices in
their own release packages. A Cargo lockfile may also contain optional
packages not selected in this reachable graph; the full workspace lockfile
is separately checked by the security workflow.

Refresh after dependency changes:

```sh
python modules/signatures/update_notices.py
cargo deny --locked check --config deny.toml licenses
cargo audit --deny warnings
```

The refresh uses cached Cargo packages and copies original upstream license
files without editing them. Review inventory and lockfile changes before release.
