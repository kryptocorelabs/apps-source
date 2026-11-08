# Verify third-party notices

First-party code is MIT licensed. Verify uses the Core and optional Signatures
module without modifying their cryptographic primitives. Resolved direct and
transitive Rust versions, checksums, license expressions and upstream notices
are recorded in [the dependency inventory](third-party/DEPENDENCIES.tsv).
Keep the referenced original notice files with redistributions.

The workspace Cargo.lock is authoritative for builds; CI checks the complete
lockfile for Rust advisories and approved license expressions. Inventory changes
need review whenever the lockfile changes. This scope covers the native Rust
Verify tool, not Vault's Python/Qt packaging or any OS signing service.
