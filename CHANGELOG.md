# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-07-21

### Added

- Homomorphic combine / difference (and + / - / += / -= operators) for SecureMultisetHash and FastMultisetHash
- Multiplicity helpers: add_with_count / remove_with_count
- Wire/storage round-trip: to_compressed_bytes / try_from_compressed_bytes (with DecodeError)
- GitHub Actions CI (cargo test, cargo doc)
- Optional `parallel` Cargo feature (default on) gating the rayon dependency
- Crate-level doctest mirroring the README quick example

### Changed

- Crate metadata for crates.io discoverability (repository, homepage, documentation, keywords, categories, readme)
- README rewritten: Secure vs Fast threat models, bytes-first example, feature overview
- Bump `k256` dependency from 0.11 to 0.14
- `FastMultisetHash::get_digest` now returns blake3 of the compressed limb state (aligned with Secure)
- Secure bulk `add_elements` / `remove_elements` sum element scalars then perform a single base-point multiply

### Removed

- Duplicate placeholder `LICENSE.txt` (keep `LICENSE`)

## [0.3.1] - 2025-02-08

### Changed

- Patch release on crates.io (see git history)

## [0.3.0] - 2025-02-08

### Added

- FastMultisetHash non-cryptographic variant

## [0.2.0] - 2025-02-08

### Changed

- Publishing / metadata cleanup

## [0.1.0] - 2025-02-06

### Added

- Initial SecureMultisetHash (blake3 to secp256k1 ECMH-style multiset hash)
- Incremental add/remove and parallel bulk add_elements / remove_elements

[Unreleased]: https://github.com/keyneom/minchash/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/keyneom/minchash/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/keyneom/minchash/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/keyneom/minchash/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/keyneom/minchash/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/keyneom/minchash/releases/tag/v0.1.0