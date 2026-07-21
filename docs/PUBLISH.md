# Publishing minchash

Status snapshot for releasing **0.4.0** to crates.io.

## Version status

| Location | Version | Notes |
|----------|---------|-------|
| Local `master` (`Cargo.toml`) | **0.4.0** | Clean working tree; ahead of `origin/master` by several commits |
| crates.io | **0.3.1** | Latest published (2025-02-08); ~3k downloads |
| Gap | **0.4.0 not published** | Local features below are not on crates.io yet |

Verified with crates.io API (`max_version` / `newest_version` = `0.3.1`) and `cargo search minchash` / `cargo publish --dry-run`.

## What is in 0.4.0 (vs published 0.3.1)

Local commits not yet reflected on crates.io include:

1. **Homomorphic merge/subtract** — `combine` / `difference`, plus `+` / `-` / `+=` / `-=`
2. **Multiplicity** — `add_with_count` / `remove_with_count`
3. **Bytes API** — `to_compressed_bytes` / `try_from_compressed_bytes` (+ `DecodeError`)
4. **Docs / metadata** — README rewrite (Secure vs Fast threat models), repository/keywords/categories
5. **CI** — `.github/workflows/ci.yml` (`cargo test`, `cargo doc`)

Install line once published:

```toml
[dependencies]
minchash = "0.4"
```

## Package verification (already run)

```bash
cd /home/keyneom/minchash
cargo package --list
cargo publish --dry-run
```

`cargo package --list` includes:

- `Cargo.toml`, `Cargo.lock`, `README.md`, `LICENSE`, `LICENSE.txt`
- `src/{lib,secure,fast}.rs`, `benches/benchmarks.rs`
- `.github/workflows/ci.yml`, `.gitignore`

Dry-run packaged and compiled cleanly, then aborted upload as expected.

Metadata present in `Cargo.toml`: `description`, `license`, `repository`, `homepage`, `documentation`, `readme`, `keywords`, `categories`.

## Publish checklist

Do this on the machine that owns the crates.io token (credentials may already exist under `~/.cargo/credentials.toml`).

1. **Confirm version** — `Cargo.toml` says `0.4.0`; CHANGELOG has a `[0.4.0]` section.
2. **Tests** — `cargo test --all-targets`
3. **Docs** — `cargo doc --no-deps`
4. **Package** — `cargo package` (or `cargo publish --dry-run`)
5. **Optional git tag** (local only unless you choose to push tags yourself):
   ```bash
   git tag -a v0.4.0 -m "minchash 0.4.0"
   ```
6. **Publish** (this uploads; do not run unless you intend to release):
   ```bash
   cargo publish
   ```
7. **Verify** — https://crates.io/crates/minchash and https://docs.rs/minchash/0.4.0
8. **Optional** — push `master` / tag to GitHub when you want the remote to match (not required for crates.io).

Login (only if needed):

```bash
cargo login
# paste crates.io API token
```

This repo was **not** published from this session. Prefer an explicit `cargo publish` when you are ready.

## Completeness vs competitors

### multiset-hash 0.2.0 (cronokirby)

| Capability | minchash 0.4.0 | multiset-hash 0.2.0 |
|------------|----------------|---------------------|
| Incremental add | yes | yes (`add` with multiplicity) |
| Remove | yes | no |
| Multiplicity helpers | yes | yes (on add) |
| Homomorphic combine / difference | yes | not exposed |
| Parallel bulk updates | yes (rayon) | no |
| Fast non-crypto variant | yes (`FastMultisetHash`) | no |
| State serialization | yes (compressed bytes) | via `Digest` finalize only |
| Streaming element hashing (`update` / `end_update`) | no | yes |
| `digest::Digest` impl | no | yes |
| Curve | secp256k1 (`k256`) | Ristretto (`curve25519-dalek` 3.x) |
| Last crates.io release | local 0.4.0 pending | 2021-07-23 |

**Verdict:** For incremental multiset hashing with remove, merge, parallelism, and a dual Secure/Fast API, minchash is ahead. Optional nice-to-haves (not blockers): Ristretto / hash-to-group polish, `Digest` trait, streaming `update`/`end_update` for huge single elements.

### ecmh

No crate named `ecmh` on crates.io. ECMH is the construction family (hash elements into an elliptic-curve group, sum points). `SecureMultisetHash` is already an ECMH-style implementation (blake3 → secp256k1 scalar × generator). Naming/discoverability is covered by the `ecmh` keyword.

## Recommendation

- **Ship 0.4.0** — the unpublished work is the main gap; API looks release-ready.
- **No further feature work required** for a coherent 0.4 release.
- Optional later (not needed to publish): rustdoc examples on the trait, MSRV `rust-version`, drop duplicate `LICENSE.txt`, exclude `.github` from the package tarball, Ristretto or `Digest` interop if you care about parity with `multiset-hash`.

## Local git note

`master` is ahead of `origin/master`. Publishing to crates.io does not require a git push. Push only when you want GitHub to match local history.