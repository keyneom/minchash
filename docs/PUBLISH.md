# Publishing minchash

Status snapshot for releasing **0.4.0** to crates.io.

## Version status

| Location | Version | Notes |
|----------|---------|-------|
| Local `master` (`Cargo.toml`) | **0.4.0** | Ready to publish; ahead of `origin/master` |
| crates.io | **0.3.1** | Latest published (verified via `cargo search minchash`) |
| Gap | **0.4.0 not published** | Local features below are not on crates.io yet |

Verified: `cargo search minchash` reports `minchash = "0.3.1"`.

## What is in 0.4.0 (vs published 0.3.1)

1. **Homomorphic merge/subtract** — `combine` / `difference`, plus `+` / `-` / `+=` / `-=`
2. **Multiplicity** — `add_with_count` / `remove_with_count`
3. **Bytes API** — `to_compressed_bytes` / `try_from_compressed_bytes` (+ `DecodeError`)
4. **`parallel` feature** — rayon behind a default-on feature gate
5. **k256 0.14** — bumped from 0.11
6. **Aligned digests** — Fast `get_digest` uses blake3 like Secure
7. **Faster Secure bulk** — scalar accumulation + one `G * sum` for bulk updates
8. **Docs / metadata / CI** — README, CHANGELOG, GitHub Actions, crate doctest

Install line once published:

```toml
[dependencies]
minchash = "0.4"
```

Without rayon:

```toml
[dependencies]
minchash = { version = "0.4", default-features = false }
```

## Publish checklist (one-command release)

On the machine that owns the crates.io token:

```bash
cd /home/keyneom/minchash
cargo test --lib && cargo test --doc && cargo publish
```

Or dry-run first:

```bash
cargo publish --dry-run
```

Optional local tag (do not push unless you intend to):

```bash
git tag -a v0.4.0 -m "minchash 0.4.0"
```

Verify after publish: https://crates.io/crates/minchash and https://docs.rs/minchash/0.4.0

Login only if needed:

```bash
cargo login
```

This repo was **not** published from automation. Prefer an explicit `cargo publish` when you are ready.

## Local git note

`master` may be ahead of `origin/master`. Publishing to crates.io does not require a git push.
