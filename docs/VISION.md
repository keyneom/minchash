# minchash — product vision

## What we're building

A **Rust library for order-independent multiset hashing** — add/remove elements incrementally, merge multisets homomorphically, and compare large unordered collections without sorting or shipping full lists.

## User stories

1. **As a systems developer**, I want to hash a multiset incrementally as data arrives (torrent chunks, log batches) and verify equality without waiting for the full set.
2. **As a distributed systems author**, I want `combine` / `difference` so I can merge partial hashes from nodes and check equivalence with low network overhead.
3. **As a security engineer**, I want a **Secure** variant (EC-based) for integrity and a **Fast** variant for best-effort speed when crypto strength is not required.
4. **As a library consumer**, I want bytes (not just strings), multiplicity (`add_with_count`), round-trip state bytes, and optional parallel bulk ops behind a feature flag.

## Scope status

The library is **relatively complete** at **0.4.0** locally. Remaining work is mostly **publish hygiene** (crates.io still on 0.3.1) and optional perf polish — not new product surface.

| Capability | Status |
|------------|--------|
| Incremental add/remove | Done |
| Parallel bulk | Done (`parallel` feature, default on) |
| combine / difference | Done (0.4.0) |
| Multiplicity | Done (0.4.0) |
| Compressed bytes round-trip | Done (0.4.0) |
| crates.io 0.4.0 publish | Pending — see [PUBLISH.md](PUBLISH.md) |

## Use cases (detail)

See [README.md](../README.md) — torrent verification, combinatorial search pruning, distributed multiset comparison.
