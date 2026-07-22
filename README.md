# minchash

Multiset Incremental Hash library in Rust.

Order-independent hashing for multisets with efficient incremental add/remove, parallel bulk updates, and (for the secure variant) elliptic-curve cryptography.

## Install

```toml
[dependencies]
minchash = "0.4"
```

Optional Cargo features:

| Feature | Default | Description |
|---|---|---|
| `parallel` | yes | Enables rayon-backed `add_elements` / `remove_elements`. Disable with `default-features = false` if you do not want the rayon dependency. |

## Quick example

```rust
use minchash::{MultisetHash, SecureMultisetHash};

fn main() {
    let mut a = SecureMultisetHash::new();
    a.add(b"apple");
    a.add(b"banana");

    let mut b = SecureMultisetHash::new();
    b.add(b"banana");
    b.add(b"apple");

    // Order does not matter
    assert_eq!(a.get_digest(), b.get_digest());

    // Bytes are first-class — any `&[u8]` works
    a.add(&[0xde, 0xad, 0xbe, 0xef]);

    // Homomorphic merge of independent hashes
    let mut left = SecureMultisetHash::new();
    left.add(b"x");
    let mut right = SecureMultisetHash::new();
    right.add(b"y");
    let merged = left.combine(&right);
    let mut expected = SecureMultisetHash::new();
    expected.add(b"x");
    expected.add(b"y");
    assert_eq!(merged.get_compressed(), expected.get_compressed());
}
```

## Secure vs Fast

| | `SecureMultisetHash` | `FastMultisetHash` |
|---|---|---|
| **Construction** | blake3 → secp256k1 scalar × generator (ECMH-style) | Custom 4×u64 FNV-like mix + wrapping limb add |
| **Threat model** | Collision / forgery hard under the elliptic-curve discrete-log assumption | **Not cryptographically secure** — fine for checksums, caches, search pruning; do **not** use against adversaries |
| **Digest** | blake3 of compressed EC point | blake3 of 32-byte limb state |
| **Speed** | Slower (EC ops); parallel bulk helps | Extremely fast |

Pick **Secure** when hashes may be compared across trust boundaries or used for integrity. Pick **Fast** when you only need order-independent equality / bookkeeping in a trusted setting.

## Key features

- **Incremental updates** — add or remove elements without recomputing from scratch
- **Multiplicity** — `add_with_count` / `remove_with_count` for repeated elements
- **Homomorphic combine / difference** — merge or subtract independent hashes (`+` / `-` operators too)
- **State bytes** — `to_compressed_bytes` / `try_from_compressed_bytes` for wire / storage round-trips
- **Parallel bulk ops** — `add_elements` / `remove_elements` via rayon (`parallel` feature, on by default)
- **Element type** — any byte slice (`&[u8]`, strings via `.as_bytes()`, etc.)

## Potential uses

- **Unordered stream verification** — hash chunks as they arrive in any order (e.g. torrents), then compare digests
- **Combinatorial search** — detect equivalent subspaces reached via different permutations
- **Distributed multiset compare** — hash locally, combine hashes, compare without shipping full collections

## License

MIT
