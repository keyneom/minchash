//! Multiset incremental hashing (ECMH-style and a fast non-crypto variant).
//!
//! ```
//! use minchash::{MultisetHash, SecureMultisetHash};
//!
//! let mut a = SecureMultisetHash::new();
//! a.add(b"apple");
//! a.add(b"banana");
//!
//! let mut b = SecureMultisetHash::new();
//! b.add(b"banana");
//! b.add(b"apple");
//!
//! // Order does not matter
//! assert_eq!(a.get_digest(), b.get_digest());
//!
//! // Bytes are first-class — any `&[u8]` works
//! a.add(&[0xde, 0xad, 0xbe, 0xef]);
//!
//! // Homomorphic merge of independent hashes
//! let mut left = SecureMultisetHash::new();
//! left.add(b"x");
//! let mut right = SecureMultisetHash::new();
//! right.add(b"y");
//! let merged = left.combine(&right);
//! let mut expected = SecureMultisetHash::new();
//! expected.add(b"x");
//! expected.add(b"y");
//! assert_eq!(merged.get_compressed(), expected.get_compressed());
//! ```

mod secure;
mod fast;

pub use secure::SecureMultisetHash;
pub use fast::FastMultisetHash;

/// Error returned when compressed state bytes cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid compressed multiset hash bytes")
    }
}

impl std::error::Error for DecodeError {}

pub trait MultisetHash: Clone {
    /// Creates a new, empty multiset hash.
    fn new() -> Self
    where
        Self: Sized;

    /// Adds a single element (provided as a byte slice) to the hash.
    fn add(&mut self, data: &[u8]);

    /// Removes a single element (provided as a byte slice) from the hash.
    fn remove(&mut self, data: &[u8]);

    /// Adds `count` copies of an element.
    fn add_with_count(&mut self, data: &[u8], count: u64);

    /// Removes `count` copies of an element.
    fn remove_with_count(&mut self, data: &[u8], count: u64);

    /// Adds multiple elements (in parallel) to the hash.
    fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync;

    /// Removes multiple elements (in parallel) from the hash.
    fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync;

    /// Homomorphic combine: `H(self ∪ other)` when the multisets are disjoint
    /// in the usual ECMH sense (counts add).
    fn combine(&self, other: &Self) -> Self;

    /// Homomorphic difference: subtract `other`'s contribution from `self`.
    fn difference(&self, other: &Self) -> Self;

    /// Returns the current compressed state as a vector of bytes.
    /// Empty (identity) state yields `None`.
    fn get_compressed(&self) -> Option<Vec<u8>>;

    /// Returns a 32‑byte digest of the current state.
    fn get_digest(&self) -> Option<Vec<u8>>;

    /// Serialize the full state (including empty/identity) for storage or the wire.
    fn to_compressed_bytes(&self) -> Vec<u8>;

    /// Restore state from [`Self::to_compressed_bytes`].
    fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use crate::{fast::FastMultisetHash, secure::SecureMultisetHash, MultisetHash};
    use itertools::Itertools;
    use rand::prelude::*;
    use std::collections::HashSet;

    // Generic test functions that work with any MultisetHash implementation
    fn test_basic_impl<T: MultisetHash>() {
        let mut ms = T::new();
        let mut hashes = Vec::new();
        hashes.push(ms.get_compressed());

        ms.add("foo".as_bytes());
        hashes.push(ms.get_compressed());

        ms.add("world".as_bytes());
        hashes.push(ms.get_compressed());

        ms.add("hello".as_bytes());
        hashes.push(ms.get_compressed());

        ms.add("hello".as_bytes());
        hashes.push(ms.get_compressed());

        assert_eq!(hashes.pop().unwrap(), ms.get_compressed());

        ms.remove("hello".as_bytes());
        assert_eq!(hashes.pop().unwrap(), ms.get_compressed());

        ms.remove("hello".as_bytes());
        assert_eq!(hashes.pop().unwrap(), ms.get_compressed());

        ms.remove("world".as_bytes());
        assert_eq!(hashes.pop().unwrap(), ms.get_compressed());

        ms.remove("foo".as_bytes());
        assert_eq!(hashes.pop().unwrap(), ms.get_compressed());

        assert_eq!(ms.get_compressed(), None);
    }

    fn test_permutations_of_subsets_impl<T: MultisetHash>() {
        let test_set = vec!["1", "2", "3", "4", "5", "6", "7"];

        for r in 0..=test_set.len() {
            for subset in test_set.iter().combinations(r) {
                let mut hash_values = HashSet::new();

                for perm in subset.iter().permutations(r) {
                    let mut ms = T::new();
                    for element in &perm {
                        ms.add(element.as_bytes());
                    }
                    hash_values.insert(ms.get_compressed());
                }

                assert_eq!(
                    hash_values.len(),
                    1,
                    "Permutation hash mismatch for subset: {:?}. Got: {:?}",
                    subset,
                    hash_values
                );
            }
        }
    }

    fn test_add_elements_impl<T: MultisetHash>() {
        let mut ms = T::new();
        let elements = vec![
            "apple".as_bytes(),
            "banana".as_bytes(),
            "cherry".as_bytes(),
            "date".as_bytes(),
            "elderberry".as_bytes(),
        ];

        ms.add_elements(&elements);

        let mut ms_seq = T::new();
        for &elem in &elements {
            ms_seq.add(elem);
        }

        assert_eq!(ms.get_compressed(), ms_seq.get_compressed());
    }

    fn test_remove_elements_impl<T: MultisetHash>() {
        let mut ms = T::new();
        let elements = vec![
            "fig".as_bytes(),
            "grape".as_bytes(),
            "honeydew".as_bytes(),
            "kiwi".as_bytes(),
            "lemon".as_bytes(),
        ];

        ms.add_elements(&elements);
        ms.remove_elements(&["grape".as_bytes(), "lemon".as_bytes()]);

        let mut ms_expected = T::new();
        for &elem in &elements {
            if elem != "grape".as_bytes() && elem != "lemon".as_bytes() {
                ms_expected.add(elem);
            }
        }

        assert_eq!(ms.get_compressed(), ms_expected.get_compressed());
    }

    fn test_parallel_consistency_impl<T: MultisetHash>() {
        let mut rng = thread_rng();
        let elements: Vec<String> = (0..1000).map(|i| format!("item{}", i)).collect();
        let mut shuffled = elements.clone();
        shuffled.shuffle(&mut rng);

        let mut ms = T::new();
        ms.add_elements(&elements.iter().map(|s| s.as_bytes()).collect::<Vec<_>>());
        ms.remove_elements(&shuffled.iter().map(|s| s.as_bytes()).collect::<Vec<_>>());

        assert_eq!(ms.get_compressed(), None);
    }

    fn test_combine_difference_impl<T: MultisetHash>() {
        let mut a = T::new();
        a.add(b"one");
        a.add(b"two");

        let mut b = T::new();
        b.add(b"three");
        b.add(b"four");

        let combined = a.combine(&b);

        let mut expected = T::new();
        expected.add(b"one");
        expected.add(b"two");
        expected.add(b"three");
        expected.add(b"four");

        assert_eq!(combined.get_compressed(), expected.get_compressed());

        let back = combined.difference(&b);
        assert_eq!(back.get_compressed(), a.get_compressed());

        // Combine is commutative
        assert_eq!(a.combine(&b).get_compressed(), b.combine(&a).get_compressed());
    }

    fn test_with_count_impl<T: MultisetHash>() {
        let mut counted = T::new();
        counted.add_with_count(b"x", 5);
        counted.add_with_count(b"y", 0); // no-op
        counted.remove_with_count(b"x", 2);

        let mut looped = T::new();
        for _ in 0..5 {
            looped.add(b"x");
        }
        for _ in 0..2 {
            looped.remove(b"x");
        }

        assert_eq!(counted.get_compressed(), looped.get_compressed());
    }

    fn test_compressed_round_trip_impl<T: MultisetHash>() {
        let empty = T::new();
        let restored_empty = T::try_from_compressed_bytes(&empty.to_compressed_bytes()).unwrap();
        assert_eq!(empty.get_compressed(), restored_empty.get_compressed());
        assert_eq!(empty.get_digest(), restored_empty.get_digest());

        let mut ms = T::new();
        ms.add(b"alpha");
        ms.add(b"beta");
        ms.add_with_count(b"gamma", 3);

        let bytes = ms.to_compressed_bytes();
        let mut restored = T::try_from_compressed_bytes(&bytes).unwrap();
        assert_eq!(ms.get_compressed(), restored.get_compressed());
        assert_eq!(ms.get_digest(), restored.get_digest());

        // Continue updating after deserialize
        restored.add(b"delta");
        ms.add(b"delta");
        assert_eq!(ms.get_compressed(), restored.get_compressed());
    }

    // Tests for both implementations
    #[test]
    fn test_basic() {
        test_basic_impl::<SecureMultisetHash>();
        test_basic_impl::<FastMultisetHash>();
    }

    #[test]
    fn test_permutations_of_subsets() {
        test_permutations_of_subsets_impl::<SecureMultisetHash>();
        test_permutations_of_subsets_impl::<FastMultisetHash>();
    }

    #[test]
    fn test_add_elements() {
        test_add_elements_impl::<SecureMultisetHash>();
        test_add_elements_impl::<FastMultisetHash>();
    }

    #[test]
    fn test_remove_elements() {
        test_remove_elements_impl::<SecureMultisetHash>();
        test_remove_elements_impl::<FastMultisetHash>();
    }

    #[test]
    fn test_parallel_consistency() {
        test_parallel_consistency_impl::<SecureMultisetHash>();
        test_parallel_consistency_impl::<FastMultisetHash>();
    }

    #[test]
    fn test_combine_difference() {
        test_combine_difference_impl::<SecureMultisetHash>();
        test_combine_difference_impl::<FastMultisetHash>();
    }

    #[test]
    fn test_with_count() {
        test_with_count_impl::<SecureMultisetHash>();
        test_with_count_impl::<FastMultisetHash>();
    }

    #[test]
    fn test_compressed_round_trip() {
        test_compressed_round_trip_impl::<SecureMultisetHash>();
        test_compressed_round_trip_impl::<FastMultisetHash>();
    }
}
