mod secure;
mod fast;

pub use secure::SecureMultisetHash;
pub use fast::FastMultisetHash;

pub trait MultisetHash: Clone {
    /// Creates a new, empty multiset hash.
    fn new() -> Self where Self: Sized;
    /// Adds a single element (provided as a byte slice) to the hash.
    fn add(&mut self, data: &[u8]);
    /// Removes a single element (provided as a byte slice) from the hash.
    fn remove(&mut self, data: &[u8]);
    /// Adds multiple elements (in parallel) to the hash.
    fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync;
    /// Removes multiple elements (in parallel) from the hash.
    fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync;
    /// Returns the current “compressed” state as a vector of bytes.
    fn get_compressed(&self) -> Option<Vec<u8>>;
    /// Returns a 32‑byte digest of the current state.
    fn get_digest(&self) -> Option<Vec<u8>>;
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
}