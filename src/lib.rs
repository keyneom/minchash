use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;

// Add Rayon for parallel processing
use rayon::prelude::*;

/// The `MultisetHash` structure maintains a running elliptic curve hash.
pub struct MultisetHash {
    current: ProjectivePoint,
}

impl MultisetHash {
    /// Create a new, empty multiset hash (the identity element).
    pub fn new() -> Self {
        MultisetHash {
            current: ProjectivePoint::IDENTITY,
        }
    }

    /// Hash an element to a point on the elliptic curve.
    ///
    /// We hash the string representation with SHA‑256, reduce modulo the group order,
    /// and multiply the secp256k1 generator by the result.
    fn h(element: &str) -> ProjectivePoint {
        let mut hasher = Sha256::new();
        hasher.update(element.as_bytes());
        let digest = hasher.finalize();
        // Explicitly supply U256 as the type parameter using fully-qualified syntax.
        let scalar = <Scalar as Reduce<U256>>::from_be_bytes_reduced(digest.into());
        // Multiply the generator by the scalar.
        ProjectivePoint::GENERATOR * scalar
    }

    /// Add an element to the multiset hash.
    pub fn add(&mut self, element: &str) {
        self.current += Self::h(element);
    }

    /// Remove an element from the multiset hash.
    ///
    /// This is done by adding the inverse (negation) of H(element).
    pub fn remove(&mut self, element: &str) {
        self.current += -Self::h(element);
    }

    /// Add multiple elements to the multiset hash in parallel.
    pub fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<str> + Sync,
    {
        let sum = elements
            .par_iter()
            .map(|element| Self::h(element.as_ref()))
            .reduce(|| ProjectivePoint::IDENTITY, |a, b| a + b);
        self.current += sum;
    }

    /// Remove multiple elements from the multiset hash in parallel.
    pub fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<str> + Sync,
    {
        let sum = elements
            .par_iter()
            .map(|element| -Self::h(element.as_ref()))
            .reduce(|| ProjectivePoint::IDENTITY, |a, b| a + b);
        self.current += sum;
    }

    /// Get the current hash.
    ///
    /// Returns `None` if the hash is the identity (empty multiset). Otherwise, it returns a
    /// tuple of hexadecimal strings for the x and y coordinates of the point.
    pub fn get_hash(&self) -> Option<(String, String)> {
        if self.current == ProjectivePoint::IDENTITY {
            None
        } else {
            let affine = self.current.to_affine();
            let encoded = affine.to_encoded_point(false);
            let x_hex = hex::encode(encoded.x().unwrap());
            let y_hex = hex::encode(encoded.y().unwrap());
            Some((x_hex, y_hex))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use rand::prelude::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_basic() {
        // Basic test: add a few elements then remove some, printing the hash along the way.
        let mut ms = MultisetHash::new();

        // Push each hash to a list when adding and pop from the list when removing to ensure that hashes match what they should be
        let mut hashes = Vec::new();
        hashes.push(ms.get_hash());
        println!("Initial hash (empty set): {:?}", ms.get_hash());

        ms.add("foo");
        hashes.push(ms.get_hash());
        println!("After adding 'foo': {:?}", ms.get_hash());

        ms.add("world");
        hashes.push(ms.get_hash());
        println!("After adding 'world': {:?}", ms.get_hash());

        ms.add("hello");
        hashes.push(ms.get_hash());
        println!("After adding 'hello': {:?}", ms.get_hash());

        ms.add("hello");
        hashes.push(ms.get_hash());
        println!("After adding 'hello': {:?}", ms.get_hash());

        assert_eq!(hashes.pop(), Some(ms.get_hash()));

        ms.remove("hello");
        assert_eq!(hashes.pop(), Some(ms.get_hash()));
        println!("After removing 'hello': {:?}", ms.get_hash());

        ms.remove("hello");
        assert_eq!(hashes.pop(), Some(ms.get_hash()));
        println!("After removing 'hello': {:?}", ms.get_hash());

        ms.remove("world");
        assert_eq!(hashes.pop(), Some(ms.get_hash()));
        println!("After removing 'world': {:?}", ms.get_hash());
        
        ms.remove("foo");
        assert_eq!(hashes.pop(), Some(ms.get_hash()));
        println!("After removing 'foo': {:?}", ms.get_hash());
    }

    #[test]
    fn test_permutations_of_subsets() {
        // For each subset of a test set, verify that every permutation yields the same hash.
        // let test_set = vec![
        //     "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13",
        // ];
        let test_set = vec![
            "1", "2", "3", "4", "5", "6", "7"
        ];
        for r in 0..=test_set.len() {
            // Use itertools to generate combinations of size `r`.
            for subset in test_set.iter().combinations(r) {
                let mut hash_values = HashSet::new();
                // For every permutation of the subset:
                for perm in subset.iter().permutations(r) {
                    let mut ms = MultisetHash::new();
                    for &&element in &perm {
                        ms.add(element);
                    }
                    hash_values.insert(ms.get_hash());
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

    #[test]
    fn test_complex_random_operations() {
        // Complex test: perform a long randomized sequence of add/remove operations,
        // tracking the multiset counts and comparing the running hash with the expected hash.
        let mut rng = StdRng::seed_from_u64(42);

        // Define a universe of 100 distinct elements.
        let universe: Vec<String> = (0..100).map(|i| format!("item{}", i)).collect();
        let num_operations = 20_000;

        let mut ms = MultisetHash::new();
        // Ground-truth multiset: a mapping from element -> count.
        let mut counts: HashMap<String, i64> = HashMap::new();
        for elem in &universe {
            counts.insert(elem.clone(), 0);
        }

        // Perform a long series of random add/remove operations.
        for _ in 0..num_operations {
            let op: u8 = rng.gen_range(0..2);
            let elem = universe.choose(&mut rng).unwrap().clone();
            if op == 0 {
                ms.add(&elem);
                *counts.get_mut(&elem).unwrap() += 1;
            } else {
                if *counts.get(&elem).unwrap() > 0 {
                    ms.remove(&elem);
                    *counts.get_mut(&elem).unwrap() -= 1;
                } else {
                    ms.add(&elem);
                    *counts.get_mut(&elem).unwrap() += 1;
                }
            }
        }

        // Compute the expected hash by summing count * H(element) for each element.
        let mut expected = ProjectivePoint::IDENTITY;
        for (elem, count) in &counts {
            if *count > 0 {
                // Convert count to a scalar.
                let count_scalar = Scalar::from(*count as u64);
                expected += MultisetHash::h(elem) * count_scalar;
            }
        }

        // Compare the computed expected hash with the running hash.
        let ms_affine = ms.current.to_affine();
        let expected_affine = expected.to_affine();
        assert_eq!(
            ms_affine, expected_affine,
            "The running multiset hash does not match the expected hash computed from the final multiset."
        );
    }

    #[test]
    fn test_add_elements() {
        let mut ms = MultisetHash::new();
        let elements = vec!["apple", "banana", "cherry", "date", "elderberry"];

        ms.add_elements(&elements);

        let mut ms_seq = MultisetHash::new();
        for &elem in &elements {
            ms_seq.add(elem);
        }

        assert_eq!(ms.get_hash(), ms_seq.get_hash());
    }

    #[test]
    fn test_remove_elements() {
        let mut ms = MultisetHash::new();
        let elements = vec!["fig", "grape", "honeydew", "kiwi", "lemon"];
        ms.add_elements(&elements);

        ms.remove_elements(&["grape", "lemon"]);

        let mut ms_expected = MultisetHash::new();
        for &elem in &elements {
            if elem != "grape" && elem != "lemon" {
                ms_expected.add(elem);
            }
        }

        assert_eq!(ms.get_hash(), ms_expected.get_hash());
    }

    #[test]
    fn test_parallel_consistency() {
        let mut rng = thread_rng();
        let elements: Vec<String> = (0..1000).map(|i| format!("item{}", i)).collect();
        let mut shuffled = elements.clone();
        shuffled.shuffle(&mut rng);

        let mut ms = MultisetHash::new();
        ms.add_elements(&elements);
        ms.remove_elements(&shuffled);

        assert_eq!(ms.get_hash(), None);
    }
}