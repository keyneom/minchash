use k256::{ProjectivePoint, Scalar};
use blake3;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use rayon::prelude::*;

/// The `SecureMultisetHash` structure maintains a running elliptic curve hash.
pub struct SecureMultisetHash {
    current: ProjectivePoint,
}

impl SecureMultisetHash {
    /// Creates a new, empty multiset hash (the identity element).
    pub fn new() -> Self {
        SecureMultisetHash {
            current: ProjectivePoint::IDENTITY,
        }
    }

    /// Hash an element (provided as a byte slice) to a point on the elliptic curve.
    ///
    /// This function:
    /// 1. Hashes the input using Blake3 (producing 32 bytes),
    /// 2. Reduces that 32‑byte output modulo the secp256k1 group order (using
    ///    `from_be_bytes_reduced`), and
    /// 3. Multiplies the secp256k1 generator by the resulting scalar.
    fn h(element: &[u8]) -> ProjectivePoint {
        // Compute a Blake3 hash of the input.
        let hash = blake3::hash(element);
        let digest: [u8; 32] = *hash.as_bytes(); // Blake3 always produces 32 bytes.
        // Reduce the 32-byte array to a scalar (using U256 as the underlying type).
        let scalar = <Scalar as Reduce<U256>>::from_be_bytes_reduced(digest.into());
        // Multiply the generator by the scalar.
        ProjectivePoint::GENERATOR * scalar
    }

    /// Add an element to the multiset hash.
    pub fn add(&mut self, element: &[u8]) {
        self.current += Self::h(element);
    }

    /// Removes an element (provided as a byte slice) from the multiset hash.
    ///
    /// This is done by adding the inverse (negation) of H(element).
    pub fn remove(&mut self, element: &[u8]) {
        self.current += -Self::h(element);
    }

    /// Adds multiple elements in parallel.
    pub fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        let sum = elements
            .par_iter()
            .map(|element| Self::h(element.as_ref()))
            .reduce(|| ProjectivePoint::IDENTITY, |a, b| a + b);
        self.current += sum;
    }

    /// Removes multiple elements in parallel.
    pub fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        let sum = elements
            .par_iter()
            .map(|element| -Self::h(element.as_ref()))
            .reduce(|| ProjectivePoint::IDENTITY, |a, b| a + b);
        self.current += sum;
    }

    pub fn get_compressed(&self) -> Option<[u8; 33]> {
        if self.current == ProjectivePoint::IDENTITY {
            None
        } else {
            let affine = self.current.to_affine();
            let encoded = affine.to_encoded_point(true); // compressed = true
            let bytes = encoded.as_bytes();
            let mut out = [0u8; 33];
            out.copy_from_slice(bytes);
            Some(out)
        }
    }

    pub fn get_digest(&self) -> Option<[u8; 32]> {
        self.get_compressed().map(|compressed| {
            let digest = blake3::hash(&compressed);
            let mut out = [0u8; 32];
            out.copy_from_slice(digest.as_bytes());
            out
        })
    }
}

/// A high‑performance (non‑secure) multiset hash that is order‑independent.
/// 
/// Internally, the state is a 256‑bit value represented as four u64’s.
/// Each element is mapped to a 256‑bit value by a very simple (non‑cryptographic)
/// hash function, and the overall multiset hash is just the sum (with wrapping addition)
/// of all the element hashes. Removal is implemented as subtraction.
/// 
/// This implementation sacrifices cryptographic security for speed.
pub struct FastMultisetHash {
    /// The current state, a 256‑bit value stored as [u64; 4].
    current: [u64; 4],
}

impl FastMultisetHash {
    /// Creates a new, empty multiset hash (the zero value).
    pub fn new() -> Self {
        FastMultisetHash {
            current: [0, 0, 0, 0],
        }
    }

    /// A very simple non‑cryptographic 256‑bit hash function.
    ///
    /// We use four parallel FNV‑1a–like accumulators (all seeded with the FNV offset
    /// basis) and update them in round‑robin fashion over the input data.
    fn simple_hash_256(data: &[u8]) -> [u64; 4] {
        // Use the FNV offset basis as our initial value for each accumulator.
        let mut h1: u64 = 0xcbf29ce484222325;
        let mut h2: u64 = 0xcbf29ce484222325;
        let mut h3: u64 = 0xcbf29ce484222325;
        let mut h4: u64 = 0xcbf29ce484222325;
        // A common prime constant (the FNV prime) is used for the multiplication.
        let prime: u64 = 0x100000001b3;
        
        for (i, &b) in data.iter().enumerate() {
            match i % 4 {
                0 => {
                    h1 = h1.wrapping_add(b as u64);       // Addition
                    h1 = h1.rotate_left(13);                // Rotation (rotate left by 13 bits)
                    h1 ^= b as u64;                         // XOR with the byte
                    h1 = h1.wrapping_mul(prime);            // Multiplication
                },
                1 => {
                    h2 = h2.wrapping_add(b as u64);
                    h2 = h2.rotate_left(17);
                    h2 ^= b as u64;
                    h2 = h2.wrapping_mul(prime);
                },
                2 => {
                    h3 = h3.wrapping_add(b as u64);
                    h3 = h3.rotate_left(19);
                    h3 ^= b as u64;
                    h3 = h3.wrapping_mul(prime);
                },
                3 => {
                    h4 = h4.wrapping_add(b as u64);
                    h4 = h4.rotate_left(23);
                    h4 ^= b as u64;
                    h4 = h4.wrapping_mul(prime);
                },
                _ => unreachable!(),
            }
        }
        [h1, h2, h3, h4]
    }
    

    /// Helper: wrapping addition of two 256‑bit values.
    fn add_256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        [
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            a[2].wrapping_add(b[2]),
            a[3].wrapping_add(b[3]),
        ]
    }

    /// Helper: wrapping subtraction of two 256‑bit values.
    fn sub_256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        [
            a[0].wrapping_sub(b[0]),
            a[1].wrapping_sub(b[1]),
            a[2].wrapping_sub(b[2]),
            a[3].wrapping_sub(b[3]),
        ]
    }

    /// Maps an element (a byte slice) to a 256‑bit hash value.
    fn h(data: &[u8]) -> [u64; 4] {
        Self::simple_hash_256(data)
    }

    /// Adds an element (given as a byte slice) to the multiset hash.
    pub fn add(&mut self, data: &[u8]) {
        let h = Self::h(data);
        self.current = Self::add_256(self.current, h);
    }

    /// Removes an element (given as a byte slice) from the multiset hash.
    ///
    /// This is done by subtracting the hash of the element.
    pub fn remove(&mut self, data: &[u8]) {
        let h = Self::h(data);
        self.current = Self::sub_256(self.current, h);
    }

    /// Adds multiple elements in parallel.
    pub fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        use rayon::prelude::*;
        let sum = elements
            .par_iter()
            .map(|element| Self::h(element.as_ref()))
            .reduce(|| [0, 0, 0, 0], |a, b| Self::add_256(a, b));
        self.current = Self::add_256(self.current, sum);
    }

    /// Removes multiple elements in parallel.
    pub fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        use rayon::prelude::*;
        let sum = elements
            .par_iter()
            .map(|element| {
                let h = Self::h(element.as_ref());
                // Negate each accumulator (wrapping negation mod 2^64)
                [h[0].wrapping_neg(), h[1].wrapping_neg(), h[2].wrapping_neg(), h[3].wrapping_neg()]
            })
            .reduce(|| [0, 0, 0, 0], |a, b| Self::add_256(a, b));
        self.current = Self::add_256(self.current, sum);
    }

    /// Returns the "compressed" state of the multiset hash as 32 bytes.
    ///
    /// (In the secure ECC version this is 33 bytes; here our state is 256 bits so we return 32 bytes.)
    pub fn get_compressed(&self) -> Option<[u8; 32]> {
        if self.current == [0, 0, 0, 0] {
            None
        } else {
            let mut out = [0u8; 32];
            out[0..8].copy_from_slice(&self.current[0].to_be_bytes());
            out[8..16].copy_from_slice(&self.current[1].to_be_bytes());
            out[16..24].copy_from_slice(&self.current[2].to_be_bytes());
            out[24..32].copy_from_slice(&self.current[3].to_be_bytes());
            Some(out)
        }
    }

    /// Returns a 32‑byte digest of the current multiset hash.
    ///
    /// For this non‑secure implementation, we simply return the compressed state.
    pub fn get_digest(&self) -> Option<[u8; 32]> {
        self.get_compressed()
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
        let mut ms = SecureMultisetHash::new();
        
        // Push each hash to a list when adding and pop from the list when removing to ensure that hashes match what they should be
        let mut hashes = Vec::new();
        hashes.push(ms.get_compressed());
        println!("Initial hash (empty set): {:?}", ms.get_compressed());

        ms.add("foo".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'foo': {:?}", ms.get_compressed());

        ms.add("world".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'world': {:?}", ms.get_compressed());

        ms.add("hello".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'hello': {:?}", ms.get_compressed());

        ms.add("hello".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'hello': {:?}", ms.get_compressed());

        assert_eq!(hashes.pop(), Some(ms.get_compressed()));

        ms.remove("hello".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'hello': {:?}", ms.get_compressed());

        ms.remove("hello".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'hello': {:?}", ms.get_compressed());

        ms.remove("world".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'world': {:?}", ms.get_compressed());
        
        ms.remove("foo".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'foo': {:?}", ms.get_compressed());
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
                    let mut ms = SecureMultisetHash::new();
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

    #[test]
    fn test_complex_random_operations() {
        // Complex test: perform a long randomized sequence of add/remove operations,
        // tracking the multiset counts and comparing the running hash with the expected hash.
        let mut rng = StdRng::seed_from_u64(42);

        // Define a universe of 100 distinct elements.
        let universe: Vec<String> = (0..100).map(|i| format!("item{}", i)).collect();
        let num_operations = 20_000;

        let mut ms = SecureMultisetHash::new();
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
                ms.add(elem.as_bytes());
                *counts.get_mut(&elem).unwrap() += 1;
            } else {
                if *counts.get(&elem).unwrap() > 0 {
                    ms.remove(elem.as_bytes());
                    *counts.get_mut(&elem).unwrap() -= 1;
                } else {
                    ms.add(elem.as_bytes());
                    *counts.get_mut(&elem).unwrap() += 1;
                }
            }
        }

        // Compute the expected hash by summing count * H(element) for each element.
        let mut expected = ProjectivePoint::IDENTITY;
        for (elem, count) in &counts {
            if *count > 0 {
                let count_scalar = Scalar::from(*count as u64);
                expected += SecureMultisetHash::h(elem.as_bytes()) * count_scalar;
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
        let mut ms = SecureMultisetHash::new();
        let elements = vec![
            "apple".as_bytes(),
            "banana".as_bytes(),
            "cherry".as_bytes(),
            "date".as_bytes(),
            "elderberry".as_bytes(),
        ];
        ms.add_elements(&elements);
        let mut ms_seq = SecureMultisetHash::new();
        for &elem in &elements {
            ms_seq.add(elem);
        }
        assert_eq!(ms.get_compressed(), ms_seq.get_compressed());
    }

    #[test]
    fn test_remove_elements() {
        let mut ms = SecureMultisetHash::new();
        let elements = vec![
            "fig".as_bytes(),
            "grape".as_bytes(),
            "honeydew".as_bytes(),
            "kiwi".as_bytes(),
            "lemon".as_bytes(),
        ];
        ms.add_elements(&elements);
        ms.remove_elements(&[ "grape".as_bytes(), "lemon".as_bytes() ]);
        let mut ms_expected = SecureMultisetHash::new();
        for &elem in &elements {
            if elem != "grape".as_bytes() && elem != "lemon".as_bytes() {
                ms_expected.add(elem);
            }
        }
        assert_eq!(ms.get_compressed(), ms_expected.get_compressed());
    }

    #[test]
    fn test_parallel_consistency() {
        let mut rng = thread_rng();
        let elements: Vec<String> = (0..1000).map(|i| format!("item{}", i)).collect();
        let mut shuffled = elements.clone();
        shuffled.shuffle(&mut rng);

        let mut ms = SecureMultisetHash::new();
        ms.add_elements(&elements.iter().map(|s| s.as_bytes()).collect::<Vec<_>>());
        ms.remove_elements(&shuffled.iter().map(|s| s.as_bytes()).collect::<Vec<_>>());

        assert_eq!(ms.get_compressed(), None);
    }

    #[test]
    fn test_fast_basic() {
        // Basic test: add a few elements then remove some, printing the hash along the way.
        let mut ms = FastMultisetHash::new();
        
        // Push each hash to a list when adding and pop from the list when removing to ensure that hashes match what they should be
        let mut hashes = Vec::new();
        hashes.push(ms.get_compressed());
        println!("Initial hash (empty set): {:?}", ms.get_compressed());

        ms.add("foo".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'foo': {:?}", hex::encode(ms.get_compressed().unwrap()));

        ms.add("world".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'world': {:?}", hex::encode(ms.get_compressed().unwrap()));

        ms.add("hello".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'hello': {:?}", hex::encode(ms.get_compressed().unwrap()));

        ms.add("hello".as_bytes());
        hashes.push(ms.get_compressed());
        println!("After adding 'hello': {:?}", hex::encode(ms.get_compressed().unwrap()));

        assert_eq!(hashes.pop(), Some(ms.get_compressed()));

        ms.remove("hello".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'hello': {:?}", hex::encode(ms.get_compressed().unwrap()));

        ms.remove("hello".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'hello': {:?}", hex::encode(ms.get_compressed().unwrap()));

        ms.remove("world".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'world': {:?}", hex::encode(ms.get_compressed().unwrap()));
        
        ms.remove("foo".as_bytes());
        assert_eq!(hashes.pop(), Some(ms.get_compressed()));
        println!("After removing 'foo': {:?}", ms.get_compressed());
    }

    #[test]
    fn test_fast_permutations_of_subsets() {
        // For each subset of a test set, verify that every permutation yields the same hash.
        // let test_set = vec![
        //     "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13",
        // ];
        let test_set = vec![
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
        ];
        for r in 0..=test_set.len() {
            // Use itertools to generate combinations of size `r`.
            for subset in test_set.iter().combinations(r) {
                let mut hash_values = HashSet::new();
                // For every permutation of the subset:
                for perm in subset.iter().permutations(r) {
                    let mut ms = FastMultisetHash::new();
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

    /// Test that adding random u128 values and then removing them in reverse order
    /// returns us to the previously recorded states.
    #[test]
    fn test_intensive_basic() {
        let mut rng = rand::thread_rng();
        // Number of operations to perform
        let num_ops = 10_000_000;
        let mut ms = FastMultisetHash::new();
        // We'll record the state after each operation (including the initial empty state).
        let mut state_stack: Vec<Option<[u8; 32]>> = Vec::new();
        state_stack.push(ms.get_compressed()); // initial state (should be None for empty)
        // Also record the values we add (as u128)
        let mut elements: Vec<u128> = Vec::new();

        // Perform a series of additions.
        for _ in 0..num_ops {
            let val: u128 = rng.gen();
            elements.push(val);
            ms.add(&val.to_be_bytes());
            state_stack.push(ms.get_compressed());
        }

        state_stack.pop();

        // Now, remove the elements in LIFO order.
        while let Some(expected_state) = state_stack.pop() {
            if !elements.is_empty() {
                let val = elements.pop().unwrap();
                ms.remove(&val.to_be_bytes());
            }
            let current_state = ms.get_compressed();
            assert_eq!(
                current_state, expected_state,
                "State mismatch after removal: expected {:?}, got {:?}",
                expected_state, current_state
            );
        }
    }

    /// Test the collision resistance of the non-secure multiset hash.
    /// We generate many random multisets and assert that their final states are unique.
    #[test]
    fn test_collision_resistance() {
        // We'll generate a number of multisets and record their final state.
        let num_multisets = 10_000_000;
        let mut rng = rand::thread_rng();
        let mut final_hashes = HashSet::new();

        for _ in 0..num_multisets {
            // Each multiset will have between 0 and 50 random elements.
            let num_elements = rng.gen_range(1..=50);
            let mut ms = FastMultisetHash::new();
            for _ in 0..num_elements {
                let val: u128 = rng.gen();
                ms.add(&val.to_be_bytes());
            }
            // For an empty multiset, use a canonical 32-byte zero array.
            let final_state = ms.get_compressed().unwrap_or([0u8; 32]);
            final_hashes.insert(final_state);
        }

        assert_eq!(
            final_hashes.len(),
            num_multisets,
            "Collision detected in non-secure multiset hash ({} multisets but only {} unique states)",
            num_multisets,
            final_hashes.len()
        );
    }

    #[test]
    fn test_fast_add_elements() {
        let mut ms = FastMultisetHash::new();
        let elements = vec![
            "apple".as_bytes(),
            "banana".as_bytes(),
            "cherry".as_bytes(),
            "date".as_bytes(),
            "elderberry".as_bytes(),
        ];
        ms.add_elements(&elements);
        let mut ms_seq = FastMultisetHash::new();
        for &elem in &elements {
            ms_seq.add(elem);
        }
        assert_eq!(ms.get_compressed(), ms_seq.get_compressed());
    }

    #[test]
    fn test_fast_remove_elements() {
        let mut ms = FastMultisetHash::new();
        let elements = vec![
            "fig".as_bytes(),
            "grape".as_bytes(),
            "honeydew".as_bytes(),
            "kiwi".as_bytes(),
            "lemon".as_bytes(),
        ];
        ms.add_elements(&elements);
        ms.remove_elements(&[ "grape".as_bytes(), "lemon".as_bytes() ]);
        let mut ms_expected = FastMultisetHash::new();
        for &elem in &elements {
            if elem != "grape".as_bytes() && elem != "lemon".as_bytes() {
                ms_expected.add(elem);
            }
        }
        assert_eq!(ms.get_compressed(), ms_expected.get_compressed());
    }

    #[test]
    fn test_fast_parallel_consistency() {
        let mut rng = thread_rng();
        let elements: Vec<String> = (0..1000).map(|i| format!("item{}", i)).collect();
        let mut shuffled = elements.clone();
        shuffled.shuffle(&mut rng);

        let mut ms = FastMultisetHash::new();
        ms.add_elements(&elements.iter().map(|s| s.as_bytes()).collect::<Vec<_>>());
        ms.remove_elements(&shuffled.iter().map(|s| s.as_bytes()).collect::<Vec<_>>());

        assert_eq!(ms.get_compressed(), None);
    }
}