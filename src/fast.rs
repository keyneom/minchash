use crate::{DecodeError, MultisetHash};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastMultisetHash {
    current: [u64; 4],
}

impl Default for FastMultisetHash {
    fn default() -> Self {
        Self::new()
    }
}

impl FastMultisetHash {
    pub fn new() -> Self {
        FastMultisetHash {
            current: [0, 0, 0, 0],
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        let h = Self::h(data);
        self.current = Self::add_256(self.current, h);
    }

    pub fn remove(&mut self, data: &[u8]) {
        let h = Self::h(data);
        self.current = Self::sub_256(self.current, h);
    }

    pub fn add_with_count(&mut self, data: &[u8], count: u64) {
        if count == 0 {
            return;
        }
        let scaled = Self::scale_256(Self::h(data), count);
        self.current = Self::add_256(self.current, scaled);
    }

    pub fn remove_with_count(&mut self, data: &[u8], count: u64) {
        if count == 0 {
            return;
        }
        let scaled = Self::scale_256(Self::h(data), count);
        self.current = Self::sub_256(self.current, scaled);
    }

    pub fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        #[cfg(feature = "parallel")]
        {
            let sum = elements
                .par_iter()
                .map(|element| Self::h(element.as_ref()))
                .reduce(|| [0, 0, 0, 0], Self::add_256);
            self.current = Self::add_256(self.current, sum);
        }
        #[cfg(not(feature = "parallel"))]
        {
            for element in elements {
                self.add(element.as_ref());
            }
        }
    }

    pub fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        #[cfg(feature = "parallel")]
        {
            let sum = elements
                .par_iter()
                .map(|element| {
                    let h = Self::h(element.as_ref());
                    [
                        h[0].wrapping_neg(),
                        h[1].wrapping_neg(),
                        h[2].wrapping_neg(),
                        h[3].wrapping_neg(),
                    ]
                })
                .reduce(|| [0, 0, 0, 0], Self::add_256);
            self.current = Self::add_256(self.current, sum);
        }
        #[cfg(not(feature = "parallel"))]
        {
            for element in elements {
                self.remove(element.as_ref());
            }
        }
    }

    pub fn combine(&self, other: &Self) -> Self {
        Self {
            current: Self::add_256(self.current, other.current),
        }
    }

    pub fn difference(&self, other: &Self) -> Self {
        Self {
            current: Self::sub_256(self.current, other.current),
        }
    }

    pub fn get_compressed(&self) -> Option<Vec<u8>> {
        if self.current == [0, 0, 0, 0] {
            None
        } else {
            Some(self.to_compressed_bytes())
        }
    }

    pub fn get_digest(&self) -> Option<Vec<u8>> {
        self.get_compressed().map(|compressed| {
            let digest = blake3::hash(&compressed);
            digest.as_bytes().to_vec()
        })
    }

    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.current[0].to_be_bytes());
        out[8..16].copy_from_slice(&self.current[1].to_be_bytes());
        out[16..24].copy_from_slice(&self.current[2].to_be_bytes());
        out[24..32].copy_from_slice(&self.current[3].to_be_bytes());
        out.to_vec()
    }

    pub fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != 32 {
            return Err(DecodeError);
        }
        let mut limbs = [0u64; 4];
        limbs[0] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        limbs[1] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        limbs[2] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        limbs[3] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
        Ok(Self { current: limbs })
    }

    fn add_256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        [
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            a[2].wrapping_add(b[2]),
            a[3].wrapping_add(b[3]),
        ]
    }

    fn sub_256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        [
            a[0].wrapping_sub(b[0]),
            a[1].wrapping_sub(b[1]),
            a[2].wrapping_sub(b[2]),
            a[3].wrapping_sub(b[3]),
        ]
    }

    fn scale_256(a: [u64; 4], count: u64) -> [u64; 4] {
        [
            a[0].wrapping_mul(count),
            a[1].wrapping_mul(count),
            a[2].wrapping_mul(count),
            a[3].wrapping_mul(count),
        ]
    }

    /// Maps an element to a 256‑bit value.
    fn h(data: &[u8]) -> [u64; 4] {
        let mut h1: u64 = 0xcbf29ce484222325;
        let mut h2: u64 = 0xcbf29ce484222325;
        let mut h3: u64 = 0xcbf29ce484222325;
        let mut h4: u64 = 0xcbf29ce484222325;
        let prime: u64 = 0x100000001b3;
        for (i, &b) in data.iter().enumerate() {
            match i % 4 {
                0 => {
                    h1 = h1.wrapping_add(b as u64);
                    h1 = h1.rotate_left(13);
                    h1 ^= b as u64;
                    h1 = h1.wrapping_mul(prime);
                }
                1 => {
                    h2 = h2.wrapping_add(b as u64);
                    h2 = h2.rotate_left(17);
                    h2 ^= b as u64;
                    h2 = h2.wrapping_mul(prime);
                }
                2 => {
                    h3 = h3.wrapping_add(b as u64);
                    h3 = h3.rotate_left(19);
                    h3 ^= b as u64;
                    h3 = h3.wrapping_mul(prime);
                }
                3 => {
                    h4 = h4.wrapping_add(b as u64);
                    h4 = h4.rotate_left(23);
                    h4 ^= b as u64;
                    h4 = h4.wrapping_mul(prime);
                }
                _ => unreachable!(),
            }
        }
        [h1, h2, h3, h4]
    }
}

impl std::ops::Add for FastMultisetHash {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.combine(&rhs)
    }
}

impl std::ops::Add<&FastMultisetHash> for FastMultisetHash {
    type Output = Self;

    fn add(self, rhs: &FastMultisetHash) -> Self::Output {
        self.combine(rhs)
    }
}

impl std::ops::Add for &FastMultisetHash {
    type Output = FastMultisetHash;

    fn add(self, rhs: Self) -> Self::Output {
        self.combine(rhs)
    }
}

impl std::ops::Sub for &FastMultisetHash {
    type Output = FastMultisetHash;

    fn sub(self, rhs: Self) -> Self::Output {
        self.difference(rhs)
    }
}

impl std::ops::AddAssign for FastMultisetHash {
    fn add_assign(&mut self, rhs: Self) {
        self.current = Self::add_256(self.current, rhs.current);
    }
}

impl std::ops::AddAssign<&FastMultisetHash> for FastMultisetHash {
    fn add_assign(&mut self, rhs: &FastMultisetHash) {
        self.current = Self::add_256(self.current, rhs.current);
    }
}

impl std::ops::Sub for FastMultisetHash {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.difference(&rhs)
    }
}

impl std::ops::Sub<&FastMultisetHash> for FastMultisetHash {
    type Output = Self;

    fn sub(self, rhs: &FastMultisetHash) -> Self::Output {
        self.difference(rhs)
    }
}

impl std::ops::SubAssign for FastMultisetHash {
    fn sub_assign(&mut self, rhs: Self) {
        self.current = Self::sub_256(self.current, rhs.current);
    }
}

impl std::ops::SubAssign<&FastMultisetHash> for FastMultisetHash {
    fn sub_assign(&mut self, rhs: &FastMultisetHash) {
        self.current = Self::sub_256(self.current, rhs.current);
    }
}

impl MultisetHash for FastMultisetHash {
    fn new() -> Self {
        Self::new()
    }

    fn add(&mut self, data: &[u8]) {
        self.add(data)
    }

    fn remove(&mut self, data: &[u8]) {
        self.remove(data)
    }

    fn add_with_count(&mut self, data: &[u8], count: u64) {
        self.add_with_count(data, count)
    }

    fn remove_with_count(&mut self, data: &[u8], count: u64) {
        self.remove_with_count(data, count)
    }

    fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        self.add_elements(elements)
    }

    fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        self.remove_elements(elements)
    }

    fn combine(&self, other: &Self) -> Self {
        self.combine(other)
    }

    fn difference(&self, other: &Self) -> Self {
        self.difference(other)
    }

    fn get_compressed(&self) -> Option<Vec<u8>> {
        self.get_compressed()
    }

    fn get_digest(&self) -> Option<Vec<u8>> {
        self.get_digest()
    }

    fn to_compressed_bytes(&self) -> Vec<u8> {
        self.to_compressed_bytes()
    }

    fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from_compressed_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use std::collections::HashSet;

    #[test]
    #[ignore = "10M ops — run with `cargo test -- --ignored`"]
    fn test_intensive_basic() {
        let mut rng = rand::thread_rng();
        // Number of operations to perform
        let num_ops = 10_000_000;
        let mut ms = FastMultisetHash::new();
        // We'll record the state after each operation (including the initial empty state).
        let mut state_stack: Vec<Option<Vec<u8>>> = Vec::new();
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

    #[test]
    #[ignore = "10M multisets — run with `cargo test -- --ignored`"]
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
            // Record the hash
            if let Some(hash) = ms.get_compressed() {
                final_hashes.insert(hash);
            }
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
    fn test_fast_combine_and_count_smoke() {
        let mut a = FastMultisetHash::new();
        a.add_with_count(b"item", 4);
        let mut b = FastMultisetHash::new();
        for _ in 0..4 {
            b.add(b"item");
        }
        assert_eq!(a, b);

        let mut other = FastMultisetHash::new();
        other.add(b"extra");
        let merged = a.combine(&other);
        let via_op = a + other.clone();
        assert_eq!(merged, via_op);
        assert_eq!(merged.difference(&other), b);
    }
}
