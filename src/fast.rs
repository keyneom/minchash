use rayon::prelude::*;
use crate::MultisetHash;

#[derive(Clone)]
pub struct FastMultisetHash {
    pub current: [u64; 4],
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

    pub fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        let sum = elements
            .par_iter()
            .map(|element| Self::h(element.as_ref()))
            .reduce(|| [0, 0, 0, 0], Self::add_256);
        self.current = Self::add_256(self.current, sum);
    }

    pub fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        let sum = elements
            .par_iter()
            .map(|element| {
                let h = Self::h(element.as_ref());
                [h[0].wrapping_neg(), h[1].wrapping_neg(), h[2].wrapping_neg(), h[3].wrapping_neg()]
            })
            .reduce(|| [0, 0, 0, 0], Self::add_256);
        self.current = Self::add_256(self.current, sum);
    }

    pub fn get_compressed(&self) -> Option<Vec<u8>> {
        if self.current == [0, 0, 0, 0] {
            None
        } else {
            let mut out = [0u8; 32];
            out[0..8].copy_from_slice(&self.current[0].to_be_bytes());
            out[8..16].copy_from_slice(&self.current[1].to_be_bytes());
            out[16..24].copy_from_slice(&self.current[2].to_be_bytes());
            out[24..32].copy_from_slice(&self.current[3].to_be_bytes());
            Some(out.to_vec())
        }
    }

    pub fn get_digest(&self) -> Option<Vec<u8>> {
        self.get_compressed()
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
}

impl MultisetHash for FastMultisetHash {
    fn new() -> Self {
        Self::new() // Call the inherent impl
    }

    fn add(&mut self, data: &[u8]) {
        self.add(data) // Call the inherent impl
    }

    fn remove(&mut self, data: &[u8]) {
        self.remove(data) // Call the inherent impl
    }

    fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        self.add_elements(elements) // Call the inherent impl
    }

    fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        self.remove_elements(elements) // Call the inherent impl
    }

    fn get_compressed(&self) -> Option<Vec<u8>> {
        self.get_compressed() // Call the inherent impl
    }

    fn get_digest(&self) -> Option<Vec<u8>> {
        self.get_digest() // Call the inherent impl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use rand::prelude::*;

    #[test]
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
}