use k256::{ProjectivePoint, Scalar};
use blake3;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use rayon::prelude::*;
use crate::MultisetHash;

#[derive(Clone)]
pub struct SecureMultisetHash {
    pub current: ProjectivePoint,
}

impl SecureMultisetHash {
    pub fn new() -> Self {
        SecureMultisetHash {
            current: ProjectivePoint::IDENTITY,
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        self.current += Self::h(data);
    }

    pub fn remove(&mut self, data: &[u8]) {
        self.current += -Self::h(data);
    }

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

    pub fn get_compressed(&self) -> Option<Vec<u8>> {
        if self.current == ProjectivePoint::IDENTITY {
            None
        } else {
            let affine = self.current.to_affine();
            let encoded = affine.to_encoded_point(true); // compressed = true
            Some(encoded.as_bytes().to_vec())
        }
    }

    pub fn get_digest(&self) -> Option<Vec<u8>> {
        self.get_compressed().map(|compressed| {
            let digest = blake3::hash(&compressed);
            digest.as_bytes().to_vec()
        })
    }

    /// Helper function to hash an element (byte slice) to an EC point.
    fn h(data: &[u8]) -> ProjectivePoint {
        let hash = blake3::hash(data);
        let digest: [u8; 32] = *hash.as_bytes();
        let scalar = <Scalar as Reduce<U256>>::from_be_bytes_reduced(digest.into());
        ProjectivePoint::GENERATOR * scalar
    }
}

impl MultisetHash for SecureMultisetHash {
    fn new() -> Self {
        Self::new()
    }

    fn add(&mut self, data: &[u8]) {
        self.add(data)
    }

    fn remove(&mut self, data: &[u8]) {
        self.remove(data)
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

    fn get_compressed(&self) -> Option<Vec<u8>> {
        self.get_compressed()
    }

    fn get_digest(&self) -> Option<Vec<u8>> {
        self.get_digest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;
    use std::collections::HashMap;
    use rand::prelude::*;

    #[test]
    fn test_complex_random_operations() {
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
}