use crate::{DecodeError, MultisetHash};
use blake3;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone)]
pub struct SecureMultisetHash {
    current: ProjectivePoint,
}

impl Default for SecureMultisetHash {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SecureMultisetHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureMultisetHash")
            .field("compressed", &self.to_compressed_bytes())
            .finish()
    }
}

impl PartialEq for SecureMultisetHash {
    fn eq(&self, other: &Self) -> bool {
        self.current.to_affine() == other.current.to_affine()
    }
}

impl Eq for SecureMultisetHash {}

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

    pub fn add_with_count(&mut self, data: &[u8], count: u64) {
        if count == 0 {
            return;
        }
        self.current += Self::h(data) * Scalar::from(count);
    }

    pub fn remove_with_count(&mut self, data: &[u8], count: u64) {
        if count == 0 {
            return;
        }
        self.current += -(Self::h(data) * Scalar::from(count));
    }

    pub fn add_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        // All element points are multiples of G, so sum scalars then one mul:
        // sum(s_i * G) = (sum s_i) * G.
        let scalar_sum = Self::sum_element_scalars(elements);
        self.current += ProjectivePoint::GENERATOR * scalar_sum;
    }

    pub fn remove_elements<'a, T>(&mut self, elements: &'a [T])
    where
        T: AsRef<[u8]> + Sync,
    {
        let scalar_sum = Self::sum_element_scalars(elements);
        self.current += -(ProjectivePoint::GENERATOR * scalar_sum);
    }

    pub fn combine(&self, other: &Self) -> Self {
        Self {
            current: self.current + other.current,
        }
    }

    pub fn difference(&self, other: &Self) -> Self {
        Self {
            current: self.current + (-other.current),
        }
    }

    pub fn get_compressed(&self) -> Option<Vec<u8>> {
        if self.current == ProjectivePoint::IDENTITY {
            None
        } else {
            let affine = self.current.to_affine();
            Some(affine.to_sec1_point(true).as_bytes().to_vec())
        }
    }

    pub fn get_digest(&self) -> Option<Vec<u8>> {
        self.get_compressed().map(|compressed| {
            let digest = blake3::hash(&compressed);
            digest.as_bytes().to_vec()
        })
    }

    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        if self.current == ProjectivePoint::IDENTITY {
            // SEC1 encoding of the point at infinity
            vec![0x00]
        } else {
            let affine = self.current.to_affine();
            affine.to_sec1_point(true).as_bytes().to_vec()
        }
    }

    pub fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes == [0x00] {
            return Ok(Self::new());
        }
        let affine = AffinePoint::from_sec1_bytes(bytes).map_err(|_| DecodeError)?;
        Ok(Self {
            current: ProjectivePoint::from(affine),
        })
    }

    /// Hash an element to a secp256k1 scalar (blake3 digest reduced mod n).
    fn hash_to_scalar(data: &[u8]) -> Scalar {
        let hash = blake3::hash(data);
        let digest = FieldBytes::from(*hash.as_bytes());
        Scalar::reduce(&digest)
    }

    /// Helper function to hash an element (byte slice) to an EC point.
    fn h(data: &[u8]) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * Self::hash_to_scalar(data)
    }

    fn sum_element_scalars<'a, T>(elements: &'a [T]) -> Scalar
    where
        T: AsRef<[u8]> + Sync,
    {
        #[cfg(feature = "parallel")]
        {
            elements
                .par_iter()
                .map(|element| Self::hash_to_scalar(element.as_ref()))
                .reduce(|| Scalar::ZERO, |a, b| a + b)
        }
        #[cfg(not(feature = "parallel"))]
        {
            elements
                .iter()
                .map(|element| Self::hash_to_scalar(element.as_ref()))
                .fold(Scalar::ZERO, |a, b| a + b)
        }
    }
}

impl std::ops::Add for SecureMultisetHash {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.combine(&rhs)
    }
}

impl std::ops::Add<&SecureMultisetHash> for SecureMultisetHash {
    type Output = Self;

    fn add(self, rhs: &SecureMultisetHash) -> Self::Output {
        self.combine(rhs)
    }
}

impl std::ops::Add for &SecureMultisetHash {
    type Output = SecureMultisetHash;

    fn add(self, rhs: Self) -> Self::Output {
        self.combine(rhs)
    }
}

impl std::ops::Sub for &SecureMultisetHash {
    type Output = SecureMultisetHash;

    fn sub(self, rhs: Self) -> Self::Output {
        self.difference(rhs)
    }
}

impl std::ops::AddAssign for SecureMultisetHash {
    fn add_assign(&mut self, rhs: Self) {
        self.current += rhs.current;
    }
}

impl std::ops::AddAssign<&SecureMultisetHash> for SecureMultisetHash {
    fn add_assign(&mut self, rhs: &SecureMultisetHash) {
        self.current += rhs.current;
    }
}

impl std::ops::Sub for SecureMultisetHash {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.difference(&rhs)
    }
}

impl std::ops::Sub<&SecureMultisetHash> for SecureMultisetHash {
    type Output = Self;

    fn sub(self, rhs: &SecureMultisetHash) -> Self::Output {
        self.difference(rhs)
    }
}

impl std::ops::SubAssign for SecureMultisetHash {
    fn sub_assign(&mut self, rhs: Self) {
        self.current += -rhs.current;
    }
}

impl std::ops::SubAssign<&SecureMultisetHash> for SecureMultisetHash {
    fn sub_assign(&mut self, rhs: &SecureMultisetHash) {
        self.current += -rhs.current;
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
    use std::collections::HashMap;

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
            } else if *counts.get(&elem).unwrap() > 0 {
                ms.remove(elem.as_bytes());
                *counts.get_mut(&elem).unwrap() -= 1;
            } else {
                ms.add(elem.as_bytes());
                *counts.get_mut(&elem).unwrap() += 1;
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
    fn test_combine_matches_union() {
        let mut left = SecureMultisetHash::new();
        left.add_with_count(b"a", 2);
        left.add(b"b");

        let mut right = SecureMultisetHash::new();
        right.add(b"c");

        let merged = &left + &right;
        let mut expected = SecureMultisetHash::new();
        expected.add_with_count(b"a", 2);
        expected.add(b"b");
        expected.add(b"c");
        assert_eq!(merged, expected);
    }

    #[test]
    fn test_bytes_round_trip_continue() {
        let mut ms = SecureMultisetHash::new();
        ms.add(b"hello");
        let restored =
            SecureMultisetHash::try_from_compressed_bytes(&ms.to_compressed_bytes()).unwrap();
        assert_eq!(ms, restored);
        assert!(SecureMultisetHash::try_from_compressed_bytes(&[0xff, 0x00]).is_err());
    }

    #[test]
    fn test_bulk_matches_sequential() {
        let elems = [b"a".as_slice(), b"b", b"c", b"a"];
        let mut bulk = SecureMultisetHash::new();
        bulk.add_elements(&elems);
        let mut seq = SecureMultisetHash::new();
        for e in elems {
            seq.add(e);
        }
        assert_eq!(bulk, seq);
        bulk.remove_elements(&[b"a".as_slice(), b"c"]);
        seq.remove(b"a");
        seq.remove(b"c");
        assert_eq!(bulk, seq);
    }
}
