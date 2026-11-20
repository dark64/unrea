//! A tiny, deterministic, dependency-free pseudo-random number generator.
//!
//! This crate deliberately avoids external dependencies. For the controlled,
//! *reproducible* randomness used by the variation engine and techniques we use
//! a SplitMix64 generator. It is not cryptographically secure; it only needs to
//! be fast and deterministic so that output is stable across runs.

/// A seedable SplitMix64 pseudo-random number generator.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Create a new generator from a 64-bit seed.
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// Return the next raw 64-bit value and advance the state.
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64 (Steele, Lea & Flood).
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Return a value in `0..bound` (uniform enough for our purposes).
    ///
    /// Returns 0 when `bound` is 0.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    /// Return `true` with probability roughly `numerator / denominator`.
    pub fn chance(&mut self, numerator: u32, denominator: u32) -> bool {
        if denominator == 0 {
            return false;
        }
        (self.next_u64() % denominator as u64) < numerator as u64
    }

    /// Pick a reference to a random element of a non-empty slice.
    ///
    /// Returns `None` if the slice is empty.
    pub fn choose<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let idx = self.below(items.len());
        Some(&items[idx])
    }

    /// Shuffle a slice in place (Fisher–Yates).
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        let len = items.len();
        if len < 2 {
            return;
        }
        for i in (1..len).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        // Extremely unlikely to match on the first draw.
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn below_respects_bound() {
        let mut r = Rng::new(7);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
    }

    #[test]
    fn choose_and_shuffle() {
        let mut r = Rng::new(99);
        let items = [1, 2, 3, 4, 5];
        assert!(r.choose::<i32>(&[]).is_none());
        assert!(items.contains(r.choose(&items).unwrap()));

        let mut v = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let original = v.clone();
        r.shuffle(&mut v);
        // Same multiset, likely different order.
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, original);
    }
}
