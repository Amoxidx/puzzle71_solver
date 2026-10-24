//! Duplicate Prevention Engine for Scanned Key Blocks.
//!
//! Architectural Comparison of Duplicate Prevention Strategies:
//!
//! 1. Full Bitmap:
//!    - Pros: O(1) exact membership test.
//!    - Cons: Range 2^70 with 2^24 blocks requires 2^46 bits = 8 Terabytes of RAM! Infeasible.
//!
//! 2. Naive HashSet / Range Database:
//!    - Pros: Exact matching.
//!    - Cons: Unbounded memory growth (16-32 bytes per scanned block, fragmentation, slow disk I/O).
//!
//! 3. Standalone Bloom Filter:
//!    - Pros: Constant tiny memory footprint (e.g. 8 MB), O(1) query time.
//!    - Cons: False positives can cause the solver to skip unsearched blocks. (Unacceptable alone).
//!
//! 4. Hybrid Compressed Interval Tree + Fast Bloom Pre-Filter (Chosen Solution):
//!    - Contiguous blocks are automatically merged into single intervals [start_block, end_block].
//!    - Binary search on sorted interval list (O(log N) lookup, minimal memory, compact JSON/binary storage).
//!    - Bloom Filter provides ultra-fast rejection without disk / heavy tree traversal.
//!    - Exact interval check resolves any Bloom false positive. Zero unsearched block skipping.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntervalSet {
    /// Disjoint sorted intervals of scanned block indices: `(start_block_idx, end_block_idx)` (inclusive)
    pub intervals: Vec<(u64, u64)>,
}

impl Default for IntervalSet {
    fn default() -> Self {
        Self::new()
    }
}

impl IntervalSet {
    pub fn new() -> Self {
        Self {
            intervals: Vec::new(),
        }
    }

    /// Check if a block index is already contained in the scanned intervals
    pub fn contains(&self, block_idx: u64) -> bool {
        self.intervals
            .binary_search_by(|&(start, end)| {
                if block_idx < start {
                    std::cmp::Ordering::Greater
                } else if block_idx > end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Insert a block index, merging adjacent intervals automatically
    pub fn insert(&mut self, block_idx: u64) {
        let idx = self
            .intervals
            .partition_point(|&(start, _)| start <= block_idx);
        if idx > 0 && self.intervals[idx - 1].1 >= block_idx {
            return;
        }
        let joins_left = idx > 0 && self.intervals[idx - 1].1.checked_add(1) == Some(block_idx);
        let joins_right = self
            .intervals
            .get(idx)
            .is_some_and(|&(start, _)| block_idx.checked_add(1) == Some(start));
        match (joins_left, joins_right) {
            (true, true) => {
                self.intervals[idx - 1].1 = self.intervals[idx].1;
                self.intervals.remove(idx);
            }
            (true, false) => self.intervals[idx - 1].1 = block_idx,
            (false, true) => self.intervals[idx].0 = block_idx,
            (false, false) => self.intervals.insert(idx, (block_idx, block_idx)),
        }
    }

    /// Insert an entire continuous block range [start, end] (inclusive)
    pub fn insert_range(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }
        self.intervals.push((start, end));
        self.intervals.sort_by_key(|&(s, _)| s);
        self.consolidate();
    }

    /// Merge overlapping or adjacent intervals
    fn consolidate(&mut self) {
        if self.intervals.is_empty() {
            return;
        }
        self.intervals.sort_by_key(|&(start, _)| start);

        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.intervals.len());
        let mut current = self.intervals[0];

        for &next in &self.intervals[1..] {
            if next.0 <= current.1.saturating_add(1) {
                current.1 = std::cmp::max(current.1, next.1);
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        self.intervals = merged;
    }

    /// Total number of individual blocks covered
    pub fn total_blocks_count(&self) -> u64 {
        self.intervals
            .iter()
            .map(|&(start, end)| end - start + 1)
            .sum()
    }
}

/// Compact Fast Bloom Filter for O(1) negative check
pub struct CompactBloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
}

impl CompactBloomFilter {
    /// Create a Bloom filter of given size in bits (default: 8 MB = 67,108,864 bits)
    pub fn new(num_bits: usize) -> Self {
        let num_u64s = num_bits.div_ceil(64);
        Self {
            bits: vec![0u64; num_u64s],
            num_bits,
        }
    }

    #[inline(always)]
    fn hashes(&self, item: u64) -> [usize; 4] {
        let h1 = item.wrapping_mul(0x517cc1b727220a95);
        let h2 = item.wrapping_mul(0x9e3779b97f4a7c15) ^ (item >> 32);
        let h3 = item.wrapping_mul(0xbf58476d1ce4e5b9);
        let h4 = item.wrapping_mul(0x94d049bb133111eb);

        [
            (h1 as usize) % self.num_bits,
            (h2 as usize) % self.num_bits,
            (h3 as usize) % self.num_bits,
            (h4 as usize) % self.num_bits,
        ]
    }

    pub fn insert(&mut self, item: u64) {
        for h in self.hashes(item) {
            let u64_idx = h / 64;
            let bit_idx = h % 64;
            self.bits[u64_idx] |= 1u64 << bit_idx;
        }
    }

    pub fn may_contain(&self, item: u64) -> bool {
        for h in self.hashes(item) {
            let u64_idx = h / 64;
            let bit_idx = h % 64;
            if (self.bits[u64_idx] & (1u64 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }
}

/// Hybrid Duplicate Filter combining Bloom Pre-filter with exact Interval Set
pub struct DuplicateFilter {
    bloom: CompactBloomFilter,
    pub intervals: IntervalSet,
}

impl Default for DuplicateFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DuplicateFilter {
    pub fn new() -> Self {
        Self {
            bloom: CompactBloomFilter::new(8 * 1024 * 1024), // 1MB Bloom
            intervals: IntervalSet::new(),
        }
    }

    pub fn from_intervals(intervals: IntervalSet) -> Self {
        let mut filter = Self::new();
        // Long merged intervals can represent trillions of blocks. Rebuilding each bit
        // would prevent an otherwise valid completed checkpoint from ever starting.
        let covered = intervals.intervals.iter().fold(0u64, |sum, &(start, end)| {
            sum.saturating_add(end.saturating_sub(start).saturating_add(1))
        });
        if covered > 1_000_000 {
            // A saturated Bloom filter has only false positives, all resolved by the
            // authoritative interval lookup. It can never skip an unsearched block.
            filter.bloom.bits.fill(u64::MAX);
        } else {
            for &(start, end) in &intervals.intervals {
                for b in start..=end {
                    filter.bloom.insert(b);
                }
            }
        }
        filter.intervals = intervals;
        filter
    }

    /// Check if a block index was already scanned
    pub fn is_scanned(&self, block_idx: u64) -> bool {
        if !self.bloom.may_contain(block_idx) {
            return false;
        }
        self.intervals.contains(block_idx)
    }

    /// Mark a block index as scanned
    pub fn mark_scanned(&mut self, block_idx: u64) {
        self.bloom.insert(block_idx);
        self.intervals.insert(block_idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_insertion_merges_both_neighbours_and_ignores_duplicates() {
        let mut intervals = IntervalSet::new();
        for index in [8, 2, 4, 3, 7, 5, 6, 2] {
            intervals.insert(index);
        }
        assert_eq!(intervals.intervals, vec![(2, 8)]);
        assert_eq!(intervals.total_blocks_count(), 7);
        assert!(!intervals.contains(1));
        assert!(!intervals.contains(9));
    }

    #[test]
    fn singleton_insertion_handles_u64_boundaries_without_wrapping() {
        let mut intervals = IntervalSet::new();
        for index in [u64::MAX, 0, u64::MAX - 1, 1] {
            intervals.insert(index);
        }
        assert_eq!(intervals.intervals, vec![(0, 1), (u64::MAX - 1, u64::MAX)]);
    }

    #[test]
    fn merged_large_intervals_keep_exact_membership_with_a_bounded_bloom_rebuild() {
        let filter = DuplicateFilter::from_intervals(IntervalSet {
            intervals: vec![(1, u64::MAX - 1)],
        });
        assert!(!filter.is_scanned(0));
        assert!(filter.is_scanned(1));
        assert!(filter.is_scanned(u64::MAX - 1));
        assert!(!filter.is_scanned(u64::MAX));
    }
}
