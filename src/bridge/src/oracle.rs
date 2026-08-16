//! Independent canonical coverage authority.
//!
//! Replays inputs on a coverage-instrumented target and admits only those
//! that add edges to a union bitmap. Published coverage must come from this
//! replay, not from a dirty worker map. Not on the worker hot path.

use std::io;

use achlys_protocol::{CoverageDigest, InputId};
use libafl::executors::ExitKind;

use crate::target::{InfraError, Target};

/// Owned coverage bitmap used for snapshots and the oracle union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageBitmap {
    map: Vec<u8>,
}

impl CoverageBitmap {
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self { map: vec![0; len] }
    }

    #[must_use]
    pub fn from_slice(map: &[u8]) -> Self {
        Self { map: map.to_vec() }
    }

    pub fn reset(&mut self) {
        self.map.fill(0);
    }

    /// OR bits from `other`. Returns how many edges became non-zero.
    pub fn union_from(&mut self, other: &[u8]) -> u32 {
        let mut newly = 0u32;
        for (slot, &bit) in self.map.iter_mut().zip(other.iter()) {
            if bit != 0 && *slot == 0 {
                newly = newly.saturating_add(1);
            }
            *slot |= bit;
        }
        newly
    }

    #[must_use]
    pub fn hit_indices(&self) -> Vec<u32> {
        self.map
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| (b != 0).then_some(i as u32))
            .collect()
    }

    /// Digest of the sorted hit-index set (`CoverageDigest::from_hit_indices`).
    #[must_use]
    pub fn digest(&self) -> CoverageDigest {
        let mut indices = self.hit_indices();
        indices.sort_unstable();
        CoverageDigest::from_hit_indices(&indices)
    }

    #[must_use]
    pub fn edge_count(&self) -> u32 {
        u32::try_from(self.hit_indices().len()).unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.map
    }
}

/// Result of replaying one input against the canonical build.
#[derive(Debug, Clone)]
pub struct Admission {
    pub input_id: InputId,
    pub digest: CoverageDigest,
    pub new_edges: u32,
    pub total_edges: u32,
    pub admitted: bool,
    pub exit: ExitKind,
}

/// Measurement authority: execute, snapshot, union, admit on new edges.
pub struct CanonicalOracle<T: Target> {
    target: T,
    union: CoverageBitmap,
}

impl<T: Target> CanonicalOracle<T> {
    /// Requires a target that exposes a coverage map.
    pub fn new(mut target: T) -> Result<Self, anyhow::Error> {
        let Some(map) = target.coverage_map() else {
            anyhow::bail!("canonical oracle requires a target with a coverage map");
        };
        let union = CoverageBitmap::new(map.len());
        Ok(Self { target, union })
    }

    /// Zero the target map, execute, snapshot, union, admit if `new_edges > 0`.
    ///
    /// Per-input `digest` is taken from the snapshot hit indices, never the union.
    pub fn replay(&mut self, input: &[u8]) -> Result<Admission, InfraError> {
        require_coverage_map(&mut self.target)?.fill(0);
        let exit = self.target.execute(input)?;
        let snapshot = CoverageBitmap::from_slice(require_coverage_map(&mut self.target)?);
        let new_edges = self.union.union_from(snapshot.as_slice());
        Ok(Admission {
            input_id: InputId::from_bytes(input),
            digest: snapshot.digest(),
            new_edges,
            total_edges: self.union.edge_count(),
            admitted: new_edges > 0,
            exit,
        })
    }

    #[must_use]
    pub fn union(&self) -> &CoverageBitmap {
        &self.union
    }

    #[must_use]
    pub fn report(&self, admitted: usize, rejected: usize, replayed: usize) -> OracleReport {
        OracleReport {
            digest: self.union.digest(),
            edge_count: self.union.edge_count(),
            admitted,
            rejected,
            replayed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleReport {
    pub digest: CoverageDigest,
    pub edge_count: u32,
    pub admitted: usize,
    pub rejected: usize,
    pub replayed: usize,
}

fn require_coverage_map(target: &mut impl Target) -> Result<&mut [u8], InfraError> {
    target.coverage_map().ok_or_else(|| InfraError::Write {
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "canonical oracle coverage map missing after construction",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inprocess::{CoverageMap, InProcessTarget};

    fn slot_harness(map: &mut [u8]) -> InProcessTarget {
        let ptr = map.as_mut_ptr();
        let len = map.len();
        let harness = move |input: &[u8]| {
            if let Some(&b) = input.first() {
                // SAFETY: `map` outlives the target; single-threaded test access only.
                unsafe {
                    *ptr.add((b as usize) % len) = 1;
                }
            }
            ExitKind::Ok
        };
        // SAFETY: `ptr` remains valid for the target lifetime; no concurrent writers.
        unsafe { InProcessTarget::with_coverage(harness, CoverageMap::new(ptr, len), "test_edges") }
    }

    #[test]
    fn union_from_admits_then_identical_map_adds_nothing() {
        let mut union = CoverageBitmap::new(8);
        let first = [0u8, 1, 0, 1, 0, 0, 0, 0];
        assert_eq!(union.union_from(&first), 2);
        assert_eq!(union.edge_count(), 2);
        assert_eq!(union.union_from(&first), 0);
        assert_eq!(union.edge_count(), 2);
    }

    #[test]
    fn digest_stable_for_same_hit_set() {
        let a = CoverageBitmap::from_slice(&[0, 1, 0, 2]);
        let b = CoverageBitmap::from_slice(&[0, 5, 0, 1]);
        let expected = CoverageDigest::from_hit_indices(&[1, 3]);
        assert_eq!(a.digest(), expected);
        assert_eq!(b.digest(), expected);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.hit_indices(), vec![1, 3]);
    }

    #[test]
    fn oracle_admits_distinct_slots_then_rejects_repeat() {
        let mut map = [0u8; 16];
        let mut oracle = CanonicalOracle::new(slot_harness(&mut map)).expect("coverage map");

        let first = oracle.replay(&[0]).expect("replay A");
        assert!(first.admitted);
        assert_eq!(first.new_edges, 1);
        assert_eq!(first.total_edges, 1);

        let second = oracle.replay(&[1]).expect("replay B");
        assert!(second.admitted);
        assert_eq!(second.new_edges, 1);
        assert_eq!(second.total_edges, 2);
        assert_ne!(first.digest, second.digest);

        let repeat = oracle.replay(&[0]).expect("replay A again");
        assert!(!repeat.admitted);
        assert_eq!(repeat.new_edges, 0);
        assert_eq!(repeat.total_edges, 2);
        assert_eq!(repeat.digest, first.digest);
    }

    #[test]
    fn replay_resets_map_so_snapshot_is_per_input() {
        let mut map = [0u8; 16];
        let mut oracle = CanonicalOracle::new(slot_harness(&mut map)).expect("coverage map");

        let a = oracle.replay(&[0]).expect("replay A");
        let b = oracle.replay(&[1]).expect("replay B");

        let only_a = CoverageDigest::from_hit_indices(&[0]);
        let only_b = CoverageDigest::from_hit_indices(&[1]);
        let both = CoverageDigest::from_hit_indices(&[0, 1]);

        assert_eq!(a.digest, only_a);
        assert_eq!(b.digest, only_b);
        assert_ne!(b.digest, both);
        assert_ne!(b.digest, oracle.union().digest());
        assert_eq!(oracle.union().digest(), both);
    }

    #[test]
    fn new_requires_coverage_map() {
        let target = InProcessTarget::without_coverage(|_| ExitKind::Ok, "none");
        assert!(CanonicalOracle::new(target).is_err());
    }
}
