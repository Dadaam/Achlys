use libafl::executors::ExitKind;

use crate::target::Target;

/// Raw pointer + length to an external coverage map (e.g. EDGES_MAP from SanCov).
///
/// # Safety
/// The caller must ensure the pointer remains valid for the lifetime of the target
/// and that no other code writes to this memory concurrently during execution.
pub struct CoverageMap {
    ptr: *mut u8,
    len: usize,
}

impl CoverageMap {
    /// Create a new coverage map from a raw pointer and length.
    ///
    /// # Safety
    /// `ptr` must point to a valid, mutable memory region of at least `len` bytes
    /// that remains valid for the lifetime of this struct.
    pub unsafe fn new(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Get a mutable slice to the coverage map.
    ///
    /// # Safety
    /// Caller must ensure no concurrent access to the underlying memory.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.ptr, self.len)
    }
}

// SAFETY: The coverage map is only accessed single-threaded within the fuzz loop.
unsafe impl Send for CoverageMap {}
unsafe impl Sync for CoverageMap {}

/// In-process target that calls a function (typically FFI) within the same process.
///
/// This is the fastest execution mode — no process spawn overhead.
/// Used for fuzzing libraries linked into the fuzzer binary.
pub struct InProcessTarget {
    harness: Box<dyn FnMut(&[u8]) -> ExitKind>,
    coverage: Option<CoverageMap>,
    observer_name: String,
}

impl InProcessTarget {
    /// Create a new in-process target with coverage feedback (graybox mode).
    ///
    /// # Safety
    /// The coverage map must remain valid for the lifetime of this target.
    pub unsafe fn with_coverage(
        harness: impl FnMut(&[u8]) -> ExitKind + 'static,
        coverage: CoverageMap,
        observer_name: impl Into<String>,
    ) -> Self {
        Self {
            harness: Box::new(harness),
            coverage: Some(coverage),
            observer_name: observer_name.into(),
        }
    }

    /// Create a new in-process target without coverage (blackbox mode).
    pub fn without_coverage(
        harness: impl FnMut(&[u8]) -> ExitKind + 'static,
        observer_name: impl Into<String>,
    ) -> Self {
        Self {
            harness: Box::new(harness),
            coverage: None,
            observer_name: observer_name.into(),
        }
    }
}

impl Target for InProcessTarget {
    fn execute(&mut self, input: &[u8]) -> ExitKind {
        (self.harness)(input)
    }

    fn coverage_map(&mut self) -> Option<&mut [u8]> {
        self.coverage.as_mut().map(|cm| {
            // SAFETY: Single-threaded access within fuzz loop
            unsafe { cm.as_mut_slice() }
        })
    }

    fn observer_name(&self) -> &str {
        &self.observer_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inprocess_blackbox() {
        let mut target = InProcessTarget::without_coverage(
            |input| {
                if input.contains(&0xff) {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                }
            },
            "test_observer",
        );

        assert_eq!(target.observer_name(), "test_observer");
        assert!(!target.has_coverage());

        assert!(matches!(target.execute(b"hello"), ExitKind::Ok));
        assert!(matches!(target.execute(&[0xff]), ExitKind::Crash));
    }

    #[test]
    fn test_inprocess_with_coverage() {
        let mut map = [0u8; 16];
        let ptr = map.as_mut_ptr();

        let mut target = unsafe {
            let cm = CoverageMap::new(ptr, 16);
            InProcessTarget::with_coverage(
                move |input| {
                    // Simulate coverage: set byte at index 0
                    *ptr = 1;
                    if input.len() > 5 {
                        *ptr.add(1) = 1;
                    }
                    ExitKind::Ok
                },
                cm,
                "edges_map",
            )
        };

        assert!(target.has_coverage());
        assert_eq!(target.coverage_map().unwrap().len(), 16);
        assert!(matches!(target.execute(b"hi"), ExitKind::Ok));
    }
}
