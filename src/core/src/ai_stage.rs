use libafl::{stages::Stage, stages::Restartable, Error};

/// Hybrid stage that alternates between havoc and AI mutations.
///
/// In Stage 2 (AI Hybrid), we don't stop havoc entirely — we mix in AI
/// predictions at a configurable ratio. This keeps throughput high
/// while injecting smart mutations.
///
/// The ratio means: run AI stage every `ai_ratio` executions,
/// havoc the rest. Default is 10 (1 AI per 10 havoc).
pub struct HybridStage<H, A> {
    havoc: H,
    ai: A,
    ai_ratio: usize,
    counter: usize,
}

impl<H, A> HybridStage<H, A> {
    /// Create a hybrid stage. `ai_ratio` = run AI every Nth execution.
    /// E.g., ai_ratio=10 means 1 AI mutation per 10 havoc mutations.
    pub fn new(havoc: H, ai: A, ai_ratio: usize) -> Self {
        Self {
            havoc,
            ai,
            ai_ratio: ai_ratio.max(1),
            counter: 0,
        }
    }
}

impl<E, EM, S, Z, H, A> Stage<E, EM, S, Z> for HybridStage<H, A>
where
    H: Stage<E, EM, S, Z>,
    A: Stage<E, EM, S, Z>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.counter += 1;

        if self.counter.is_multiple_of(self.ai_ratio) {
            self.ai.perform(fuzzer, executor, state, manager)
        } else {
            self.havoc.perform(fuzzer, executor, state, manager)
        }
    }
}

impl<S, H, A> Restartable<S> for HybridStage<H, A>
where
    H: Restartable<S>,
    A: Restartable<S>,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        if self.counter.is_multiple_of(self.ai_ratio) {
            self.ai.should_restart(state)
        } else {
            self.havoc.should_restart(state)
        }
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        if self.counter.is_multiple_of(self.ai_ratio) {
            self.ai.clear_progress(state)
        } else {
            self.havoc.clear_progress(state)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_ratio_default() {
        struct FakeStage;
        impl<E, EM, S, Z> Stage<E, EM, S, Z> for FakeStage {
            fn perform(&mut self, _: &mut Z, _: &mut E, _: &mut S, _: &mut EM) -> Result<(), Error> {
                Ok(())
            }
        }
        impl<S> Restartable<S> for FakeStage {
            fn should_restart(&mut self, _: &mut S) -> Result<bool, Error> { Ok(true) }
            fn clear_progress(&mut self, _: &mut S) -> Result<(), Error> { Ok(()) }
        }

        let hybrid = HybridStage::new(FakeStage, FakeStage, 10);
        assert_eq!(hybrid.ai_ratio, 10);
        assert_eq!(hybrid.counter, 0);
    }

    #[test]
    fn test_hybrid_ratio_min_one() {
        struct FakeStage;
        impl<E, EM, S, Z> Stage<E, EM, S, Z> for FakeStage {
            fn perform(&mut self, _: &mut Z, _: &mut E, _: &mut S, _: &mut EM) -> Result<(), Error> {
                Ok(())
            }
        }
        impl<S> Restartable<S> for FakeStage {
            fn should_restart(&mut self, _: &mut S) -> Result<bool, Error> { Ok(true) }
            fn clear_progress(&mut self, _: &mut S) -> Result<(), Error> { Ok(()) }
        }

        let hybrid = HybridStage::new(FakeStage, FakeStage, 0);
        assert_eq!(hybrid.ai_ratio, 1); // clamped to 1
    }
}
