use std::borrow::Cow;

use libafl::{
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    Error, HasNamedMetadata,
};
use libafl_bolts::Named;

use crate::plateau::SharedPlateauDetector;

/// Wrapper around any LibAFL Feedback that notifies a PlateauDetector
/// whenever new interesting coverage is found.
///
/// This is the bridge between LibAFL's feedback system and Achlys'
/// escalation engine. When the inner feedback reports a new interesting
/// input, the plateau timer is reset.
pub struct PlateauAwareFeedback<F> {
    inner: F,
    detector: SharedPlateauDetector,
    edge_count: usize,
}

impl<F> PlateauAwareFeedback<F> {
    pub fn new(inner: F, detector: SharedPlateauDetector) -> Self {
        Self {
            inner,
            detector,
            edge_count: 0,
        }
    }
}

impl<F: Named> Named for PlateauAwareFeedback<F> {
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

impl<F, S> StateInitializer<S> for PlateauAwareFeedback<F>
where
    F: StateInitializer<S>,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.init_state(state)
    }
}

impl<F, EM, I, OT, S> Feedback<EM, I, OT, S> for PlateauAwareFeedback<F>
where
    F: Feedback<EM, I, OT, S>,
    S: HasNamedMetadata,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let interesting = self
            .inner
            .is_interesting(state, manager, input, observers, exit_kind)?;

        if interesting {
            self.edge_count += 1;
            if let Ok(mut detector) = self.detector.lock() {
                detector.on_new_coverage(self.edge_count);
            }
        }

        Ok(interesting)
    }

}
