//! Long operations as named steps, logged when each starts as step `k` of `n`.

pub struct Progress {
    steps: usize,
    started: usize,
}
impl Progress {
    pub fn new(steps: usize) -> Self {
        Self { steps, started: 0 }
    }

    /// Logs the start of the next step: `event.name` is the step, `paymoney.step` its 1-based
    /// index and `paymoney.steps` how many there are.
    pub fn advance(&mut self, step: &str) {
        self.started += 1;
        tracing::info!(
            event.name = step,
            paymoney.step = self.started,
            paymoney.steps = self.steps
        );
    }
}
