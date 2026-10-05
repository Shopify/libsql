//! Test hooks for fence race tests (`docs/NAMESPACE_FENCE.md` section 16).
//!
//! The crate has no failpoint library. Instead, a [`FenceController`] built by the library's
//! own test build carries a `FenceTestHooks`: named points on the transition path where a
//! test can park the task until it releases it, or inject a failure. Race tests are written
//! against these points and never against elapsed time. Outside `cfg(test)` only the point
//! names exist, and reaching a point does nothing.
//!
//! [`FenceController`]: super::controller::FenceController

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use parking_lot::Mutex;
#[cfg(test)]
use tokio::sync::Notify;

use super::outcome::FenceError;

/// A named point on a fence transition or a gated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPoint {
    /// The in-memory `INSTALLING` gate of a closing transition has been published.
    AfterInstallingGate,
    /// Under the transition lock, immediately before the metastore transaction runs.
    BeforeMetastoreCommit,
    /// The metastore transaction returned a committed result.
    AfterMetastoreCommit,
    /// The committed result is about to be published to the gate.
    BeforeGatePublish,
    /// In `begin_write_txn`, after the gate check admitted the transaction.
    InBeginWriteTxnAfterCheck,
    /// The connection manager released the write slot.
    AfterManagerRelease,
    /// A drain is about to read the frozen boundary.
    BeforeBoundaryCapture,
    /// The rows of a quarantined target were committed; the target is not published yet.
    AfterTargetRowsCommitted,
    /// The gate is published; the answer is about to be returned.
    BeforeResponse,
}

#[cfg(test)]
/// What happens when a task reaches an armed point. Every action fires once: reaching the
/// point disarms it.
#[derive(Debug, Clone)]
pub enum HookAction {
    /// Signal `reached`, then wait until `resume` is notified.
    Pause {
        reached: Arc<Notify>,
        resume: Arc<Notify>,
    },
    /// Fail at this point with `error`, as if the step had failed before it took effect.
    Fail(FenceError),
    /// At `AfterMetastoreCommit`: report the commit as indeterminate even though it happened,
    /// which is what a lost commit acknowledgement looks like to the controller. At
    /// `BeforeMetastoreCommit`: report it as indeterminate without running it, which is a
    /// commit that failed without applying but whose outcome the controller cannot know.
    Indeterminate,
}

/// What the task that reached a point has to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    Continue,
    Fail(FenceError),
    Indeterminate,
}

#[cfg(test)]
/// The armed points of one controller.
#[derive(Debug, Default)]
pub struct FenceTestHooks {
    armed: Mutex<HashMap<HookPoint, HookAction>>,
}

#[cfg(test)]
/// The handles a test uses to follow a paused task.
#[derive(Debug, Clone)]
pub struct Paused {
    pub reached: Arc<Notify>,
    pub resume: Arc<Notify>,
}

#[cfg(test)]
impl Paused {
    /// Wait until the task reaches the point.
    pub async fn reached(&self) {
        self.reached.notified().await
    }

    /// Let the task continue.
    pub fn resume(&self) {
        self.resume.notify_one()
    }
}

#[cfg(test)]
impl FenceTestHooks {
    pub fn arm(&self, point: HookPoint, action: HookAction) {
        self.armed.lock().insert(point, action);
    }

    /// Arm `point` to pause, returning the handles to wait for it and to release it.
    pub fn pause_at(&self, point: HookPoint) -> Paused {
        let paused = Paused {
            reached: Arc::new(Notify::new()),
            resume: Arc::new(Notify::new()),
        };
        self.arm(
            point,
            HookAction::Pause {
                reached: paused.reached.clone(),
                resume: paused.resume.clone(),
            },
        );
        paused
    }

    pub fn fail_at(&self, point: HookPoint, error: FenceError) {
        self.arm(point, HookAction::Fail(error));
    }

    /// Called by the code under test when it reaches `point`.
    pub async fn hit(&self, point: HookPoint) -> HookOutcome {
        let action = self.armed.lock().remove(&point);
        match action {
            None => HookOutcome::Continue,
            Some(HookAction::Pause { reached, resume }) => {
                // `notify_one` stores a permit, so a test that starts waiting after the task
                // got here still sees it.
                reached.notify_one();
                resume.notified().await;
                HookOutcome::Continue
            }
            Some(HookAction::Fail(e)) => HookOutcome::Fail(e),
            Some(HookAction::Indeterminate) => HookOutcome::Indeterminate,
        }
    }
}
