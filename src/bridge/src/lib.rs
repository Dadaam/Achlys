pub mod target;
pub mod inprocess;
pub mod forkexec;

pub use target::Target;
pub use inprocess::{InProcessTarget, CoverageMap};
pub use forkexec::ForkExecTarget;
