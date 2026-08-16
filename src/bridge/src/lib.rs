//! Target abstraction layer for Achlys.
//!
//! Defines the `Target` trait and provides backends for different
//! execution modes: in-process FFI, fork+exec, auto-compilation,
//! and off-hot-path sanitizer replay.

pub mod compiler;
pub mod forkexec;
pub mod inprocess;
pub mod sanitizer;
pub mod target;

#[cfg(test)]
mod micro;

pub use compiler::AutoCompiler;
pub use forkexec::ForkExecTarget;
pub use inprocess::{CoverageMap, InProcessTarget};
pub use sanitizer::{
    ReplayClass, ReplayReport, SanitizerReplayer, dedup_key, normalize_stack_signature,
};
pub use target::{InfraError, Target};
