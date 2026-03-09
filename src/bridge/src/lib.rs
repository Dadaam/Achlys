//! Target abstraction layer for Achlys.
//!
//! Defines the `Target` trait and provides backends for different
//! execution modes: in-process FFI, fork+exec, and auto-compilation.

pub mod target;
pub mod inprocess;
pub mod forkexec;
pub mod compiler;

pub use target::Target;
pub use inprocess::{InProcessTarget, CoverageMap};
pub use forkexec::ForkExecTarget;
pub use compiler::AutoCompiler;
