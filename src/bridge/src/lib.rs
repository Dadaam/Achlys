//! Target abstraction layer for Achlys.
//!
//! Defines the `Target` trait and provides backends for different
//! execution modes: in-process FFI, fork+exec, and auto-compilation.

pub mod compiler;
pub mod forkexec;
pub mod inprocess;
pub mod oracle;
pub mod target;

#[cfg(test)]
mod micro;

pub use compiler::AutoCompiler;
pub use forkexec::ForkExecTarget;
pub use inprocess::{CoverageMap, InProcessTarget};
pub use oracle::{Admission, CanonicalOracle, CoverageBitmap, OracleReport};
pub use target::{InfraError, Target};
