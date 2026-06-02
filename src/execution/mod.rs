//! Execution primitives — isolated, deterministic bytecode execution.
//!
//! No side effects, no file I/O, no allocation during execution.
//! Every run produces a deterministic root and auto-wipes its state.

pub mod vm;

pub use vm::MicroVM;
