// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! Storage primitives — oblivious memory and integrity structures.
//!
//! Privacy property: every access pattern is independent of the logical
//! address. An observer who can see the memory bus learns nothing about
//! which data is being read or written.

pub mod oram;

pub use oram::ObliviousRAM;
