// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! Foundational shared types used across every layer.
//!
//! Named `common` rather than `core` deliberately: a module literally named
//! `core` shadows Rust's built-in `core` crate in path resolution and is a
//! latent source of confusing errors. `common` carries the same intent without
//! the collision.

pub mod domain;
pub mod error;
pub mod transcript;

pub use error::VeilError;
pub use transcript::Transcript;
