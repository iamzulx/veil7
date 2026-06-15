// Author: Iamzulx
//! The engine's single error type.

/// Deliberately opaque: it never names *why* something failed, to avoid leaking
/// an oracle through error variants. One bit of failure to the outside world.
#[derive(Debug, PartialEq, Eq)]
pub enum VeilError {
    /// Entropy source unavailable.
    Entropy,
    /// A cryptographic operation failed (keygen / sign / verify).
    Crypto,
}
