#[macro_use]
extern crate tracing;
mod signer;
pub use signer::{GcpKeyRingRef, GcpSigner, GcpSignerError, KeySpecifier};
