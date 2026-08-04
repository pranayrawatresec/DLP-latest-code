//! Library surface of the DLP agent. Exposes the pure-computation pieces so
//! integration tests (tests/golden_vectors.rs, tests/usb_audit.rs) can gate
//! them, and the shared config/storage/USB-channel modules so the binary and
//! the tests use ONE set of types (no duplicate-type mismatches).
//!
//! Windows-only side effects inside these modules are `#[cfg(windows)]`-gated
//! with non-Windows stubs, so the library still builds and its pure logic still
//! runs cross-platform (the golden-vector tests are cross-platform).

pub mod browser_host;
pub mod clipboard;
pub mod config;
pub mod detect;
pub mod netfilter;
pub mod storage;
pub mod usb;
