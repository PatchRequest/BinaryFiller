//! Compile-/link-time binary filling for Windows PE agents.
//!
//! See workspace `docs/OPERATOR.md` for the full integration guide.
//!
//! ## Quick start
//!
//! ```ignore
//! // build.rs
//! fn main() {
//!     binary_filler_build::Builder::ops()
//!         .cover_preset("usb-utility")
//!         .corpus_from_env_or("/path/to/corpus")
//!         .emit()
//!         .expect("binary-filler");
//! }
//!
//! // main.rs
//! #![cfg_attr(windows, windows_subsystem = "windows")]
//!
//! fn main() {
//!     binary_filler::keep!();
//!     // agent entry...
//! }
//! ```
//!
//! `keep!` includes `$OUT_DIR/binary_filler/generated.rs` and calls its `keep()`
//! so section blobs and import anchors survive LTO.

/// Include build-script output and retain filler material through linking/LTO.
///
/// Must be invoked from the binary (or a crate whose `build.rs` ran
/// `binary_filler_build::Builder::emit`).
#[macro_export]
macro_rules! keep {
    () => {{
        mod __binary_filler_generated {
            #![allow(dead_code, non_upper_case_globals, unused_imports)]
            include!(concat!(env!("OUT_DIR"), "/binary_filler/generated.rs"));
        }
        __binary_filler_generated::keep();
    }};
}
