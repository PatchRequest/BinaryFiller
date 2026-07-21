use serde::{Deserialize, Serialize};

/// Fail-closed controls for ops builds.
///
/// Defaults are lab-friendly (synthetic blobs allowed). Call [`FailPolicy::ops`]
/// for engagement builds that must use a real corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailPolicy {
    /// Fail when no corpus path is configured or the path cannot be loaded.
    pub require_corpus: bool,

    /// Fail when the plan would fall back to synthetic blobs.
    pub forbid_synthetic_blobs: bool,

    /// Fail on Windows targets if resources cannot be embedded.
    pub require_resources_on_windows: bool,

    /// Emit `cargo:warning` reminding the binary crate to set GUI subsystem.
    ///
    /// Off by default — the reminder stays in `report.json` either way.
    pub emit_subsystem_cargo_warning: bool,
}

impl Default for FailPolicy {
    fn default() -> Self {
        Self {
            require_corpus: false,
            forbid_synthetic_blobs: false,
            require_resources_on_windows: true,
            emit_subsystem_cargo_warning: false,
        }
    }
}

impl FailPolicy {
    /// Lab defaults (synthetic allowed, soft corpus).
    pub fn lab() -> Self {
        Self::default()
    }

    /// Engagement defaults: real corpus required, no synthetic filler.
    pub fn ops() -> Self {
        Self {
            require_corpus: true,
            forbid_synthetic_blobs: true,
            require_resources_on_windows: true,
            emit_subsystem_cargo_warning: false,
        }
    }
}
