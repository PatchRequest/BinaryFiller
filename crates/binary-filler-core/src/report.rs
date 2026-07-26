use serde::{Deserialize, Serialize};

/// Compact summary suitable for `OUT_DIR` JSON and CI artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSummary {
    pub cover_name: String,
    pub blob_count: usize,
    pub total_blob_bytes: usize,
    pub average_blob_entropy: f64,
    pub import_profile: String,
    pub subsystem: String,
    pub synthetic_blobs: bool,
    pub has_icon: bool,
    /// Source paths (corpus-relative) or synthetic markers for each planned blob.
    #[serde(default)]
    pub blob_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmitReport {
    pub features: FeatureSummary,
    pub generated_files: Vec<String>,
    pub warnings: Vec<String>,
    pub target_os: String,
    pub resources_embedded: bool,
}
