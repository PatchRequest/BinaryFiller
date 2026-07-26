//! Shared types and pure selection logic for compile-time binary filling.
//!
//! Windows resources/imports are applied by `binary-filler-build` during the
//! consumer crate's build script. Authenticode stamping is a post-link PE edit
//! ([`stamp_certificate_file`]) — the signature will not cryptographically verify.

mod budget;
mod corpus;
mod cover;
mod error;
mod fail_policy;
mod hashutil;
mod ingest;
mod pe_cert;
mod plan;
mod presets;
mod report;

pub use budget::{Budget, shannon_entropy};
pub use corpus::{ChunkMeta, Corpus, CorpusComponent, select_chunks};
pub use cover::{CoverProfile, ImportProfile, Subsystem};
pub use error::{Error, Result};
pub use fail_policy::FailPolicy;
pub use hashutil::{hex_sha256, utf16le_contains};
pub use ingest::{IngestOptions, IngestReport, ingest_file};
pub use pe_cert::{
    CertStampReport, extract_certificate_table, security_directory, stamp_certificate_bytes,
    stamp_certificate_file, strip_certificate_table,
};
pub use plan::{FillPlan, PlannedBlob, select_plan};
pub use presets::{PRESET_NAMES, cover_preset, preset_toml};
pub use report::{EmitReport, FeatureSummary};
