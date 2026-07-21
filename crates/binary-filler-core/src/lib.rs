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
mod ingest;
mod pe_cert;
mod plan;
mod presets;
mod report;

pub use budget::{shannon_entropy, Budget};
pub use corpus::{ChunkMeta, Corpus, CorpusComponent};
pub use cover::{CoverProfile, ImportProfile, Subsystem};
pub use error::{Error, Result};
pub use fail_policy::FailPolicy;
pub use ingest::{ingest_file, IngestOptions, IngestReport};
pub use pe_cert::{
    extract_certificate_table, security_directory, stamp_certificate_bytes, stamp_certificate_file,
    strip_certificate_table, CertStampReport,
};
pub use plan::{select_plan, FillPlan, PlannedBlob};
pub use presets::{cover_preset, preset_toml, PRESET_NAMES};
pub use report::{EmitReport, FeatureSummary};
