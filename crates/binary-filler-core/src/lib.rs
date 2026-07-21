//! Shared types and pure selection logic for compile-time binary filling.
//!
//! This crate has no PE writer and no Windows-only runtime code. It is safe to
//! unit-test on any host. Windows PE resources/imports are applied by
//! `binary-filler-build` during the consumer crate's build script.

mod budget;
mod corpus;
mod cover;
mod error;
mod fail_policy;
mod ingest;
mod plan;
mod presets;
mod report;

pub use budget::{shannon_entropy, Budget};
pub use corpus::{ChunkMeta, Corpus, CorpusComponent};
pub use cover::{CoverProfile, ImportProfile, Subsystem};
pub use error::{Error, Result};
pub use fail_policy::FailPolicy;
pub use ingest::{ingest_file, IngestOptions, IngestReport};
pub use plan::{select_plan, FillPlan, PlannedBlob};
pub use presets::{cover_preset, preset_toml, PRESET_NAMES};
pub use report::{EmitReport, FeatureSummary};
