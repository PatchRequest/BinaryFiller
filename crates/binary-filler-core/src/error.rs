use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse TOML at {path}: {source}")]
    TomlParse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("failed to parse JSON at {path}: {source}")]
    JsonParse {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("invalid cover profile '{name}': {reason}")]
    InvalidCover { name: String, reason: String },

    #[error("invalid budget: {0}")]
    InvalidBudget(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("corpus not found or empty at {0}")]
    EmptyCorpus(PathBuf),

    #[error("cover '{0}' not found")]
    CoverNotFound(String),

    #[error("fill plan exceeds budget: {0}")]
    BudgetExceeded(String),

    /// Ops fail policy: a real corpus path/load is required.
    #[error("fail policy require_corpus: {0}")]
    RequireCorpus(String),

    /// Ops fail policy: synthetic filler blobs are forbidden.
    #[error("fail policy forbid_synthetic_blobs: {0}")]
    ForbidSyntheticBlobs(String),

    #[error("PE error: {0}")]
    Pe(String),

    #[error("verification failed: {0}")]
    VerifyFailed(String),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
