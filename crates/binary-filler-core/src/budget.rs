use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Hard limits enforced while selecting filler material at build time.
///
/// Builds fail closed when a plan would exceed these limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    /// Maximum total bytes of section blobs embedded into the binary.
    pub max_blob_bytes: usize,

    /// Refuse individual corpus chunks whose Shannon entropy (bits/byte) exceeds this.
    ///
    /// High-entropy chunks look packed/encrypted and work against the goal.
    pub max_chunk_entropy: f64,

    /// Refuse near-empty / zero-padding chunks (entropy below this).
    ///
    /// Pure zeros are common PE section padding and look artificial as fill.
    pub min_chunk_entropy: f64,

    /// Minimum size of an accepted corpus chunk (filters tiny noise files).
    pub min_chunk_bytes: usize,

    /// Maximum size of a single chunk before it is truncated or rejected.
    pub max_chunk_bytes: usize,
}

impl Default for Budget {
    /// Same as [`Self::standard`] — the lab/ops default footprint.
    fn default() -> Self {
        Self::standard()
    }
}

impl Budget {
    /// Lab/ops default: modest footprint (~32 KiB blobs).
    pub fn standard() -> Self {
        Self {
            max_blob_bytes: 32 * 1024,
            max_chunk_entropy: 6.0,
            min_chunk_entropy: 1.5,
            min_chunk_bytes: 256,
            max_chunk_bytes: 8 * 1024,
        }
    }

    /// Delivery-sensitive: small size increase.
    pub fn conservative() -> Self {
        Self {
            max_blob_bytes: 12 * 1024,
            max_chunk_entropy: 5.5,
            min_chunk_entropy: 1.5,
            min_chunk_bytes: 256,
            max_chunk_bytes: 4 * 1024,
        }
    }

    /// Stronger static pollution; still entropy-capped.
    pub fn aggressive() -> Self {
        Self {
            max_blob_bytes: 128 * 1024,
            max_chunk_entropy: 6.2,
            min_chunk_entropy: 1.25,
            min_chunk_bytes: 256,
            max_chunk_bytes: 16 * 1024,
        }
    }

    /// Alias for ops docs: same as [`Self::standard`].
    pub fn ops() -> Self {
        Self::standard()
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_blob_bytes == 0 {
            return Err(Error::InvalidBudget(
                "max_blob_bytes must be > 0 (or disable blobs explicitly in the builder)".into(),
            ));
        }
        if !(0.0..=8.0).contains(&self.max_chunk_entropy)
            || !(0.0..=8.0).contains(&self.min_chunk_entropy)
        {
            return Err(Error::InvalidBudget(
                "chunk entropy bounds must be within 0.0..=8.0".into(),
            ));
        }
        if self.min_chunk_entropy > self.max_chunk_entropy {
            return Err(Error::InvalidBudget(
                "min_chunk_entropy must be <= max_chunk_entropy".into(),
            ));
        }
        if self.min_chunk_bytes == 0 {
            return Err(Error::InvalidBudget("min_chunk_bytes must be > 0".into()));
        }
        if self.max_chunk_bytes < self.min_chunk_bytes {
            return Err(Error::InvalidBudget(
                "max_chunk_bytes must be >= min_chunk_bytes".into(),
            ));
        }
        if self.max_blob_bytes < self.min_chunk_bytes {
            return Err(Error::InvalidBudget(
                "max_blob_bytes must be >= min_chunk_bytes".into(),
            ));
        }
        Ok(())
    }

    pub fn with_max_blob_bytes(mut self, bytes: usize) -> Self {
        self.max_blob_bytes = bytes;
        self
    }

    pub fn with_max_chunk_entropy(mut self, entropy: f64) -> Self {
        self.max_chunk_entropy = entropy;
        self
    }

    pub fn with_max_chunk_bytes(mut self, bytes: usize) -> Self {
        self.max_chunk_bytes = bytes;
        self
    }
}

/// Shannon entropy in bits per byte (0.0 ..= 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros_is_zero() {
        assert_eq!(shannon_entropy(&[0; 100]), 0.0);
    }

    #[test]
    fn entropy_of_uniform_is_high() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "entropy was {e}");
    }

    #[test]
    fn default_budget_validates() {
        Budget::default().validate().unwrap();
    }

    #[test]
    fn default_matches_standard() {
        assert_eq!(Budget::default(), Budget::standard());
        assert_eq!(Budget::ops(), Budget::standard());
    }
}
