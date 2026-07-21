use crate::budget::Budget;
use crate::corpus::{select_chunks, ChunkMeta, Corpus};
use crate::cover::{CoverProfile, ImportProfile};
use crate::error::{Error, Result};
use crate::fail_policy::FailPolicy;
use crate::report::FeatureSummary;

/// Fully resolved fill plan ready for `binary-filler-build` to emit.
#[derive(Debug, Clone)]
pub struct FillPlan {
    pub cover: CoverProfile,
    pub budget: Budget,
    pub blobs: Vec<PlannedBlob>,
    pub import_profile: ImportProfile,
    /// True when blobs were synthesized because no corpus was provided.
    pub synthetic_blobs: bool,
}

#[derive(Debug, Clone)]
pub struct PlannedBlob {
    pub name: String,
    pub data: Vec<u8>,
    pub entropy: f64,
    pub source: String,
}

/// Build a plan from cover + optional corpus under a fail policy.
///
/// When `corpus` is `None` and synthetic blobs are allowed, low-entropy synthetic
/// material is generated up to the budget.
pub fn select_plan(
    cover: CoverProfile,
    budget: Budget,
    corpus: Option<&Corpus>,
    fail: &FailPolicy,
) -> Result<FillPlan> {
    budget.validate()?;
    cover.validate()?;

    if fail.require_corpus && corpus.is_none() {
        return Err(Error::Msg(
            "fail policy require_corpus: no corpus loaded (set BINARY_FILLER_CORPUS or Builder::corpus)".into(),
        ));
    }

    let import_profile = cover.import_profile;
    let (blobs, synthetic_blobs) = match corpus {
        Some(corpus) => {
            let selected = plan_from_corpus(&cover, &budget, corpus)?;
            if selected.is_empty() {
                if fail.forbid_synthetic_blobs {
                    return Err(Error::Msg(
                        "fail policy forbid_synthetic_blobs: corpus had no eligible chunks under budget"
                            .into(),
                    ));
                }
                (synthetic_blobs_for_budget(&budget), true)
            } else {
                (selected, false)
            }
        }
        None => {
            if fail.forbid_synthetic_blobs {
                return Err(Error::Msg(
                    "fail policy forbid_synthetic_blobs: no corpus available".into(),
                ));
            }
            (synthetic_blobs_for_budget(&budget), true)
        }
    };

    Ok(FillPlan {
        cover,
        budget,
        blobs,
        import_profile,
        synthetic_blobs,
    })
}

fn plan_from_corpus(
    cover: &CoverProfile,
    budget: &Budget,
    corpus: &Corpus,
) -> Result<Vec<PlannedBlob>> {
    let components = corpus.components_for_tags(&cover.tags);
    let chunk_refs: Vec<&ChunkMeta> = components.iter().flat_map(|c| c.chunks.iter()).collect();
    let selected = select_chunks(chunk_refs, budget);

    let mut blobs = Vec::with_capacity(selected.len());
    for (idx, meta) in selected.into_iter().enumerate() {
        let mut data = corpus.read_chunk(meta)?;
        if data.len() > budget.max_chunk_bytes {
            data.truncate(budget.max_chunk_bytes);
        }
        blobs.push(PlannedBlob {
            name: format!("chunk_{idx:02}"),
            entropy: crate::budget::shannon_entropy(&data),
            source: meta.relative_path.display().to_string(),
            data,
        });
    }
    Ok(blobs)
}

fn synthetic_blobs_for_budget(budget: &Budget) -> Vec<PlannedBlob> {
    // Text-like, highly compressible material: stable across builds, low entropy.
    const SEED: &str = "Copyright (c) Example Softworks. Configuration template. \
        Language=en-US; Theme=Light; AutoSave=true; Font=Consolas; Size=11; \
        Plugins=spellcheck,diff,formatter; ";

    let target = budget
        .max_blob_bytes
        .min(budget.max_chunk_bytes.max(budget.min_chunk_bytes));
    if target < budget.min_chunk_bytes {
        return Vec::new();
    }

    let mut data = Vec::with_capacity(target);
    while data.len() < target {
        let remaining = target - data.len();
        let take = remaining.min(SEED.len());
        data.extend_from_slice(&SEED.as_bytes()[..take]);
    }

    let entropy = crate::budget::shannon_entropy(&data);
    vec![PlannedBlob {
        name: "synthetic_00".into(),
        data,
        entropy,
        source: "synthetic:low-entropy-text".into(),
    }]
}

impl FillPlan {
    pub fn total_blob_bytes(&self) -> usize {
        self.blobs.iter().map(|b| b.data.len()).sum()
    }

    pub fn feature_summary(&self) -> FeatureSummary {
        let entropies: Vec<f64> = self.blobs.iter().map(|b| b.entropy).collect();
        let avg_entropy = if entropies.is_empty() {
            0.0
        } else {
            entropies.iter().sum::<f64>() / entropies.len() as f64
        };
        FeatureSummary {
            cover_name: self.cover.name.clone(),
            blob_count: self.blobs.len(),
            total_blob_bytes: self.total_blob_bytes(),
            average_blob_entropy: avg_entropy,
            import_profile: format!("{:?}", self.import_profile),
            subsystem: format!("{:?}", self.cover.subsystem),
            synthetic_blobs: self.synthetic_blobs,
            has_icon: self.cover.icon.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cover::Subsystem;

    fn sample_cover() -> CoverProfile {
        CoverProfile {
            name: "text-editor".into(),
            company_name: "Example".into(),
            product_name: "PlainEdit".into(),
            file_description: "Editor".into(),
            internal_name: "plainedit".into(),
            original_filename: "plainedit.exe".into(),
            legal_copyright: "Copyright".into(),
            file_version: [1, 0, 0, 0],
            product_version: [1, 0, 0, 0],
            subsystem: Subsystem::Gui,
            import_profile: ImportProfile::Gui,
            icon: None,
            tags: vec![],
        }
    }

    #[test]
    fn synthetic_plan_respects_budget() {
        let budget = Budget::default().with_max_blob_bytes(4096);
        let plan = select_plan(sample_cover(), budget.clone(), None, &FailPolicy::lab()).unwrap();
        assert!(plan.synthetic_blobs);
        assert!(plan.total_blob_bytes() <= budget.max_blob_bytes);
        assert!(!plan.blobs.is_empty());
    }

    #[test]
    fn ops_policy_rejects_missing_corpus() {
        let err = select_plan(
            sample_cover(),
            Budget::standard(),
            None,
            &FailPolicy::ops(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("require_corpus") || msg.contains("forbid_synthetic"),
            "{msg}"
        );
    }
}
