//! Build-script integration for `binary-filler`.
//!
//! Call [`Builder::emit`] from the consumer crate's `build.rs`. This writes
//! generated Rust + a Windows `.rc` into `OUT_DIR` and, when targeting Windows,
//! compiles/embeds resources via `embed-resource`.

mod rc;
mod rustgen;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use binary_filler_core::select_plan;

pub use binary_filler_core::{
    cover_preset, preset_toml, Budget, Corpus, CoverProfile, EmitReport, Error, FailPolicy,
    FeatureSummary, FillPlan, ImportProfile, Subsystem, PRESET_NAMES,
};

/// Fluent builder intended for use inside `build.rs`.
#[derive(Debug)]
pub struct Builder {
    cover: Option<CoverProfile>,
    cover_path: Option<PathBuf>,
    preset_name: Option<String>,
    corpus_path: Option<PathBuf>,
    budget: Budget,
    fail: FailPolicy,
    enable_blobs: bool,
    enable_resources: bool,
    enable_import_anchors: bool,
    out_dir: Option<PathBuf>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    pub fn new() -> Self {
        Self {
            cover: None,
            cover_path: None,
            preset_name: None,
            corpus_path: None,
            budget: Budget::standard(),
            fail: FailPolicy::lab(),
            enable_blobs: true,
            enable_resources: true,
            enable_import_anchors: true,
            out_dir: None,
        }
    }

    /// Ops-oriented defaults: standard budget + [`FailPolicy::ops`].
    pub fn ops() -> Self {
        Self::new().fail_policy(FailPolicy::ops()).budget(Budget::ops())
    }

    /// Load a built-in cover preset (`usb-utility`, `text-editor`, …).
    pub fn cover_preset(mut self, name: impl Into<String>) -> Self {
        self.preset_name = Some(name.into());
        self
    }

    /// Load cover profile from a TOML file.
    pub fn cover_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.cover_path = Some(path.into());
        self
    }

    /// Use an already-constructed cover profile.
    pub fn cover(mut self, cover: CoverProfile) -> Self {
        self.cover = Some(cover);
        self
    }

    /// Optional goodware component corpus root.
    pub fn corpus(mut self, path: impl Into<PathBuf>) -> Self {
        self.corpus_path = Some(path.into());
        self
    }

    /// `BINARY_FILLER_CORPUS` env var, falling back to `fallback` if unset/empty.
    pub fn corpus_from_env_or(mut self, fallback: impl Into<PathBuf>) -> Self {
        let path = env::var_os("BINARY_FILLER_CORPUS")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| fallback.into());
        self.corpus_path = Some(path);
        self
    }

    pub fn budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    pub fn fail_policy(mut self, fail: FailPolicy) -> Self {
        self.fail = fail;
        self
    }

    pub fn enable_blobs(mut self, on: bool) -> Self {
        self.enable_blobs = on;
        self
    }

    pub fn enable_resources(mut self, on: bool) -> Self {
        self.enable_resources = on;
        self
    }

    pub fn enable_import_anchors(mut self, on: bool) -> Self {
        self.enable_import_anchors = on;
        self
    }

    /// Override `OUT_DIR` (tests). Normal `build.rs` usage leaves this unset.
    pub fn out_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.out_dir = Some(path.into());
        self
    }

    /// Plan, write artifacts, print `cargo:` instructions, embed Windows resources.
    pub fn emit(self) -> Result<EmitReport, EmitError> {
        let Builder {
            cover,
            cover_path,
            preset_name,
            corpus_path,
            budget,
            fail,
            enable_blobs,
            enable_resources,
            enable_import_anchors,
            out_dir,
        } = self;

        let out_dir = match out_dir {
            Some(p) => p,
            None => env::var_os("OUT_DIR")
                .map(PathBuf::from)
                .ok_or(EmitError::MissingOutDir)?,
        };

        let cover = resolve_cover(cover, cover_path.as_ref(), preset_name.as_deref())?;
        if let Some(path) = &cover_path {
            println!("cargo:rerun-if-changed={}", path.display());
        }
        println!("cargo:rerun-if-env-changed=BINARY_FILLER_CORPUS");
        if let Some(path) = &corpus_path {
            println!("cargo:rerun-if-changed={}", path.display());
        }

        let corpus = load_corpus(corpus_path.as_ref(), &fail)?;
        let mut plan =
            select_plan(cover, budget, corpus.as_ref(), &fail).map_err(EmitError::Core)?;

        if !enable_blobs {
            plan.blobs.clear();
            plan.synthetic_blobs = false;
        }
        if !enable_import_anchors {
            plan.import_profile = binary_filler_core::ImportProfile::None;
        }

        let gen_dir = out_dir.join("binary_filler");
        fs::create_dir_all(&gen_dir).map_err(|e| EmitError::Io(gen_dir.clone(), e))?;

        let mut generated_files = Vec::new();
        let mut warnings = Vec::new();

        let blob_manifest = write_blobs(&gen_dir, &plan)?;
        for p in &blob_manifest {
            generated_files.push(p.display().to_string());
        }

        let generated_rs = gen_dir.join("generated.rs");
        let rs = rustgen::render_generated(&plan, &blob_manifest, enable_import_anchors);
        fs::write(&generated_rs, rs).map_err(|e| EmitError::Io(generated_rs.clone(), e))?;
        generated_files.push(generated_rs.display().to_string());

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".into());
        let targeting_windows = target_os == "windows";
        let mut resources_embedded = false;

        if enable_resources {
            let rc_path = gen_dir.join("filler.rc");
            let rc_source = rc::render_rc(&plan.cover, &mut warnings)?;
            fs::write(&rc_path, rc_source).map_err(|e| EmitError::Io(rc_path.clone(), e))?;
            generated_files.push(rc_path.display().to_string());

            if targeting_windows {
                embed_resource::compile(&rc_path, embed_resource::NONE)
                    .manifest_optional()
                    .map_err(|e| EmitError::Resource(e.to_string()))?;
                resources_embedded = true;
            } else {
                warnings.push(format!(
                    "target OS is '{target_os}', not windows: VERSIONINFO/icon .rc was generated but not embedded"
                ));
            }
        }

        if targeting_windows && fail.require_resources_on_windows && enable_resources && !resources_embedded
        {
            return Err(EmitError::Msg(
                "fail policy require_resources_on_windows: resources were not embedded".into(),
            ));
        }

        match plan.cover.subsystem {
            binary_filler_core::Subsystem::Gui => {
                let note = "cover expects GUI subsystem: set #![windows_subsystem = \"windows\"] on the binary crate";
                warnings.push(note.into());
                if fail.emit_subsystem_cargo_warning {
                    println!("cargo:warning=binary-filler: {note}");
                }
            }
            binary_filler_core::Subsystem::Console => {}
        }

        let report = EmitReport {
            features: plan.feature_summary(),
            generated_files,
            warnings: warnings.clone(),
            target_os,
            resources_embedded,
        };

        let report_path = gen_dir.join("report.json");
        let report_json = serde_json::to_string_pretty(&report)
            .map_err(|e| EmitError::Msg(format!("serialize report: {e}")))?;
        fs::write(&report_path, report_json).map_err(|e| EmitError::Io(report_path.clone(), e))?;

        for w in &warnings {
            // Soft notes stay in report.json; only policy-driven items use cargo:warning above.
            let _ = w;
        }

        // Always surface non-subsystem warnings that are actionable (missing icon, host OS).
        for w in &report.warnings {
            if w.contains("not windows") || w.contains("icon not found") {
                println!("cargo:warning=binary-filler: {w}");
            }
        }

        Ok(report)
    }
}

fn resolve_cover(
    cover: Option<CoverProfile>,
    cover_path: Option<&PathBuf>,
    preset_name: Option<&str>,
) -> Result<CoverProfile, EmitError> {
    if let Some(cover) = cover {
        cover.validate().map_err(EmitError::Core)?;
        return Ok(cover);
    }
    if let Some(name) = preset_name {
        return cover_preset(name).map_err(EmitError::Core);
    }
    let path = cover_path.ok_or(EmitError::MissingCover)?;
    CoverProfile::load_toml(path).map_err(EmitError::Core)
}

fn load_corpus(
    corpus_path: Option<&PathBuf>,
    fail: &FailPolicy,
) -> Result<Option<Corpus>, EmitError> {
    let Some(path) = corpus_path else {
        if fail.require_corpus {
            return Err(EmitError::Msg(
                "fail policy require_corpus: no corpus path configured".into(),
            ));
        }
        return Ok(None);
    };
    if !path.exists() {
        if fail.require_corpus {
            return Err(EmitError::Msg(format!(
                "fail policy require_corpus: corpus path does not exist: {}",
                path.display()
            )));
        }
        println!(
            "cargo:warning=binary-filler: corpus path {} does not exist; using synthetic blobs",
            path.display()
        );
        return Ok(None);
    }
    Corpus::load(path).map(Some).map_err(EmitError::Core)
}

fn write_blobs(gen_dir: &Path, plan: &FillPlan) -> Result<Vec<PathBuf>, EmitError> {
    let blobs_dir = gen_dir.join("blobs");
    fs::create_dir_all(&blobs_dir).map_err(|e| EmitError::Io(blobs_dir.clone(), e))?;
    let mut paths = Vec::new();
    for blob in &plan.blobs {
        let path = blobs_dir.join(format!("{}.bin", blob.name));
        fs::write(&path, &blob.data).map_err(|e| EmitError::Io(path.clone(), e))?;
        paths.push(path);
    }
    Ok(paths)
}

#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("OUT_DIR is not set; call Builder from build.rs or set out_dir()")]
    MissingOutDir,

    #[error("no cover configured; use cover_preset(), cover_file(), or cover()")]
    MissingCover,

    #[error(transparent)]
    Core(#[from] binary_filler_core::Error),

    #[error("I/O error at {0}: {1}")]
    Io(PathBuf, std::io::Error),

    #[error("resource compile failed: {0}")]
    Resource(String),

    #[error("{0}")]
    Msg(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn emit_writes_generated_module_and_report() {
        let dir = tempfile::tempdir().unwrap();
        let cover_path = dir.path().join("cover.toml");
        let mut f = fs::File::create(&cover_path).unwrap();
        write!(
            f,
            r#"
name = "unit"
company_name = "Co"
product_name = "Prod"
file_description = "Desc"
internal_name = "unit"
original_filename = "unit.exe"
legal_copyright = "c"
file_version = [1, 0, 0, 0]
product_version = [1, 0, 0, 0]
import_profile = "none"
subsystem = "console"
"#
        )
        .unwrap();

        let out = dir.path().join("out");
        let report = Builder::new()
            .cover_file(&cover_path)
            .out_dir(&out)
            .budget(Budget::standard().with_max_blob_bytes(1024))
            .enable_import_anchors(false)
            .emit()
            .unwrap();

        assert_eq!(report.features.cover_name, "unit");
        assert!(report.features.blob_count >= 1);
        assert!(out.join("binary_filler/generated.rs").is_file());
        assert!(out.join("binary_filler/filler.rc").is_file());
        assert!(out.join("binary_filler/report.json").is_file());
    }

    #[test]
    fn emit_from_preset_ops_requires_corpus() {
        let dir = tempfile::tempdir().unwrap();
        let err = Builder::ops()
            .cover_preset("usb-utility")
            .out_dir(dir.path().join("out"))
            .emit()
            .unwrap_err();
        assert!(
            err.to_string().contains("require_corpus") || err.to_string().contains("corpus"),
            "{err}"
        );
    }
}
