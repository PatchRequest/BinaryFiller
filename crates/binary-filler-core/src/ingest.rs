//! Extract low-entropy filler chunks from goodware binaries into a corpus layout.

use std::fs;
use std::path::{Path, PathBuf};

use crate::budget::{Budget, shannon_entropy};
use crate::corpus::Corpus;
use crate::error::{Error, Result};
use crate::hashutil::hex_sha256;

/// Options for ingesting one goodware file into a corpus component directory.
#[derive(Debug, Clone)]
pub struct IngestOptions {
    /// Component id under `corpus/components/<id>/`.
    pub component_id: String,
    /// Tags written to `meta.toml`.
    pub tags: Vec<String>,
    /// Sliding-window / section slice size for candidate chunks.
    pub window_bytes: usize,
    /// Stride when scanning raw bytes (and within large sections).
    pub stride_bytes: usize,
    /// Entropy / size filters (same rules as fill-time selection).
    pub budget: Budget,
    /// Maximum number of chunks to keep (after ranking by low entropy).
    pub max_chunks: usize,
    /// Prefer PE section contents when the file parses as a PE/COFF image.
    pub prefer_pe_sections: bool,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            component_id: String::new(),
            tags: Vec::new(),
            window_bytes: 4096,
            stride_bytes: 4096,
            budget: Budget {
                max_blob_bytes: usize::MAX,
                max_chunk_entropy: 6.0,
                min_chunk_entropy: 1.5,
                min_chunk_bytes: 256,
                max_chunk_bytes: 16 * 1024,
            },
            max_chunks: 64,
            prefer_pe_sections: true,
        }
    }
}

/// Summary of an ingest run.
#[derive(Debug, Clone)]
pub struct IngestReport {
    pub component_id: String,
    pub source: PathBuf,
    pub component_dir: PathBuf,
    pub bytes_read: usize,
    pub candidates_seen: usize,
    pub chunks_written: usize,
    pub total_chunk_bytes: usize,
    pub used_pe_sections: bool,
    pub average_entropy: f64,
}

/// Ingest `source` into `corpus_root/components/<id>/chunks/`.
///
/// Overwrites an existing component with the same id.
/// Rebuilds `corpus_root/index.json` when the components tree is non-empty.
pub fn ingest_file(
    corpus_root: impl AsRef<Path>,
    source: impl AsRef<Path>,
    mut options: IngestOptions,
) -> Result<IngestReport> {
    let corpus_root = corpus_root.as_ref();
    let source = source.as_ref();

    if options.component_id.trim().is_empty() {
        options.component_id = default_component_id(source);
    }
    if options.window_bytes == 0 || options.stride_bytes == 0 {
        return Err(Error::InvalidArgument(
            "window_bytes and stride_bytes must be > 0".into(),
        ));
    }
    if !(0.0..=8.0).contains(&options.budget.max_chunk_entropy) {
        return Err(Error::InvalidBudget(
            "max_chunk_entropy must be within 0.0..=8.0".into(),
        ));
    }
    if options.budget.min_chunk_bytes == 0
        || options.budget.max_chunk_bytes < options.budget.min_chunk_bytes
    {
        return Err(Error::InvalidBudget(
            "invalid min/max chunk byte bounds".into(),
        ));
    }

    let data = fs::read(source).map_err(|e| Error::io(source, e))?;
    if data.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "source file is empty: {}",
            source.display()
        )));
    }

    let mut used_pe_sections = false;
    let mut candidates: Vec<Vec<u8>> = Vec::new();

    if options.prefer_pe_sections {
        if let Some(section_slices) = pe_section_slices(&data) {
            used_pe_sections = true;
            for slice in section_slices {
                candidates.extend(window_slices(
                    slice,
                    options.window_bytes,
                    options.stride_bytes,
                ));
            }
        }
    }

    if candidates.is_empty() {
        candidates = window_slices(&data, options.window_bytes, options.stride_bytes);
    }

    let candidates_seen = candidates.len();
    let mut ranked = rank_chunks(candidates, &options.budget);
    if ranked.len() > options.max_chunks {
        ranked.truncate(options.max_chunks);
    }

    let component_dir = corpus_root.join("components").join(&options.component_id);
    let chunks_dir = component_dir.join("chunks");
    if component_dir.exists() {
        fs::remove_dir_all(&component_dir).map_err(|e| Error::io(&component_dir, e))?;
    }
    fs::create_dir_all(&chunks_dir).map_err(|e| Error::io(&chunks_dir, e))?;

    write_meta(&component_dir, &options.tags, source)?;

    let mut total_chunk_bytes = 0usize;
    let mut entropy_sum = 0.0;
    for (idx, chunk) in ranked.iter().enumerate() {
        let entropy = shannon_entropy(chunk);
        entropy_sum += entropy;
        total_chunk_bytes += chunk.len();
        let name = format!("chunk_{idx:04}_e{entropy:.2}.bin");
        let path = chunks_dir.join(name);
        fs::write(&path, chunk).map_err(|e| Error::io(&path, e))?;
    }

    // Keep corpus index.json in sync after component mutation.
    if corpus_root.join("components").is_dir() {
        let _ = Corpus::rebuild_index(corpus_root);
    }

    let chunks_written = ranked.len();
    let average_entropy = if chunks_written == 0 {
        0.0
    } else {
        entropy_sum / chunks_written as f64
    };

    Ok(IngestReport {
        component_id: options.component_id,
        source: source.to_path_buf(),
        component_dir,
        bytes_read: data.len(),
        candidates_seen,
        chunks_written,
        total_chunk_bytes,
        used_pe_sections,
        average_entropy,
    })
}

fn default_component_id(source: &Path) -> String {
    source
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "component".into())
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_meta(component_dir: &Path, tags: &[String], source: &Path) -> Result<()> {
    let mut body = String::new();
    body.push_str("# Generated by binary-filler ingest\n");
    body.push_str(&format!(
        "source = \"{}\"\n",
        escape_toml_string(&source.display().to_string())
    ));
    if tags.is_empty() {
        body.push_str("tags = []\n");
    } else {
        body.push_str("tags = [");
        for (i, tag) in tags.iter().enumerate() {
            if i > 0 {
                body.push_str(", ");
            }
            body.push_str(&format!("\"{}\"", escape_toml_string(tag)));
        }
        body.push_str("]\n");
    }
    let path = component_dir.join("meta.toml");
    fs::write(&path, body).map_err(|e| Error::io(path, e))
}

fn escape_toml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn window_slices(data: &[u8], window: usize, stride: usize) -> Vec<Vec<u8>> {
    if data.is_empty() || window == 0 || stride == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + window).min(data.len());
        let slice = &data[offset..end];
        if !slice.is_empty() {
            out.push(slice.to_vec());
        }
        if end == data.len() {
            break;
        }
        offset = offset.saturating_add(stride);
        if offset >= data.len() {
            break;
        }
    }
    out
}

/// Rank by ascending entropy, then size; drop high-entropy / out-of-range; dedupe by hash.
fn rank_chunks(candidates: Vec<Vec<u8>>, budget: &Budget) -> Vec<Vec<u8>> {
    let mut scored: Vec<(f64, Vec<u8>, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for mut chunk in candidates {
        if chunk.len() > budget.max_chunk_bytes {
            chunk.truncate(budget.max_chunk_bytes);
        }
        if chunk.len() < budget.min_chunk_bytes {
            continue;
        }
        let entropy = shannon_entropy(&chunk);
        if entropy > budget.max_chunk_entropy || entropy < budget.min_chunk_entropy {
            continue;
        }
        let hash = hex_sha256(&chunk);
        if !seen.insert(hash.clone()) {
            continue;
        }
        scored.push((entropy, chunk, hash));
    }

    scored.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.len().cmp(&b.1.len()))
            .then_with(|| a.2.cmp(&b.2))
    });

    scored.into_iter().map(|(_, data, _)| data).collect()
}

/// Section fill priority: lower is better for goodware-like static fill.
/// Prefer resource/read-only data; demote executable code; drop code when data exists.
fn section_fill_priority(name: &str, executable: bool) -> u8 {
    let lower = name.to_ascii_lowercase();
    if lower.contains("rsrc") {
        return 0;
    }
    if lower.contains("rdata") || lower == ".data" || lower.starts_with(".data") {
        return 1;
    }
    if lower.contains("reloc") || lower.contains("pdata") || lower.contains("edata") {
        return 2;
    }
    if executable || lower == ".text" || lower.starts_with(".text") {
        return 4;
    }
    3
}

/// Return section data slices for PE images, ordered for fill quality.
/// Executable sections are omitted when any non-executable candidate exists.
fn pe_section_slices(data: &[u8]) -> Option<Vec<&[u8]>> {
    let file = object::read::File::parse(data).ok()?;
    use object::read::Object;
    use object::read::ObjectSection;
    use object::{SectionFlags, pe};

    let mut ranked: Vec<(u8, &[u8])> = Vec::new();
    for section in file.sections() {
        let Ok(section_data) = section.data() else {
            continue;
        };
        if section_data.len() < 64 {
            continue;
        }
        let name = section.name().unwrap_or("");
        let executable = match section.flags() {
            SectionFlags::Coff { characteristics } => {
                characteristics & pe::IMAGE_SCN_MEM_EXECUTE != 0
            }
            _ => {
                let lower = name.to_ascii_lowercase();
                lower == ".text" || lower.starts_with(".text")
            }
        };
        let prio = section_fill_priority(name, executable);
        ranked.push((prio, section_data));
    }

    if ranked.is_empty() {
        return None;
    }

    ranked.sort_by(|a, b| a.0.cmp(&b.0));
    let has_data_like = ranked.iter().any(|(p, _)| *p < 4);
    let slices: Vec<&[u8]> = ranked
        .into_iter()
        .filter(|(p, _)| !has_data_like || *p < 4)
        .map(|(_, data)| data)
        .collect();

    if slices.is_empty() {
        None
    } else {
        Some(slices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingests_low_entropy_regions() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("good.bin");
        // Low entropy block + high entropy block
        let mut bytes = vec![b'A'; 8192];
        for i in 0..8192 {
            bytes.push((i * 41) as u8);
        }
        fs::write(&source, &bytes).unwrap();

        let corpus = dir.path().join("corpus");
        let report = ingest_file(
            &corpus,
            &source,
            IngestOptions {
                component_id: "good".into(),
                tags: vec!["gui".into()],
                window_bytes: 2048,
                stride_bytes: 2048,
                budget: Budget {
                    max_blob_bytes: usize::MAX,
                    max_chunk_entropy: 2.0,
                    min_chunk_entropy: 0.0,
                    min_chunk_bytes: 512,
                    max_chunk_bytes: 4096,
                },
                max_chunks: 16,
                prefer_pe_sections: false,
            },
        )
        .unwrap();

        assert!(report.chunks_written >= 1);
        assert!(!report.used_pe_sections);
        assert!(corpus.join("components/good/meta.toml").is_file());
        assert!(
            corpus.join("index.json").is_file(),
            "ingest should rebuild corpus index"
        );
    }

    #[test]
    fn section_priority_orders_rsrc_before_text() {
        assert!(section_fill_priority(".rsrc", false) < section_fill_priority(".text", true));
        assert!(section_fill_priority(".rdata", false) < section_fill_priority(".text", true));
        assert_eq!(section_fill_priority(".text", true), 4);
    }
}
