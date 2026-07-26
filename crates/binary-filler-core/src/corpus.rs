use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::budget::{Budget, shannon_entropy};
use crate::error::{Error, Result};
use crate::hashutil::hex_sha256;

const INDEX_VERSION: u32 = 1;
const INDEX_FILE: &str = "index.json";

/// On-disk corpus of pre-extracted goodware components (no full EXEs required at fill time).
#[derive(Debug, Clone)]
pub struct Corpus {
    root: PathBuf,
    components: Vec<CorpusComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusComponent {
    pub id: String,
    pub tags: Vec<String>,
    pub chunks: Vec<ChunkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    /// Path relative to the corpus root.
    pub relative_path: PathBuf,
    pub byte_len: usize,
    pub entropy: f64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CorpusIndex {
    version: u32,
    components: Vec<CorpusComponent>,
}

impl Corpus {
    /// Load a corpus directory.
    ///
    /// Expected layout:
    /// ```text
    /// corpus/
    ///   index.json          # optional cache; rebuilt from components/ if missing/stale
    ///   components/
    ///     <id>/
    ///       meta.toml       # optional tags = ["gui", "editor"]
    ///       chunks/*.bin
    /// ```
    ///
    /// When `index.json` is present and consistent with on-disk chunk sizes, metadata is
    /// loaded without re-hashing every byte (fast path for build scripts).
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(Error::EmptyCorpus(root));
        }

        let components_dir = root.join("components");
        if !components_dir.is_dir() {
            return Err(Error::EmptyCorpus(root));
        }

        if let Some(corpus) = try_load_from_index(&root)? {
            return Ok(corpus);
        }

        let corpus = scan_components(&root)?;
        // Persist index for subsequent loads (best-effort; load still succeeds if write fails).
        let _ = corpus.write_index();
        Ok(corpus)
    }

    /// Rescan `components/` and rewrite `index.json`.
    pub fn rebuild_index(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let corpus = scan_components(&root)?;
        corpus.write_index()?;
        Ok(corpus)
    }

    /// Write `index.json` under the corpus root from the in-memory component list.
    pub fn write_index(&self) -> Result<()> {
        let index = CorpusIndex {
            version: INDEX_VERSION,
            components: self.components.clone(),
        };
        let path = self.root.join(INDEX_FILE);
        let json = serde_json::to_string_pretty(&index).map_err(|source| Error::JsonParse {
            path: path.clone(),
            source,
        })?;
        fs::write(&path, json).map_err(|e| Error::io(&path, e))?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn components(&self) -> &[CorpusComponent] {
        &self.components
    }

    /// Read chunk bytes from disk.
    pub fn read_chunk(&self, chunk: &ChunkMeta) -> Result<Vec<u8>> {
        let path = self.root.join(&chunk.relative_path);
        fs::read(&path).map_err(|e| Error::io(path, e))
    }

    /// Prefer components whose tags intersect the cover tags; fall back to all.
    pub fn components_for_tags(&self, tags: &[String]) -> Vec<&CorpusComponent> {
        if tags.is_empty() {
            return self.components.iter().collect();
        }
        let tagged: Vec<&CorpusComponent> = self
            .components
            .iter()
            .filter(|c| c.tags.iter().any(|t| tags.contains(t)))
            .collect();
        if tagged.is_empty() {
            self.components.iter().collect()
        } else {
            tagged
        }
    }
}

fn try_load_from_index(root: &Path) -> Result<Option<Corpus>> {
    let index_path = root.join(INDEX_FILE);
    if !index_path.is_file() {
        return Ok(None);
    }
    let text = match fs::read_to_string(&index_path) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let index: CorpusIndex = match serde_json::from_str(&text) {
        Ok(i) => i,
        Err(_) => return Ok(None),
    };
    if index.version != INDEX_VERSION || index.components.is_empty() {
        return Ok(None);
    }
    if !index_is_consistent(root, &index) {
        return Ok(None);
    }
    let mut components = index.components;
    components.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Some(Corpus {
        root: root.to_path_buf(),
        components,
    }))
}

/// Cheap consistency check: every listed chunk exists with matching size; no extra component dirs.
fn index_is_consistent(root: &Path, index: &CorpusIndex) -> bool {
    let components_dir = root.join("components");
    let Ok(entries) = fs::read_dir(&components_dir) else {
        return false;
    };
    let mut disk_ids = Vec::new();
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            disk_ids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    disk_ids.sort();
    let mut index_ids: Vec<String> = index.components.iter().map(|c| c.id.clone()).collect();
    index_ids.sort();
    if disk_ids != index_ids {
        return false;
    }

    for component in &index.components {
        for chunk in &component.chunks {
            let path = root.join(&chunk.relative_path);
            let Ok(meta) = fs::metadata(&path) else {
                return false;
            };
            if !meta.is_file() || meta.len() as usize != chunk.byte_len {
                return false;
            }
        }
    }
    true
}

fn scan_components(root: &Path) -> Result<Corpus> {
    let components_dir = root.join("components");
    if !components_dir.is_dir() {
        return Err(Error::EmptyCorpus(root.to_path_buf()));
    }

    let mut components = Vec::new();
    for entry in fs::read_dir(&components_dir).map_err(|e| Error::io(&components_dir, e))? {
        let entry = entry.map_err(|e| Error::io(&components_dir, e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        components.push(load_component(root, &path, id)?);
    }

    components.sort_by(|a, b| a.id.cmp(&b.id));
    if components.is_empty() {
        return Err(Error::EmptyCorpus(root.to_path_buf()));
    }

    Ok(Corpus {
        root: root.to_path_buf(),
        components,
    })
}

fn load_component(corpus_root: &Path, component_dir: &Path, id: String) -> Result<CorpusComponent> {
    let tags = load_tags(component_dir)?;
    let chunks_dir = component_dir.join("chunks");
    let mut chunks = Vec::new();

    if chunks_dir.is_dir() {
        for entry in WalkDir::new(&chunks_dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let data = fs::read(path).map_err(|e| Error::io(path, e))?;
            if data.is_empty() {
                continue;
            }
            let relative_path = path.strip_prefix(corpus_root).unwrap_or(path).to_path_buf();
            let sha256 = hex_sha256(&data);
            chunks.push(ChunkMeta {
                relative_path,
                byte_len: data.len(),
                entropy: shannon_entropy(&data),
                sha256,
            });
        }
    }

    chunks.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(CorpusComponent { id, tags, chunks })
}

fn load_tags(component_dir: &Path) -> Result<Vec<String>> {
    let meta_path = component_dir.join("meta.toml");
    if !meta_path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&meta_path).map_err(|e| Error::io(&meta_path, e))?;
    #[derive(Deserialize)]
    struct Meta {
        #[serde(default)]
        tags: Vec<String>,
    }
    let meta: Meta = toml::from_str(&text).map_err(|source| Error::TomlParse {
        path: meta_path,
        source,
    })?;
    Ok(meta.tags)
}

/// Filter and rank chunks under a budget. Lower entropy first, then smaller size.
pub fn select_chunks<'a>(
    chunks: impl IntoIterator<Item = &'a ChunkMeta>,
    budget: &Budget,
) -> Vec<&'a ChunkMeta> {
    let mut eligible: Vec<&ChunkMeta> = chunks
        .into_iter()
        .filter(|c| {
            c.byte_len >= budget.min_chunk_bytes
                && c.byte_len <= budget.max_chunk_bytes
                && c.entropy >= budget.min_chunk_entropy
                && c.entropy <= budget.max_chunk_entropy
        })
        .collect();

    eligible.sort_by(|a, b| {
        a.entropy
            .partial_cmp(&b.entropy)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.byte_len.cmp(&b.byte_len))
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });

    let mut chosen = Vec::new();
    let mut used = 0usize;
    for chunk in eligible {
        if used.saturating_add(chunk.byte_len) > budget.max_blob_bytes {
            continue;
        }
        used += chunk.byte_len;
        chosen.push(chunk);
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_corpus_and_selects_low_entropy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let chunks = root.join("components/sample/chunks");
        fs::create_dir_all(&chunks).unwrap();
        fs::write(chunks.join("a.bin"), vec![b'A'; 200]).unwrap();
        // high entropy-ish
        let mut high = Vec::with_capacity(200);
        for i in 0..200 {
            high.push((i * 17) as u8);
        }
        fs::write(chunks.join("b.bin"), &high).unwrap();
        let mut meta = fs::File::create(root.join("components/sample/meta.toml")).unwrap();
        writeln!(meta, r#"tags = ["gui"]"#).unwrap();

        let corpus = Corpus::load(root).unwrap();
        assert_eq!(corpus.components().len(), 1);
        assert!(root.join(INDEX_FILE).is_file(), "load should write index");

        let budget = Budget {
            max_blob_bytes: 10_000,
            max_chunk_entropy: 3.0,
            min_chunk_entropy: 0.0,
            min_chunk_bytes: 64,
            max_chunk_bytes: 10_000,
        };
        let all: Vec<&ChunkMeta> = corpus.components()[0].chunks.iter().collect();
        let selected = select_chunks(all, &budget);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].relative_path.ends_with("a.bin"));
    }

    #[test]
    fn second_load_uses_index_without_rescan_need() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let chunks = root.join("components/sample/chunks");
        fs::create_dir_all(&chunks).unwrap();
        fs::write(chunks.join("a.bin"), vec![b'B'; 300]).unwrap();

        let first = Corpus::load(root).unwrap();
        let first_sha = first.components()[0].chunks[0].sha256.clone();
        assert!(root.join(INDEX_FILE).is_file());

        let second = Corpus::load(root).unwrap();
        assert_eq!(second.components()[0].chunks[0].sha256, first_sha);
        assert_eq!(second.components()[0].chunks[0].byte_len, 300);
    }

    #[test]
    fn stale_index_triggers_rescan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let chunks = root.join("components/sample/chunks");
        fs::create_dir_all(&chunks).unwrap();
        fs::write(chunks.join("a.bin"), vec![b'C'; 256]).unwrap();
        let _ = Corpus::load(root).unwrap();

        // Grow the chunk so index byte_len no longer matches.
        fs::write(chunks.join("a.bin"), vec![b'C'; 512]).unwrap();
        let corpus = Corpus::load(root).unwrap();
        assert_eq!(corpus.components()[0].chunks[0].byte_len, 512);
    }

    #[test]
    fn tag_filter_prefers_matching_then_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (id, tags) in [
            ("gui-tool", r#"tags = ["gui"]"#),
            ("cli-tool", r#"tags = ["console"]"#),
        ] {
            let c = root.join(format!("components/{id}/chunks"));
            fs::create_dir_all(&c).unwrap();
            fs::write(c.join("a.bin"), vec![b'x'; 128]).unwrap();
            fs::write(root.join(format!("components/{id}/meta.toml")), tags).unwrap();
        }
        let corpus = Corpus::load(root).unwrap();
        let gui = corpus.components_for_tags(&["gui".into()]);
        assert_eq!(gui.len(), 1);
        assert_eq!(gui[0].id, "gui-tool");

        let none = corpus.components_for_tags(&["missing".into()]);
        assert_eq!(none.len(), 2, "fallback to all when no tag matches");
    }
}
