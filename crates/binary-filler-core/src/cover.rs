use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Which extra DLL imports the build should force into the PE IAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ImportProfile {
    /// No extra import anchors beyond what the agent already links.
    None,
    /// Typical GUI utility profile (user32, gdi32, shell32, …).
    #[default]
    Gui,
    /// Slightly broader desktop app set (gui + ole32/oleaut32/advapi32).
    DesktopApp,
}

/// PE subsystem intended by the cover story.
///
/// The consumer binary crate must still set `#![windows_subsystem = "..."]`
/// when targeting Windows; the build report records the expected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Subsystem {
    #[default]
    Gui,
    Console,
}

/// Operator-facing cover story baked into VERSIONINFO / resources / imports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverProfile {
    /// Stable id used in reports and corpus selection tags.
    pub name: String,

    pub company_name: String,
    pub product_name: String,
    pub file_description: String,
    pub internal_name: String,
    pub original_filename: String,
    pub legal_copyright: String,

    /// FILEVERSION / ProductVersion as four 16-bit components.
    pub file_version: [u16; 4],
    pub product_version: [u16; 4],

    #[serde(default)]
    pub subsystem: Subsystem,

    #[serde(default)]
    pub import_profile: ImportProfile,

    /// Optional icon path relative to the cover file's directory, or absolute.
    #[serde(default)]
    pub icon: Option<PathBuf>,

    /// Optional tags for corpus matching (e.g. `gui`, `editor`).
    #[serde(default)]
    pub tags: Vec<String>,
}

impl CoverProfile {
    pub fn load_toml(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let mut cover = Self::from_toml_str(&text, path.display().to_string())?;

        if let Some(icon) = cover.icon.take() {
            let resolved = resolve_relative_to_parent(path, &icon);
            cover.icon = Some(resolved);
        }

        Ok(cover)
    }

    /// Parse cover TOML from a string (`source` is only used in error messages).
    pub fn from_toml_str(text: &str, source: impl Into<String>) -> Result<Self> {
        let source = source.into();
        let cover: Self = toml::from_str(text).map_err(|source_err| Error::TomlParse {
            path: PathBuf::from(source),
            source: source_err,
        })?;
        cover.validate()?;
        Ok(cover)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::InvalidCover {
                name: self.name.clone(),
                reason: "name must not be empty".into(),
            });
        }
        for (label, value) in [
            ("company_name", &self.company_name),
            ("product_name", &self.product_name),
            ("file_description", &self.file_description),
            ("internal_name", &self.internal_name),
            ("original_filename", &self.original_filename),
        ] {
            if value.trim().is_empty() {
                return Err(Error::InvalidCover {
                    name: self.name.clone(),
                    reason: format!("{label} must not be empty"),
                });
            }
        }
        if self.original_filename.contains(['/', '\\']) {
            return Err(Error::InvalidCover {
                name: self.name.clone(),
                reason: "original_filename must be a bare file name".into(),
            });
        }
        Ok(())
    }

    pub fn file_version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.file_version[0],
            self.file_version[1],
            self.file_version[2],
            self.file_version[3]
        )
    }

    pub fn product_version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.product_version[0],
            self.product_version[1],
            self.product_version[2],
            self.product_version[3]
        )
    }

    /// Windows VERSIONINFO numeric dword pair encoding.
    pub fn file_version_ms_ls(&self) -> (u32, u32) {
        version_ms_ls(self.file_version)
    }

    pub fn product_version_ms_ls(&self) -> (u32, u32) {
        version_ms_ls(self.product_version)
    }
}

fn version_ms_ls(v: [u16; 4]) -> (u32, u32) {
    let ms = ((v[0] as u32) << 16) | (v[1] as u32);
    let ls = ((v[2] as u32) << 16) | (v[3] as u32);
    (ms, ls)
}

fn resolve_relative_to_parent(cover_path: &Path, icon: &Path) -> PathBuf {
    if icon.is_absolute() {
        icon.to_path_buf()
    } else if let Some(parent) = cover_path.parent() {
        parent.join(icon)
    } else {
        icon.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_cover_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cover.toml");
        let mut f = fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
name = "text-editor"
company_name = "Example Softworks"
product_name = "PlainEdit"
file_description = "Lightweight text editor"
internal_name = "plainedit"
original_filename = "plainedit.exe"
legal_copyright = "Copyright Example"
file_version = [1, 2, 3, 4]
product_version = [1, 2, 3, 4]
subsystem = "gui"
import_profile = "gui"
"#
        )
        .unwrap();

        let cover = CoverProfile::load_toml(&path).unwrap();
        assert_eq!(cover.name, "text-editor");
        assert_eq!(cover.file_version, [1, 2, 3, 4]);
        assert_eq!(cover.import_profile, ImportProfile::Gui);
    }
}
