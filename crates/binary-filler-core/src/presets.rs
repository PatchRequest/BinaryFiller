//! Built-in cover presets for common red-team cover stories.
//!
//! These are intentionally generic (not real vendor branding). Operators should
//! customize company/product fields per engagement.

use crate::cover::CoverProfile;
use crate::error::{Error, Result};

/// All shipped preset identifiers.
pub const PRESET_NAMES: &[&str] = &[
    "usb-utility",
    "text-editor",
    "software-updater",
    "vpn-helper",
    "desktop-app",
];

/// Load a built-in cover preset by name.
pub fn cover_preset(name: &str) -> Result<CoverProfile> {
    let toml = preset_toml(name).ok_or_else(|| Error::CoverNotFound(name.to_string()))?;
    CoverProfile::from_toml_str(toml, format!("preset:{name}"))
}

/// Raw TOML for a preset (useful for CLI dump).
pub fn preset_toml(name: &str) -> Option<&'static str> {
    match name {
        "usb-utility" => Some(include_str!("../presets/usb-utility.toml")),
        "text-editor" => Some(include_str!("../presets/text-editor.toml")),
        "software-updater" => Some(include_str!("../presets/software-updater.toml")),
        "vpn-helper" => Some(include_str!("../presets/vpn-helper.toml")),
        "desktop-app" => Some(include_str!("../presets/desktop-app.toml")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_presets_load_and_validate() {
        for name in PRESET_NAMES {
            let cover = cover_preset(name).unwrap();
            assert_eq!(cover.name, *name);
            cover.validate().unwrap();
        }
    }
}
