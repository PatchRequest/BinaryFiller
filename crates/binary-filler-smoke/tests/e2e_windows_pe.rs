//! End-to-end smoketests: cross-compile `dummy-agent` Windows PE matrix and inspect.
//!
//! Profiles: debug, release, release-lto, release-fat-lto.
//!
//! Requires mingw target + corpus. Run:
//!   cargo test -p binary-filler-smoke --test e2e_windows_pe -- --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use binary_filler_core::shannon_entropy;
use object::pe::{IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_SUBSYSTEM_WINDOWS_GUI};
use object::read::pe::{PeFile, PeFile64};
use object::LittleEndian as LE;
use object::{Object, ObjectSection};

const TARGET: &str = "x86_64-pc-windows-gnu";
const PACKAGE: &str = "dummy-agent";
const COVER_STRINGS: &[&str] = &[
    "Northwind Softworks",
    "DrivePrep",
    "driveprep.exe",
    "USB drive preparation",
];
const REQUIRED_DLLS: &[&str] = &["user32.dll", "gdi32.dll", "shell32.dll", "comctl32.dll"];

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    /// cargo args after `build -p dummy-agent --target ...`
    cargo_args: &'static [&'static str],
    /// relative under target/<triple>/
    out_dir: &'static str,
}

const PROFILES: &[Profile] = &[
    Profile {
        name: "debug",
        cargo_args: &[],
        out_dir: "debug",
    },
    Profile {
        name: "release",
        cargo_args: &["--release"],
        out_dir: "release",
    },
    Profile {
        name: "release-lto",
        cargo_args: &["--profile", "release-lto"],
        out_dir: "release-lto",
    },
    Profile {
        name: "release-fat-lto",
        cargo_args: &["--profile", "release-fat-lto"],
        out_dir: "release-fat-lto",
    },
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn ensure_corpus(root: &Path) {
    let chunks = root.join("corpus/components/rufus-4.15/chunks");
    assert!(
        chunks.is_dir(),
        "missing Rufus corpus at {}; run ingest first",
        chunks.display()
    );
}

fn cross_build(root: &Path, profile: Profile) -> PathBuf {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .args(["-p", PACKAGE, "--target", TARGET, "--quiet"])
        .args(profile.cargo_args)
        .current_dir(root);
    let status = cmd.status().expect("spawn cargo");
    assert!(
        status.success(),
        "cargo build profile {} failed",
        profile.name
    );

    let exe = root
        .join("target")
        .join(TARGET)
        .join(profile.out_dir)
        .join(format!("{PACKAGE}.exe"));
    assert!(exe.is_file(), "missing PE at {}", exe.display());
    exe
}

fn find_build_report(root: &Path, profile: Profile) -> PathBuf {
    let build_root = root
        .join("target")
        .join(TARGET)
        .join(profile.out_dir)
        .join("build");
    let mut matches = Vec::new();
    if build_root.is_dir() {
        for entry in fs::read_dir(&build_root).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("dummy-agent-") {
                continue;
            }
            let report = entry.path().join("out/binary_filler/report.json");
            if report.is_file() {
                matches.push(report);
            }
        }
    }
    matches.sort();
    matches
        .into_iter()
        .next_back()
        .unwrap_or_else(|| panic!("report.json missing for profile {}", profile.name))
}

fn utf16le_contains(haystack: &[u8], needle: &str) -> bool {
    let encoded: Vec<u8> = needle
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    haystack
        .windows(encoded.len())
        .any(|w| w == encoded.as_slice())
}

fn pe_imports(data: &[u8]) -> Vec<String> {
    let file = object::File::parse(data).expect("parse PE");
    let mut dlls: Vec<String> = file
        .imports()
        .expect("imports")
        .iter()
        .map(|imp| String::from_utf8_lossy(imp.library()).to_ascii_lowercase())
        .collect();
    dlls.sort();
    dlls.dedup();
    dlls
}

fn pe_section_names(data: &[u8]) -> Vec<String> {
    let file = object::File::parse(data).expect("parse PE");
    file.sections()
        .filter_map(|s| s.name().ok().map(|n| n.to_string()))
        .collect()
}

fn pe_subsystem(data: &[u8]) -> u16 {
    let pe: PeFile64<'_> = PeFile::parse(data).expect("PeFile64");
    pe.nt_headers().optional_header.subsystem.get(LE)
}

fn pe_resource_dir_present(data: &[u8]) -> bool {
    let pe: PeFile64<'_> = PeFile::parse(data).expect("PeFile64");
    match pe.data_directories().get(IMAGE_DIRECTORY_ENTRY_RESOURCE) {
        Some(dir) => dir.virtual_address.get(LE) != 0 && dir.size.get(LE) != 0,
        None => false,
    }
}

fn assert_pe_filled(root: &Path, profile: Profile, exe: &Path) {
    let data = fs::read(exe).expect("read PE");
    assert!(data.len() > 32 * 1024, "{} too small", profile.name);
    assert_eq!(&data[..2], b"MZ");

    let report_path = find_build_report(root, profile);
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report["target_os"], "windows", "{}", profile.name);
    assert_eq!(report["resources_embedded"], true, "{}", profile.name);
    assert_eq!(report["features"]["cover_name"], "usb-utility");
    assert_eq!(
        report["features"]["synthetic_blobs"], false,
        "profile {} used synthetic blobs",
        profile.name
    );
    assert!(
        report["features"]["blob_count"].as_u64().unwrap() >= 1,
        "{}",
        profile.name
    );

    assert_eq!(
        pe_subsystem(&data),
        IMAGE_SUBSYSTEM_WINDOWS_GUI,
        "{}",
        profile.name
    );
    assert!(pe_resource_dir_present(&data), "{}", profile.name);
    let sections = pe_section_names(&data);
    assert!(
        sections.iter().any(|s| s.starts_with(".rsrc")),
        "{} sections={sections:?}",
        profile.name
    );

    for s in COVER_STRINGS {
        assert!(
            utf16le_contains(&data, s),
            "{} missing UTF-16 {s:?}",
            profile.name
        );
    }

    let imports = pe_imports(&data);
    for dll in REQUIRED_DLLS {
        assert!(
            imports.iter().any(|i| i == *dll),
            "{} missing {dll}; have {imports:?}",
            profile.name
        );
    }

    // Emit-time blobs must appear verbatim in the PE (not a fixed historical path).
    let blobs_dir = report_path.parent().expect("report dir").join("blobs");
    assert!(
        blobs_dir.is_dir(),
        "{} missing blobs dir {}",
        profile.name,
        blobs_dir.display()
    );
    let mut found_blob = false;
    let mut sample_entropy = 0.0f64;
    let mut matched = 0usize;
    for entry in fs::read_dir(&blobs_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let chunk_bytes = fs::read(&path).expect("read emit blob");
        if chunk_bytes.len() < 64 {
            continue;
        }
        let h = shannon_entropy(&chunk_bytes);
        // Skip low-signal blobs for presence checks (near-padding is ambiguous in PE images).
        if h < 1.25 {
            continue;
        }
        // Full-blob match only — avoids false positives from common short patterns.
        let present = data
            .windows(chunk_bytes.len())
            .any(|w| w == chunk_bytes.as_slice());
        if present {
            found_blob = true;
            matched += 1;
            sample_entropy = h;
        }
    }
    assert!(
        found_blob,
        "{}: no emit-time blob (H>=1.25) found intact in the PE image",
        profile.name
    );
    assert!(
        matched >= 1,
        "{}: expected >=1 intact blob match, got {matched}",
        profile.name
    );
    assert!(
        (1.25..6.5).contains(&sample_entropy),
        "{}: embedded blob entropy out of band: {sample_entropy}",
        profile.name
    );

    eprintln!(
        "OK profile={} pe={} bytes={} imports={} blobH={sample_entropy:.3}",
        profile.name,
        exe.display(),
        data.len(),
        imports.len()
    );
}

#[test]
fn windows_pe_matrix_smoke() {
    let root = workspace_root();
    ensure_corpus(&root);

    let started = Instant::now();
    for profile in PROFILES {
        let t0 = Instant::now();
        let exe = cross_build(&root, *profile);
        assert_pe_filled(&root, *profile, &exe);
        eprintln!("  built+checked {} in {:?}", profile.name, t0.elapsed());
    }
    assert!(
        started.elapsed() < Duration::from_secs(900),
        "matrix too slow"
    );
}
