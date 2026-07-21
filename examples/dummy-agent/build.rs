use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_corpus = manifest_dir.join("../..").join("corpus");

    // Ops-style integration template:
    // - built-in cover preset
    // - real corpus (BINARY_FILLER_CORPUS or workspace corpus/)
    // - FailPolicy::ops (no synthetic fallback)
    binary_filler_build::Builder::ops()
        .cover_preset("usb-utility")
        .corpus_from_env_or(&workspace_corpus)
        .emit()
        .expect("binary-filler emit failed");
}
