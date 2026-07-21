# binary-filler

**Compile-time Windows PE cover filling for Rust red-team agents.**

Embed goodware-like static features (VERSIONINFO, resources, low-entropy section data, realistic GUI imports) into your agent/loader **during `cargo build`** — no fragile post-build PE patching.

Designed for Mythic-compatible Rust hosts, custom implants, and sideload wrappers. Static ML/AV feature surface only; not a runtime evasion kit.

## Features

- **Build-time only** — linker produces a valid PE; resources via `.rc` / `embed-resource`
- **Cover presets** — `usb-utility`, `text-editor`, `software-updater`, `vpn-helper`, `desktop-app`
- **All-inclusive corpus** — redistributable open-source goodware (PuTTY, Rufus, Notepad++, SumatraPDF, …) + pre-ingested chunks
- **Fail-closed ops policy** — real corpus required; no silent synthetic filler in engagement builds
- **LTO-safe** — `keep!()` retains blobs + import anchors through fat LTO
- **Windows-only** (by design)

## Quick start

```toml
# Cargo.toml
[dependencies]
binary-filler = { git = "https://github.com/PatchRequest/BinaryFiller" }

[build-dependencies]
binary-filler-build = { git = "https://github.com/PatchRequest/BinaryFiller" }
```

If using a path checkout of this monorepo:

```toml
[dependencies]
binary-filler = { path = "crates/binary-filler" }
[build-dependencies]
binary-filler-build = { path = "crates/binary-filler-build" }
```

```rust
// build.rs
fn main() {
    binary_filler_build::Builder::ops()
        .cover_preset("usb-utility")
        .corpus_from_env_or("corpus") // or BINARY_FILLER_CORPUS
        .emit()
        .expect("binary-filler");
}
```

```rust
// src/main.rs
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    binary_filler::keep!(); // required — survives LTO
    // agent entry...
}
```

```bash
export BINARY_FILLER_CORPUS=/path/to/BinaryFiller/corpus
cargo build --release --target x86_64-pc-windows-gnu
```

Cross-compile from macOS/Linux needs `mingw-w64` and:

```bash
rustup target add x86_64-pc-windows-gnu
# linker is configured in .cargo/config.toml
```

## Workspace layout

```text
crates/
  binary-filler-core/     # cover, budget, corpus, ingest, presets
  binary-filler-build/    # build.rs helper (emit .rc, blobs, report)
  binary-filler/          # keep!() macro
  binary-filler-cli/      # ingest / corpus / preset / verify
  binary-filler-smoke/    # Windows PE matrix e2e tests
examples/dummy-agent/     # integration template
corpus/
  bundled/                # redistributable goodware PEs + notices
  components/             # pre-ingested low-entropy chunks
docs/OPERATOR.md          # full operator guide
```

## CLI

```bash
# List shipped corpus
cargo run -p binary-filler-cli -- corpus list -c corpus

# Presets
cargo run -p binary-filler-cli -- preset list
cargo run -p binary-filler-cli -- preset show usb-utility

# Ingest extra goodware
cargo run -p binary-filler-cli -- ingest \
  -s path/to/tool.exe -c corpus --id mytool --tags gui,utility

# Static PE checks
cargo run -p binary-filler-cli -- verify \
  -p target/x86_64-pc-windows-gnu/release/dummy-agent.exe \
  --company "Northwind Softworks" --product DrivePrep

# Post-link: copy Authenticode *table* from a signed goodware PE
# (signature will NOT cryptographically verify — static presence only)
cargo run -p binary-filler-cli -- stamp-cert \
  -d corpus/bundled/putty-x64.exe \
  -t target/x86_64-pc-windows-gnu/release/dummy-agent.exe

cargo run -p binary-filler-cli -- verify -p target/x86_64-pc-windows-gnu/release/dummy-agent.exe --require-cert
```

Refresh bundled goodware:

```bash
./scripts/fetch-bundled-goodware.sh
./scripts/rebuild-bundled-corpus.sh
```

## Smoketests

```bash
# Unit + PE matrix (debug / release / LTO / fat-LTO)
./scripts/smoke-windows.sh

# Optional: runtime + Defender on a Windows host over SSH
export BF_SSH_HOST=user@windows-host
# prefer SSH keys; BF_SSH_PASS only if you must
./scripts/smoke-remote-windows.sh
```

Verified on Windows: VERSIONINFO, GUI subsystem, import anchors, corpus blobs intact after fat LTO, Defender custom scan clean for the dummy-agent template.

## Budgets & fail policy

| Budget | Blob budget | Use |
|--------|-------------|-----|
| `Budget::conservative()` | 12 KiB | size-sensitive delivery |
| `Budget::standard()` / `ops()` | 32 KiB | default |
| `Budget::aggressive()` | 128 KiB | heavier static pollution |

| Policy | Missing corpus | Synthetic blobs |
|--------|----------------|-----------------|
| `FailPolicy::lab()` | allowed (synthetic) | yes |
| `FailPolicy::ops()` | **build fails** | **no** |

`Builder::ops()` = ops fail policy + standard budget.

## What this does *not* do

- Runtime evasion (AMSI, ETW, unhooking, injection)
- Code signing
- Guarantee bypass of any product
- Non-Windows targets

## Third-party goodware

See [`corpus/bundled/THIRD_PARTY_NOTICES.md`](corpus/bundled/THIRD_PARTY_NOTICES.md). Only software with clear redistribution rights is shipped (MIT/Apache/GPL/LGPL upstreams, unmodified).

## License

MIT (this project). Bundled third-party binaries remain under their upstream licenses.

## Disclaimer

For authorized security testing and research only. You are responsible for compliance with law and engagement rules of engagement.
