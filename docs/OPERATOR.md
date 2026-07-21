# binary-filler — Operator Guide

Compile-time Windows PE cover filling for Rust agents/loaders (Mythic-compatible hosts, custom implants).

## 10-line integration

```toml
# Cargo.toml
[dependencies]
binary-filler = { path = "../binary-filler/crates/binary-filler" }
[build-dependencies]
binary-filler-build = { path = "../binary-filler/crates/binary-filler-build" }
```

```rust
// build.rs
fn main() {
    binary_filler_build::Builder::ops()
        .cover_preset("usb-utility") // or text-editor | software-updater | vpn-helper | desktop-app
        .corpus_from_env_or("/opt/bf-corpus")
        .emit()
        .expect("binary-filler");
}
```

```rust
// src/main.rs
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    binary_filler::keep!(); // mandatory — retains blobs + import anchors through LTO
    agent::run();
}
```

```bash
export BINARY_FILLER_CORPUS=/path/to/corpus
cargo build --release --target x86_64-pc-windows-gnu
```

## Cover presets

| Preset | Story | Import profile |
|--------|--------|----------------|
| `usb-utility` | USB prep tool | gui |
| `text-editor` | Plain text editor | gui |
| `software-updater` | Update helper | desktop-app |
| `vpn-helper` | VPN helper | desktop-app |
| `desktop-app` | Generic desktop toolkit | desktop-app |

```bash
cargo run -p binary-filler-cli -- preset list
cargo run -p binary-filler-cli -- preset show usb-utility
```

Custom cover: TOML file + `.cover_file("covers/op.toml")`.

## Budget profiles

| API | Blob budget | Use |
|-----|-------------|-----|
| `Budget::conservative()` | 12 KiB | size-sensitive delivery |
| `Budget::standard()` / `ops()` | 32 KiB | default ops |
| `Budget::aggressive()` | 128 KiB | heavier static pollution |

Always entropy-capped (default ~6.0 bits/byte) so filler does not look packed.

## Fail policy

| | `FailPolicy::lab()` | `FailPolicy::ops()` |
|--|---------------------|---------------------|
| Missing corpus | synthetic blobs | **build fails** |
| Empty eligible chunks | synthetic | **build fails** |
| Resources on Windows | required | required |

`Builder::ops()` = `FailPolicy::ops()` + `Budget::ops()`.

## Corpus playbook

### All-inclusive (default)

The repo already ships:

- `corpus/bundled/` — redistributable open-source PEs (PuTTY, Rufus, Notepad++, SumatraPDF, …)
- `corpus/components/` — pre-ingested low-entropy chunks

```bash
cargo run -p binary-filler-cli -- corpus list -c corpus
# 10 components, hundreds of KB of fill material
```

`Builder::ops().corpus_from_env_or(<workspace>/corpus)` just works after clone.

### Refresh bundled goodware

```bash
./scripts/fetch-bundled-goodware.sh
./scripts/rebuild-bundled-corpus.sh
```

Licenses: `corpus/bundled/THIRD_PARTY_NOTICES.md`.

### Add operator-local samples

```bash
mkdir -p corpus/sources   # gitignored
# only software you may use
cargo run -p binary-filler-cli -- ingest \
  -s corpus/sources/mytool.exe \
  -c corpus \
  --id mytool \
  --tags gui,utility
```

## Verify a PE (static)

```bash
cargo run -p binary-filler-cli -- verify \
  -p target/x86_64-pc-windows-gnu/release/dummy-agent.exe \
  --company "Northwind Softworks" \
  --product DrivePrep
```

## Authenticode stamp (post-link, intentionally invalid)

Compile-time fill cannot attach a cert: the PE must exist first. After `cargo build`:

```bash
cargo run -p binary-filler-cli -- stamp-cert \
  -d corpus/bundled/putty-x64.exe \
  -t target/x86_64-pc-windows-gnu/release/my-agent.exe
```

This **copies the WIN_CERTIFICATE / security directory** from a signed donor onto your
agent. Windows will **not** accept it as a valid signature (image hash mismatch). It only
adds the static artifact some heuristics look for (“has cert table”).

Signed donors in the bundled corpus include: `putty-x64.exe`, `rufus-4.15.exe`,
`notepadpp-x64.exe`, `SumatraPDF-3.6.1-64.exe`, …

```bash
cargo run -p binary-filler-cli -- verify -p my-agent.exe --require-cert
```

## Smoketests

```bash
# unit + local Windows PE matrix (debug/release/lto)
./scripts/smoke-windows.sh

# remote Windows runtime + Defender (needs SSH env)
export BF_SSH_HOST=daniel@desktop-r9q963g.tail5a21e7.ts.net
export BF_SSH_PASS='...'   # or use SSH keys; never commit secrets
./scripts/smoke-remote-windows.sh
```

## Fail modes (expected)

| Symptom | Cause | Fix |
|---------|--------|-----|
| build: `require_corpus` | ops policy, no corpus | set `BINARY_FILLER_CORPUS` or ingest |
| build: `forbid_synthetic_blobs` | no eligible chunks | lower entropy threshold / add tags / larger budget |
| PE has no VERSIONINFO | non-Windows target | build with `--target *-windows-*` |
| PE missing GUI imports after LTO | `keep!()` not called | call `binary_filler::keep!()` first in `main` |
| process hangs (GUI) | subsystem windows + no exit | agent must exit or run a message pump |

## What this does **not** do

- Runtime evasion (AMSI/ETW/hooks)
- Code signing
- Guarantee AV/EDR bypass — only shifts static feature surface
- Support non-Windows PE (by design)

## Security

Never commit operator passwords, corpus originals you cannot redistribute, or engagement-specific cover branding into public trees.
