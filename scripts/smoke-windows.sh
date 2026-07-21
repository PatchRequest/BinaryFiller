#!/usr/bin/env bash
# Local unit tests + Windows PE matrix smoketests (mingw cross).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="${SMOKE_TARGET:-x86_64-pc-windows-gnu}"

if ! rustup target list --installed | grep -qx "$TARGET"; then
  echo "installing rustup target $TARGET"
  rustup target add "$TARGET"
fi

if [[ "$TARGET" == *windows-gnu ]]; then
  command -v x86_64-w64-mingw32-gcc >/dev/null || {
    echo "error: x86_64-w64-mingw32-gcc not found (brew install mingw-w64)" >&2
    exit 1
  }
  command -v x86_64-w64-mingw32-windres >/dev/null || {
    echo "error: x86_64-w64-mingw32-windres not found" >&2
    exit 1
  }
fi

if [[ ! -d corpus/components/rufus-4.15/chunks ]]; then
  if [[ -d corpus/bundled ]] && ls corpus/bundled/*.exe >/dev/null 2>&1; then
    echo "rebuilding corpus from bundled goodware"
    ./scripts/rebuild-bundled-corpus.sh
  elif [[ -f corpus/sources/rufus-4.15.exe ]]; then
    echo "ingesting corpus from corpus/sources/rufus-4.15.exe"
    cargo run -q -p binary-filler-cli -- ingest \
      -s corpus/sources/rufus-4.15.exe \
      -c corpus \
      --id rufus-4.15 \
      --tags gui,utility,usb
  else
    echo "error: missing corpus; run ./scripts/fetch-bundled-goodware.sh && ./scripts/rebuild-bundled-corpus.sh" >&2
    exit 1
  fi
fi

echo "==> unit tests"
cargo test --workspace --exclude binary-filler-smoke

echo "==> preset sanity"
cargo run -q -p binary-filler-cli -- preset list
cargo run -q -p binary-filler-cli -- corpus list -c corpus

echo "==> e2e windows PE matrix ($TARGET: debug/release/lto/fat-lto)"
cargo test -p binary-filler-smoke --test e2e_windows_pe -- --nocapture

echo "==> cli verify release PE"
cargo run -q -p binary-filler-cli -- verify \
  -p "target/${TARGET}/release/dummy-agent.exe" \
  --company "Northwind Softworks" \
  --product DrivePrep \
  --require-imports user32.dll,gdi32.dll,shell32.dll,comctl32.dll

echo "smoke-windows: OK"
