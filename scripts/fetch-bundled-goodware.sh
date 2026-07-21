#!/usr/bin/env bash
# Download redistributable open-source goodware PEs into corpus/bundled/.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
B="$ROOT/corpus/bundled"
mkdir -p "$B"
cd "$B"

download() {
  local url="$1" out="$2"
  echo "GET $url"
  curl -fsSL -L --retry 3 --connect-timeout 30 -o "$out.partial" "$url"
  mv -f "$out.partial" "$out"
  file "$out"
}

download "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe" "putty-x64.exe"
download "https://the.earth.li/~sgtatham/putty/latest/w64/puttygen.exe" "puttygen-x64.exe"
download "https://the.earth.li/~sgtatham/putty/latest/w64/pageant.exe" "pageant-x64.exe"
download "https://github.com/pbatard/rufus/releases/download/v4.15/rufus-4.15.exe" "rufus-4.15.exe"
download "https://frippery.org/files/busybox/busybox.exe" "busybox-w32.exe"
download "https://www.7-zip.org/a/7zr.exe" "7zr.exe"
download "https://www.sumatrapdfreader.org/dl/rel/3.6.1/SumatraPDF-3.6.1-64.exe" "SumatraPDF-3.6.1-64.exe"
download "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" "jq-windows-amd64.exe"

# Notepad++ portable (version pin — update as needed)
NPP_URL="https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.8.5/npp.8.8.5.portable.x64.zip"
download "$NPP_URL" "npp.portable.x64.zip"
rm -rf _extract_npp
mkdir _extract_npp
unzip -q -o npp.portable.x64.zip -d _extract_npp
cp -f "$(find _extract_npp -iname 'notepad++.exe' | head -1)" notepadpp-x64.exe
rm -rf _extract_npp npp.portable.x64.zip

# ripgrep
RG_URL="https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
download "$RG_URL" "ripgrep.zip"
rm -rf _extract_rg
mkdir _extract_rg
unzip -q -o ripgrep.zip -d _extract_rg
cp -f "$(find _extract_rg -iname 'rg.exe' | head -1)" rg.exe
rm -rf _extract_rg ripgrep.zip

echo "bundled tree:"
ls -lh
du -sh .
