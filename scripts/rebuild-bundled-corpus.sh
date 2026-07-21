#!/usr/bin/env bash
# Ingest every PE in corpus/bundled/ into corpus/components/ using tags from manifest.toml.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
B="$ROOT/corpus/bundled"
C="$ROOT/corpus"
MANIFEST="$B/manifest.toml"

command -v cargo >/dev/null
[[ -f "$MANIFEST" ]] || { echo "missing $MANIFEST" >&2; exit 1; }

LIST_FILE="$(mktemp)"
trap 'rm -f "$LIST_FILE"' EXIT

python3 - <<'PY' "$MANIFEST" >"$LIST_FILE"
import sys, re
text = open(sys.argv[1]).read()
blocks = re.split(r"\n\[\[binary\]\]\n", text)
for b in blocks[1:]:
    def grab(key):
        m = re.search(rf'^{key}\s*=\s*"(.*)"', b, re.M)
        return m.group(1) if m else ""
    def grab_list(key):
        m = re.search(rf'^{key}\s*=\s*\[(.*)\]', b, re.M)
        if not m:
            return "gui,utility"
        items = re.findall(r'"([^"]+)"', m.group(1))
        return ",".join(items) if items else "gui,utility"
    f, i, tags = grab("file"), grab("id"), grab_list("tags")
    if f and i:
        print(f"{f}\t{i}\t{tags}")
PY

while IFS=$'\t' read -r file id tags; do
  [[ -z "${file:-}" ]] && continue
  pe="$B/$file"
  if [[ ! -f "$pe" ]]; then
    echo "WARN: missing $pe — skip" >&2
    continue
  fi
  echo "==> ingest $file ($id) tags=$tags"
  cargo run -q -p binary-filler-cli -- ingest \
    -s "$pe" \
    -c "$C" \
    --id "$id" \
    --tags "$tags" \
    --max-chunks 32 \
    --window 4096 \
    --max-entropy 6.0
done <"$LIST_FILE"

echo "==> corpus list"
cargo run -q -p binary-filler-cli -- corpus list -c "$C"
echo "rebuild-bundled-corpus: OK"
