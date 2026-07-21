#!/usr/bin/env bash
# Upload filled PEs to a Windows host and run runtime + Defender smoke.
#
# Required env:
#   BF_SSH_HOST   e.g. daniel@desktop-r9q963g.tail5a21e7.ts.net
# Optional:
#   BF_SSH_PASS   password for sshpass (prefer SSH keys)
#   BF_SSH_DIR    remote dir (default C:/Users/daniel/binary-filler-smoke)
#   SMOKE_TARGET  default x86_64-pc-windows-gnu
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOST="${BF_SSH_HOST:?set BF_SSH_HOST}"
REMOTE_DIR="${BF_SSH_DIR:-C:/Users/daniel/binary-filler-smoke}"
TARGET="${SMOKE_TARGET:-x86_64-pc-windows-gnu}"

ssh_base=(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
scp_base=(scp -o StrictHostKeyChecking=accept-new)

if [[ -n "${BF_SSH_PASS:-}" ]]; then
  command -v sshpass >/dev/null || {
    echo "error: sshpass required when BF_SSH_PASS is set" >&2
    exit 1
  }
  export SSHPASS="$BF_SSH_PASS"
  ssh_base=(sshpass -e "${ssh_base[@]}")
  scp_base=(sshpass -e "${scp_base[@]}")
fi

echo "==> ensure local matrix artifacts"
./scripts/smoke-windows.sh

echo "==> prepare remote dir"
"${ssh_base[@]}" "$HOST" "cmd /c if not exist $(echo "$REMOTE_DIR" | tr / \\) mkdir $(echo "$REMOTE_DIR" | tr / \\)"

upload() {
  local local_path="$1"
  local remote_name="$2"
  [[ -f "$local_path" ]] || {
    echo "missing $local_path" >&2
    exit 1
  }
  "${scp_base[@]}" "$local_path" "$HOST:$REMOTE_DIR/$remote_name"
}

echo "==> upload PEs + smoke script"
upload "target/${TARGET}/debug/dummy-agent.exe" "dummy-agent-debug.exe"
upload "target/${TARGET}/release/dummy-agent.exe" "dummy-agent-release.exe"
upload "target/${TARGET}/release-lto/dummy-agent.exe" "dummy-agent-release-lto.exe"
upload "target/${TARGET}/release-fat-lto/dummy-agent.exe" "dummy-agent-release-fat-lto.exe"
upload "scripts/remote-windows-smoke.ps1" "remote-windows-smoke.ps1"

# Convert path for cmd.exe
WIN_DIR=$(echo "$REMOTE_DIR" | sed 's|/|\\|g')

echo "==> remote runtime + Defender smoke"
"${ssh_base[@]}" "$HOST" \
  "cmd /c powershell -NoProfile -ExecutionPolicy Bypass -File ${WIN_DIR}\\remote-windows-smoke.ps1"

echo "smoke-remote-windows: OK"
