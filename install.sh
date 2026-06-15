#!/usr/bin/env bash
# Install pwc on Kali Linux (per-user, via pipx; falls back to venv).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE_DIR="$HOME/.local/share/pwc/shell"

echo "[*] Pentest Workspace Copilot installer (authorized use only)"

if ! command -v python3 >/dev/null; then
  echo "[!] python3 not found"; exit 1
fi

if command -v pipx >/dev/null; then
  echo "[*] Installing with pipx"
  pipx install --force "$REPO_DIR"
else
  echo "[*] pipx not found; using a virtualenv at ~/.local/pwc-venv"
  python3 -m venv "$HOME/.local/pwc-venv"
  "$HOME/.local/pwc-venv/bin/pip" install --upgrade pip >/dev/null
  "$HOME/.local/pwc-venv/bin/pip" install "$REPO_DIR"
  mkdir -p "$HOME/.local/bin"
  ln -sf "$HOME/.local/pwc-venv/bin/pwc" "$HOME/.local/bin/pwc"
  echo "[*] Ensure ~/.local/bin is on your PATH"
fi

echo "[*] Installing shell hooks to $SHARE_DIR"
mkdir -p "$SHARE_DIR"
cp "$REPO_DIR/shell/pwc.bash" "$REPO_DIR/shell/pwc.zsh" "$SHARE_DIR/"

echo "[*] Writing example config"
pwc config init || true

cat <<EOF

[OK] Installed.

Next steps:
  1) Add the shell hook to your shell rc:
       echo 'source "$SHARE_DIR/pwc.bash"' >> ~/.bashrc     # bash
       echo 'source "$SHARE_DIR/pwc.zsh"'  >> ~/.zshrc      # zsh
     then open a new shell.
  2) (Optional) export ANTHROPIC_API_KEY=... and set provider="anthropic"
     in ~/.config/pwc/config.toml
  3) Verify:  pwc doctor

Reminder: this tool is for authorized systems, labs, and defensive testing only.
EOF
