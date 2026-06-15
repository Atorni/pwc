#!/usr/bin/env bash
# Standalone tmux layout helper (pwc start uses the Python tmuxmgr instead).
# Usage: ./layout.sh <session-name> <workdir>
set -euo pipefail
SESSION="${1:?session name required}"
WORKDIR="${2:-$PWD}"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Session $SESSION exists. Attach: tmux attach -t $SESSION"
  exit 0
fi

tmux new-session -d -s "$SESSION" -n notes -c "$WORKDIR"
tmux new-window  -t "$SESSION" -n shell -c "$WORKDIR"
tmux new-window  -t "$SESSION" -n scans -c "$WORKDIR"
tmux new-window  -t "$SESSION" -n web   -c "$WORKDIR"
tmux new-window  -t "$SESSION" -n logs  -c "$WORKDIR"
tmux select-window -t "$SESSION:notes"
echo "Created $SESSION. Attach: tmux attach -t $SESSION"
