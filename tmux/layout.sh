#!/usr/bin/env bash
# Standalone tmux layout helper. The real path is the Python tmuxmgr
# (`pwc start`); this mirrors its layout for use without the package installed.
# Usage: ./layout.sh <session-name> <workdir>
set -euo pipefail
SESSION="${1:?session name required}"
WORKDIR="${2:-$PWD}"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Session $SESSION exists. Attach: tmux attach -t $SESSION"
  exit 0
fi

tmux new-session -d -s "$SESSION" -n notes -c "$WORKDIR"
tmux split-window -h -t "$SESSION:notes" -c "$WORKDIR"
tmux select-layout -t "$SESSION:notes" main-vertical
tmux select-pane   -t "$SESSION:notes.0"

tmux new-window -t "$SESSION" -n shell -c "$WORKDIR"

tmux new-window -t "$SESSION" -n scans -c "$WORKDIR"
tmux split-window -h -t "$SESSION:scans" -c "$WORKDIR"
tmux select-layout -t "$SESSION:scans" main-vertical
tmux select-pane   -t "$SESSION:scans.0"

tmux new-window -t "$SESSION" -n web  -c "$WORKDIR"
tmux new-window -t "$SESSION" -n logs -c "$WORKDIR"
tmux select-window -t "$SESSION:notes"
echo "Created $SESSION. Attach: tmux attach -t $SESSION"
