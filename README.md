# pwc — Pentest Workspace Copilot

A tmux-native, human-in-the-loop workflow accelerator for **authorized**
penetration testing on Kali Linux. It bootstraps structured engagement
workspaces, turns intent into reviewed commands, captures evidence, remembers
per-target state, and keeps a local audit trail — without ever auto-running
anything.

🔗 **Landing page:** https://atorni.github.io/pwc/

> ⚠️ **Authorized systems, labs, and defensive/security testing only.**

## What pwc is (and isn't)

pwc is a *workflow accelerator*, not an autonomous attack bot. It organizes an
engagement, proposes a single command at a time, classifies that command with a
**local** risk engine, gates execution behind explicit human approval, and files
the resulting output as evidence. The model (when one is configured) only ever
*suggests*; it never executes, never chains attacks, and never overrides the
local safety gate.

## Why tmux-native matters

Real engagements sprawl across many shells: a long scan here, a web fuzz there,
notes in a third pane, logs tailing in a fourth. `pwc start` lays that out for
you as one purpose-labelled session per engagement (and per target when one is
selected), with the busy windows pre-split into panes:

```
notes : [ live notes / copilot ] | [ scratch shell ]
shell : general shell
scans : [ long-running scan    ] | [ watch / tail   ]
web   : web / HTTP testing
logs  : log watching
```

Sessions are named `pwc-<engagement>[-<target>]`, are detected on restart, and
`pwc resume` shows which are attached. Everything is built with explicit argv
vectors — never `shell=True` — so nothing in a session name or workdir can be
shell-injected.

## Quick start

```bash
./install.sh
echo 'source "$HOME/.local/share/pwc/shell/pwc.bash"' >> ~/.bashrc
exec $SHELL
pwc doctor
```

It works fully offline out of the box (`provider = "mock"`). To enable Anthropic:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
# then set provider = "anthropic" in ~/.config/pwc/config.toml
```

## Kali usage example

```bash
pwc init "acme-external" --type network --scope "10.0.0.0/24, in-scope per SOW-2025-14"
pwc target add 10.0.0.5
pwc start                      # opens (and attaches to) the tmux workbench
pwc run "full TCP service scan of 10.0.0.5"
#   → shows the proposed command + LOCAL risk badge, asks before running,
#     captures output to scans/, and ingests open ports into target knowledge
pwc next                       # deterministic next-step suggestions from what's known
pwc note "anon SMB listing succeeded on 445"
pwc finding new "Anonymous SMB share access" --severity medium
pwc finding attach 20250615-anonymous-smb-share-access scans/10.0.0.5_smb.out
pwc history                    # local audit trail
```

## Commands

| Command | Purpose |
|---|---|
| `pwc init [name]` | bootstrap an engagement |
| `pwc target add <host>` | add/select a target |
| `pwc start [--no-attach]` | create/attach the tmux workbench |
| `pwc kill [session]` | kill a pwc tmux session (default: active) |
| `pwc ask "..."` | natural language → proposed command |
| `pwc run "..."` | natural language → command, offer to run (gated) |
| `pwc fix` | fix the failed previous command |
| `pwc next` | suggest the next step (offline heuristics + model) |
| `pwc explain [cmd]` | explain a command |
| `pwc review [cmd]` | local risk-review of a command |
| `pwc capture --tag enum` | save last command as evidence |
| `pwc note "..."` | append an engagement note |
| `pwc finding new "..."` | draft a finding |
| `pwc finding attach <id> <path>` | attach evidence |
| `pwc status` / `pwc resume` | active state / sessions |
| `pwc history` | local audit history |
| `pwc doctor` | diagnostics |
| `pwc config init/show` | configuration |
| `pwc provider list/test` | provider management |
| `pwc policy show` | show policy |

## Architecture

Modular Python package under `src/pwc/`. The flow for any AI action is always:

```
collect → redact → audit(prompt) → model → parse → classify (LOCAL risk) →
policy → render → [approve] → execute → capture → audit(outcome)
```

Nothing executes without passing the gate, and the LOCAL risk classification —
not the model's self-reported risk — is what gates.

## Project layout

```
src/pwc/
  cli.py          argparse wiring + command handlers
  config.py       TOML config + secure defaults (no secrets on disk)
  workspace.py    engagement/target folder model + active-state
  knowledge.py    per-target structured facts (ports, urls, shares, …)
  heuristics.py   deterministic, offline next-step suggestions
  context.py      shell-hook metadata + git/venv enrichment
  prompts.py      prompt building with untrusted-output fencing
  parser.py       model output → structured Suggestion
  risk.py         LOCAL authoritative risk engine (grouped rules)
  policy.py       allow/deny + confirmation decisions
  redaction.py    secret stripping before any egress
  execution.py    the approval gate + captured execution
  capture.py      evidence files + metadata
  findings.py     draft findings (JSON + Markdown)
  audit.py        append-only local JSONL audit log
  render.py       dependency-free ANSI rendering
  tmuxmgr.py      argv-safe tmux orchestration (panes, attach, info)
  diagnostics.py  `pwc doctor`
  providers/      swappable backends: mock (offline), anthropic, openai_compat
shell/            bash/zsh hooks (metadata only)
tmux/             standalone layout.sh (the Python tmuxmgr is the real path)
tests/            risk, redaction, policy, workspace, tmux, execution,
                  findings, audit
```

## Safety

See [SAFETY.md](SAFETY.md) for the full threat model. In short: every command is
shown, locally risk-classified, policy-checked, and only runs after explicit
human approval. Secrets are redacted before egress. No autonomous exploitation.

The local risk engine catches destructive deletes regardless of how the flags
are spelled (`rm -rf`, `rm -r -f`, `rm --recursive --force`), firewall flushes,
device writes, fork bombs, remote-pipe-to-shell, and more. Redaction is scoped
to avoid false positives that would corrupt commands (e.g. `nmap -p80,443` is
left intact while `mysql -pSecret` is stripped).

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

Safety-critical pieces (redaction, risk engine, policy, the execution gate)
plus workspace, tmux construction, findings, and audit logging have coverage in
`tests/`.

## Developer notes

* **No runtime dependencies.** HTTP to providers goes through stdlib `urllib`;
  rendering is hand-rolled ANSI. `pytest` is the only dev dependency.
* **The risk engine is the contract.** When adding a rule, add a test. The model
  is advisory; `risk.assess()` is authoritative.
* **tmux is exercised by argv, not mocks.** `tmuxmgr.build_create_commands()` is
  a pure function returning the exact vectors `create()` runs, so layout changes
  are unit-testable without a tmux server.

## Roadmap

* Knowledge-aware `next` ranking (weight by service exposure / prior results).
* Pluggable evidence exporters (Markdown engagement report, CSV finding list).
* Optional `tmux-resurrect`-style session persistence across reboots.
* Local model provider (llama.cpp / Ollama) behind the existing `Provider` seam.
* Per-engagement policy overrides (tighter allowlists for client constraints).
* Richer `pwc fix` using captured stderr from the last `pwc run`.

## License

MIT
