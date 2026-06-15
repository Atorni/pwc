# pwc — Pentest Workspace Copilot

A tmux-native, human-in-the-loop workflow accelerator for **authorized**
penetration testing on Kali Linux. It bootstraps structured engagement
workspaces, turns intent into reviewed commands, captures evidence, remembers
per-target state, and keeps a local audit trail — without ever auto-running
anything.

🔗 **Landing page:** https://atorni.github.io/pwc/

> ⚠️ **Authorized systems, labs, and defensive/security testing only.**

## Features

- **tmux workbench** — per-engagement sessions (notes / shell / scans / web / logs).
- **Command copilot** — `ask`, `run`, `fix`, `next`, `explain`, `review`.
- **Safety gate** — local risk engine + policy; nothing runs without explicit approval.
- **Secret redaction** — keys, tokens, credentials stripped before any model call.
- **Evidence capture** — outputs saved into structured folders with per-target knowledge.
- **Local-first** — workspaces, knowledge, and an append-only audit log stay on-device.
- **Provider-agnostic** — Anthropic, OpenAI-compatible, or offline (`mock`).

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

## Commands

| Command | Purpose |
|---|---|
| `pwc init [name]` | bootstrap an engagement |
| `pwc target add <host>` | add/select a target |
| `pwc start` | create/attach the tmux workbench |
| `pwc ask "..."` | natural language → proposed command |
| `pwc run "..."` | natural language → command, offer to run (gated) |
| `pwc fix` | fix the failed previous command |
| `pwc next` | suggest the next step |
| `pwc explain [cmd]` | explain a command |
| `pwc review [cmd]` | risk-review a command |
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
collect → redact → audit(prompt) → model → parse → classify (local risk) →
policy → render → [approve] → execute → capture → audit(outcome). Nothing
executes without passing the gate.

## Tests

```bash
pip install pytest
pytest -q
```

Safety-critical pieces (redaction, risk engine, policy) have test coverage in
`tests/`.

## Safety

See [SAFETY.md](SAFETY.md) for the full threat model. In short: every command is
shown, locally risk-classified, policy-checked, and only runs after explicit
human approval. Secrets are redacted before egress. No autonomous exploitation.

## License

MIT
