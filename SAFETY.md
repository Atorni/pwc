# Threat Model & Safety Notes

**Authorized use only.** This tool is for lawful, scoped penetration testing,
security labs, and defensive work. It does not perform exploitation, does not
chain attacks, and never executes anything without explicit human approval.

## Trust boundaries

| Source                         | Trust      | Handling                                   |
|--------------------------------|------------|--------------------------------------------|
| User input (CLI args)          | Trusted    | Used directly (still redacted before egress) |
| Shell context (hook file)      | Semi       | Redacted before egress                     |
| Tool output (nmap, web, etc.)  | Untrusted  | Wrapped in `<untrusted_output>`, treated as data |
| Model response                 | Untrusted  | Parsed, re-classified by LOCAL risk engine, gated |
| Config file                    | Trusted    | No secrets stored; keys come from env vars |

## Key controls

1. **Execution gate** - every command is displayed, locally risk-classified,
   policy-checked, and run only after `y`/double-confirm. Nothing auto-runs.
2. **Local authoritative risk engine** - the model's self-reported risk is
   advisory only; gating uses `pwc/risk.py`.
3. **Secret redaction before egress** - API keys, tokens, private keys, JWTs,
   basic-auth URLs, password assignments, and `-p<pw>` flags are stripped from
   all context sent to a provider. Covered by tests.
4. **Prompt-injection hardening** - untrusted tool output is fenced and the
   system prompt instructs the model to treat it as data and ignore directives.
   Output that tries to close the fence is neutralized.
5. **Privacy mode** - sends command-only prompts with zero shell context.
6. **Local-first** - workspaces, knowledge, evidence, and the append-only audit
   log (`~/.local/share/pwc/audit.jsonl`) never leave the device.
7. **No silent monitoring** - the shell hook records *metadata only* on each
   prompt; full output capture happens only for commands you run via `pwc run`.

## Residual risks (be aware)

- Redaction is pattern-based and best-effort; review prompts in high-sensitivity
  engagements, or use `privacy_mode = true`.
- `bash -c` is used for approved execution because suggestions may contain pipes
  and redirects. This is only reachable *after* the gate.
- The model can be wrong. The local risk engine catches common destructive
  patterns but is not exhaustive - always read the command before approving.
- Findings are drafts and require human confirmation; the tool never asserts a
  vulnerability without an attached evidence reference.
