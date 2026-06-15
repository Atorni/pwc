"""CLI entrypoint and subcommand wiring."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pwc import __version__, render
from pwc import config as cfgmod
from pwc import workspace as ws
from pwc.audit import AuditLog
from pwc.context import collect
from pwc.parser import parse, Suggestion
from pwc.policy import PolicyEngine
from pwc.providers import get_provider, ProviderError
from pwc.redaction import redact_dict, redact
from pwc.risk import assess
from pwc import prompts, execution, capture, findings, knowledge, heuristics, tmuxmgr, diagnostics

AUTH_REMINDER = ("This assistant is for authorized systems, labs, and defensive/"
                 "security testing only.")


# ---------- helpers ----------

def _load() -> tuple[cfgmod.Config, AuditLog, PolicyEngine]:
    cfgmod.ensure_dirs()
    cfg = cfgmod.load()
    audit = AuditLog(Path(cfg.audit_log))
    policy = PolicyEngine(denylist=cfg.denylist, allowlist=cfg.allowlist,
                          confirm_dangerous=cfg.confirm_dangerous,
                          double_confirm_dangerous=cfg.double_confirm_dangerous)
    return cfg, audit, policy


def _active_engagement(cfg: cfgmod.Config) -> tuple[str | None, str | None, Path | None]:
    name, target = ws.get_active()
    if not name:
        return None, None, None
    return name, target, ws.engagement_dir(cfg.workspace_root, name)


def _knowledge_summary(cfg: cfgmod.Config) -> str | None:
    name, target, _ = _active_engagement(cfg)
    if not name or not target:
        return None
    kp = ws.knowledge_path(cfg.workspace_root, name, target)
    return knowledge.summarize(knowledge.TargetKnowledge.load(kp))


def _ask_model(cfg: cfgmod.Config, audit: AuditLog, *, action: str, user_prompt: str,
               redactions: int, context_keys: list[str]) -> Suggestion:
    name, target, _ = _active_engagement(cfg)
    provider = get_provider(cfg.provider, cfg.provider_settings)
    audit.prompt_sent(action=action, provider=cfg.provider, redaction_count=redactions,
                      context_keys=context_keys, target=target)
    raw = provider.complete(prompts.SYSTEM, user_prompt)
    sug = parse(raw)
    # LOCAL risk is authoritative; overwrite the model's claim for display/gating.
    local = assess(sug.command)
    sug.model_risk = local.level
    audit.suggestion(action=action, command=sug.command, risk=local.level,
                     confidence=sug.confidence, target=target)
    return sug


def _render_suggestion(sug: Suggestion) -> None:
    local = assess(sug.command)
    render.rule("Suggestion")
    if sug.command:
        render.command_block(sug.command)
    else:
        render.warn("No command produced.")
    print()
    if sug.explanation:
        render.kv("what", sug.explanation)
    render.kv("risk", f"{render.risk_badge(local.level)}"
              + (f"  ({'; '.join(local.reasons)})" if local.reasons else ""))
    render.kv("confidence", f"{sug.confidence:.0%}")
    if sug.impact:
        render.kv("impact", sug.impact)
    if sug.alternatives:
        print(f"  {render.BOLD}alternatives{render.RESET}")
        render.bullets(sug.alternatives)
    if sug.notes:
        render.kv("notes", sug.notes)
    render.rule()


def _maybe_execute_and_capture(cfg: cfgmod.Config, audit: AuditLog, policy: PolicyEngine,
                               sug: Suggestion, *, default_run: bool, tag: str = "recon") -> None:
    if not sug.command:
        return
    name, target, edir = _active_engagement(cfg)
    cwd = str(edir) if edir else None
    if default_run:
        result = execution.gate_and_run(sug.command, policy, audit, cwd=cwd, target=target)
    else:
        ans = input("  Execute now? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            render.info("Not executed.")
            return
        result = execution.gate_and_run(sug.command, policy, audit, cwd=cwd, target=target)
    if result and result.ran and edir:
        # auto-capture + knowledge ingestion
        out_path = capture.save(edir, result, tag=tag, target=target)
        render.ok(f"Captured evidence: {out_path}")
        if target:
            kp = ws.knowledge_path(cfg.workspace_root, name, target)
            k = knowledge.TargetKnowledge.load(kp)
            added = knowledge.ingest_command_output(k, result.command,
                                                    result.stdout + "\n" + result.stderr)
            k.save(kp)
            if added:
                render.info(f"Updated target knowledge (+{added} facts). "
                            "Try `pwc next`.")


# ---------- command handlers ----------

def cmd_init(args, cfg, audit, policy) -> int:
    render.banner("Engagement bootstrap")
    print(f"  {render.YELLOW}{AUTH_REMINDER}{render.RESET}\n")
    name = args.name or input("Engagement name: ").strip()
    if not name:
        render.error("engagement name required")
        return 1
    target_type = args.type or input("Target type (host/web/network/AD/other): ").strip()
    scope = args.scope or input("Scope notes: ").strip()
    auth = input("Authorization reference (ticket/contract): ").strip()
    d = ws.init_engagement(cfg.workspace_root, name, scope_notes=scope,
                           target_type=target_type, authorization=auth)
    ws.set_active(name, None)
    render.ok(f"Created engagement at {d}")
    render.info("Add a target:  pwc target add <ip-or-host>")
    return 0


def cmd_target_add(args, cfg, audit, policy) -> int:
    name, _, edir = _active_engagement(cfg)
    if not name:
        render.error("no active engagement. Run `pwc init` first.")
        return 1
    tdir = ws.add_target(cfg.workspace_root, name, args.target, args.type)
    ws.set_active(name, args.target)
    render.ok(f"Added target {args.target} -> {tdir}")
    render.info(f"Active target is now {args.target}.")
    return 0


def cmd_start(args, cfg, audit, policy) -> int:
    name, target, edir = _active_engagement(cfg)
    if not name or not edir:
        render.error("no active engagement. Run `pwc init` first.")
        return 1
    if not tmuxmgr.available():
        render.warn("tmux not installed; skipping workbench. "
                    "Install with: sudo apt install tmux")
        return 1
    existed = tmuxmgr.session_exists(tmuxmgr.session_name(name, target))
    session = tmuxmgr.create(name, target, edir)
    render.ok(f"tmux session {'reattached' if existed else 'ready'}: {session}")
    for win, purpose in tmuxmgr.WINDOWS:
        render.kv(win, purpose)
    print()
    if args.no_attach:
        render.info("Attach with:")
        tmuxmgr.attach(session, auto=False)
    else:
        # Replaces this process with tmux when run from a normal terminal.
        if not tmuxmgr.attach(session, auto=True):
            render.info("Attach with:")
            tmuxmgr.attach(session, auto=False)
    return 0


def cmd_ask(args, cfg, audit, policy) -> int:
    ctx = collect(history_limit=cfg.history_limit)
    ctx_payload = ctx.to_dict(include_history=cfg.effective_history(),
                              history_limit=cfg.history_limit)
    redactions = 0
    if not cfg.privacy_mode:
        ctx_payload, redactions = redact_dict(ctx_payload)
    else:
        ctx_payload = {}  # privacy mode: command-only, no shell context
    q = redact(args.query).text
    user_prompt = prompts.build_ask(q, _ctx_from(ctx_payload, ctx),
                                    include_history=cfg.effective_history(),
                                    history_limit=cfg.history_limit,
                                    knowledge_summary=_knowledge_summary(cfg))
    return _ask_flow(cfg, audit, policy, "ask", user_prompt, redactions,
                     list(ctx_payload.keys()), default_run=False)


def cmd_run(args, cfg, audit, policy) -> int:
    # Same as ask but offers immediate (gated) execution.
    ctx = collect(history_limit=cfg.history_limit)
    ctx_payload = ctx.to_dict(include_history=cfg.effective_history(),
                              history_limit=cfg.history_limit)
    redactions = 0
    if not cfg.privacy_mode:
        ctx_payload, redactions = redact_dict(ctx_payload)
    else:
        ctx_payload = {}
    q = redact(args.query).text
    user_prompt = prompts.build_ask(q, _ctx_from(ctx_payload, ctx),
                                    include_history=cfg.effective_history(),
                                    history_limit=cfg.history_limit,
                                    knowledge_summary=_knowledge_summary(cfg))
    return _ask_flow(cfg, audit, policy, "run", user_prompt, redactions,
                     list(ctx_payload.keys()), default_run=True)


def cmd_fix(args, cfg, audit, policy) -> int:
    ctx = collect(history_limit=cfg.history_limit)
    if not ctx.last_command:
        render.warn("No previous command recorded. Is the shell hook active?")
    payload = {"last_command": ctx.last_command, "exit_code": ctx.exit_code,
               "stderr_snippet": ctx.stderr_snippet}
    payload, redactions = redact_dict(payload)
    extra = redact(args.stderr).text if args.stderr else ""
    ctx.last_command = payload.get("last_command", ctx.last_command)
    ctx.stderr_snippet = payload.get("stderr_snippet", ctx.stderr_snippet)
    user_prompt = prompts.build_fix(ctx, extra_stderr=extra)
    return _ask_flow(cfg, audit, policy, "fix", user_prompt, redactions,
                     list(payload.keys()), default_run=False)


def cmd_next(args, cfg, audit, policy) -> int:
    name, target, _ = _active_engagement(cfg)
    # Deterministic, offline heuristic preview based on recorded target knowledge.
    # Shown for every provider - it never runs anything and grounds the model's
    # suggestion in locally-known facts.
    if name and target:
        kp = ws.knowledge_path(cfg.workspace_root, name, target)
        k = knowledge.TargetKnowledge.load(kp)
        steps = heuristics.next_steps(k)
        if steps:
            render.rule("Heuristic next steps (offline, deterministic)")
            for cmd, why in steps:
                render.command_block(cmd)
                render.kv("why", why)
                print()
            render.info(AUTH_REMINDER)
        if cfg.provider == "mock":
            return 0
        render.rule("Model suggestion")
    ctx = collect(history_limit=cfg.history_limit)
    ctx_payload = ctx.to_dict(include_history=cfg.effective_history(),
                              history_limit=cfg.history_limit)
    if not cfg.privacy_mode:
        ctx_payload, redactions = redact_dict(ctx_payload)
    else:
        ctx_payload, redactions = {}, 0
    user_prompt = prompts.build_next(_ctx_from(ctx_payload, ctx), _knowledge_summary(cfg))
    return _ask_flow(cfg, audit, policy, "next", user_prompt, redactions,
                     list(ctx_payload.keys()), default_run=False)


def cmd_explain(args, cfg, audit, policy) -> int:
    cmd = args.command or collect().last_command
    if not cmd:
        render.error("no command to explain (supply one or run after a command)")
        return 1
    user_prompt = prompts.build_explain(redact(cmd).text)
    sug = _ask_model(cfg, audit, action="explain", user_prompt=user_prompt,
                     redactions=0, context_keys=[])
    render.rule("Explanation")
    render.command_block(cmd)
    print()
    render.kv("meaning", sug.explanation or "(no explanation returned)")
    if sug.notes:
        render.kv("notes", sug.notes)
    render.rule()
    return 0


def cmd_review(args, cfg, audit, policy) -> int:
    cmd = args.command or collect().last_command
    if not cmd:
        render.error("no command to review")
        return 1
    local = assess(cmd)
    render.rule("Local risk review")
    render.command_block(cmd)
    print()
    render.kv("risk", f"{render.risk_badge(local.level)}")
    if local.reasons:
        render.bullets(local.reasons)
    render.kv("privileged", "yes (sudo/doas)" if local.privileged else "no")
    render.kv("double-confirm", "required" if local.requires_double_confirm else "no")
    # Model adds explanation + alternatives.
    try:
        sug = _ask_model(cfg, audit, action="review",
                         user_prompt=prompts.build_review(redact(cmd).text),
                         redactions=0, context_keys=[])
        if sug.impact:
            render.kv("impact", sug.impact)
        if sug.alternatives:
            print(f"  {render.BOLD}safer alternatives{render.RESET}")
            render.bullets(sug.alternatives)
    except ProviderError as e:
        render.warn(f"model review unavailable: {e}")
    render.info(AUTH_REMINDER)
    render.rule()
    return 0


def cmd_capture(args, cfg, audit, policy) -> int:
    name, target, edir = _active_engagement(cfg)
    if not edir:
        render.error("no active engagement")
        return 1
    ctx = collect()
    if not ctx.last_command:
        render.error("no last command recorded to capture")
        return 1
    # Build a synthetic result from recorded metadata (output not auto-stored).
    res = execution.ExecResult(ctx.last_command, ctx.exit_code or 0,
                               "", ctx.stderr_snippet, ran=True)
    out = capture.save(edir, res, tag=args.tag, target=target)
    render.ok(f"Captured: {out}")
    return 0


def cmd_note(args, cfg, audit, policy) -> int:
    name, target, edir = _active_engagement(cfg)
    if not edir:
        render.error("no active engagement")
        return 1
    text = args.text or input("Note: ").strip()
    if not text:
        return 1
    notes = edir / "notes" / "notes.md"
    notes.parent.mkdir(parents=True, exist_ok=True)
    import time
    with notes.open("a", encoding="utf-8") as fh:
        fh.write(f"\n- [{time.strftime('%Y-%m-%d %H:%M')}] "
                 f"({target or 'general'}) {redact(text).text}\n")
    render.ok(f"Note added to {notes}")
    return 0


def cmd_finding(args, cfg, audit, policy) -> int:
    name, target, edir = _active_engagement(cfg)
    if not edir:
        render.error("no active engagement")
        return 1
    fdir = edir / "findings"
    if args.finding_cmd == "new":
        title = args.title or input("Finding title: ").strip()
        f = findings.new(fdir, title, target=target or "", severity=args.severity)
        render.ok(f"Draft finding created: {f.id} (status=draft)")
        render.info(f"Edit details in {fdir / (f.id + '.md')}")
    elif args.finding_cmd == "attach":
        f = findings.attach(fdir, args.id, args.evidence)
        render.ok(f"Attached {args.evidence} to {f.id}")
    elif args.finding_cmd == "list":
        for f in findings.list_all(fdir):
            render.kv(f.id, f"[{f.severity}/{f.status}] {f.title}")
    return 0


def cmd_doctor(args, cfg, audit, policy) -> int:
    return diagnostics.run(cfg)


def cmd_config(args, cfg, audit, policy) -> int:
    if args.config_cmd == "init":
        path = cfgmod.write_example(force=args.force)
        render.ok(f"Config written: {path}")
    else:
        render.kv("config", str(cfgmod.CONFIG_FILE))
        render.kv("provider", cfg.provider)
        render.kv("workspace", cfg.workspace_root)
        render.kv("privacy_mode", str(cfg.privacy_mode))
        render.kv("audit_log", cfg.audit_log)
    return 0


def cmd_history(args, cfg, audit, policy) -> int:
    records = audit.read(limit=args.limit)
    if not records:
        render.info("audit log is empty")
        return 0
    render.rule("Audit history (local only)")
    for r in records:
        ev = r.get("event")
        ts = r.get("ts", "")[-8:]
        cmd = (r.get("command") or "")
        if ev == "suggestion":
            render.kv(ts, f"suggest [{r.get('risk')}] {cmd[:70]}")
        elif ev == "approval":
            mark = "yes" if r.get("approved") else "no"
            render.kv(ts, f"{mark} approval {cmd[:60]}")
        elif ev == "execution":
            render.kv(ts, f"ran (exit {r.get('exit_code')}) {cmd[:60]}")
        elif ev == "policy_block":
            render.kv(ts, f"BLOCKED {cmd[:60]}")
        elif ev == "prompt_sent":
            render.kv(ts, f"prompt -> {r.get('provider')} "
                          f"({r.get('redactions', 0)} redacted) [{r.get('action')}]")
    render.rule()
    return 0


def cmd_status(args, cfg, audit, policy) -> int:
    name, target, edir = _active_engagement(cfg)
    render.rule("Status")
    render.kv("engagement", name or "(none)")
    render.kv("target", target or "(none)")
    if edir:
        render.kv("dir", str(edir))
    if name and target:
        kp = ws.knowledge_path(cfg.workspace_root, name, target)
        print()
        print(knowledge.summarize(knowledge.TargetKnowledge.load(kp)))
    render.rule()
    return 0


def cmd_kill(args, cfg, audit, policy) -> int:
    if not tmuxmgr.available():
        render.error("tmux not installed")
        return 1
    name, target, _ = _active_engagement(cfg)
    session = args.session or (tmuxmgr.session_name(name, target) if name else None)
    if not session:
        render.error("no session specified and no active engagement")
        return 1
    if tmuxmgr.kill(session):
        render.ok(f"Killed tmux session: {session}")
        return 0
    render.warn(f"No such session: {session}")
    return 1


def cmd_resume(args, cfg, audit, policy) -> int:
    name, target, _ = _active_engagement(cfg)
    render.rule("Resume")
    render.kv("active", f"{name or '(none)'} / {target or '(none)'}")
    infos = tmuxmgr.all_session_info() if tmuxmgr.available() else []
    if not infos:
        render.info("No pwc tmux sessions. Start one with `pwc start`.")
        return 0
    print()
    for info in infos:
        mark = f"{render.GREEN}attached{render.RESET}" if info.attached else f"{render.GREY}detached{render.RESET}"
        render.kv(info.name, f"[{mark}] windows: {', '.join(info.windows)}")
    # If exactly the active engagement's session is present, offer to jump in.
    if name:
        sess = tmuxmgr.session_name(name, target)
        if any(i.name == sess for i in infos):
            print()
            render.info(f"Attach to the active session: pwc start  (or: tmux attach -t {sess})")
    return 0


def cmd_provider(args, cfg, audit, policy) -> int:
    if args.provider_cmd == "list":
        for p in ("anthropic", "openai_compat", "mock"):
            mark = "*" if p == cfg.provider else " "
            render.kv(f"{mark} {p}", "selected" if p == cfg.provider else "")
    elif args.provider_cmd == "test":
        try:
            prov = get_provider(cfg.provider, cfg.provider_settings)
            ok, detail = prov.health()
            (render.ok if ok else render.error)(f"{cfg.provider}: {detail}")
        except ProviderError as e:
            render.error(str(e))
            return 1
    return 0


def cmd_policy(args, cfg, audit, policy) -> int:
    render.rule("Policy")
    render.kv("confirm_dangerous", str(cfg.confirm_dangerous))
    render.kv("double_confirm", str(cfg.double_confirm_dangerous))
    render.kv("denylist", ", ".join(cfg.denylist) or "(empty)")
    render.kv("allowlist", ", ".join(cfg.allowlist) or "(empty - allow with warnings)")
    render.rule()
    return 0


def cmd_shell_init(args, cfg, audit, policy) -> int:
    """Print the path to the shell hook to source."""
    here = Path(__file__).resolve().parent
    candidates = [here.parent.parent / "shell", Path.home() / ".local/share/pwc/shell",
                  Path("/usr/local/share/pwc/shell")]
    for c in candidates:
        if (c / "pwc.bash").exists():
            render.info("Add to your ~/.bashrc:")
            print(f'   source "{c / "pwc.bash"}"')
            render.info("Add to your ~/.zshrc:")
            print(f'   source "{c / "pwc.zsh"}"')
            return 0
    render.warn("shell hooks not found; see the shell/ directory in the repo.")
    return 1


# ---------- shared ask flow ----------

def _ask_flow(cfg, audit, policy, action, user_prompt, redactions, ctx_keys,
              *, default_run: bool) -> int:
    try:
        sug = _ask_model(cfg, audit, action=action, user_prompt=user_prompt,
                         redactions=redactions, context_keys=ctx_keys)
    except ProviderError as e:
        render.error(f"provider error: {e}")
        render.info("Tip: set provider='mock' for offline heuristics, or check your API key.")
        return 1
    _render_suggestion(sug)
    if sug.command:
        _maybe_execute_and_capture(cfg, audit, policy, sug, default_run=default_run)
    return 0


def _ctx_from(payload: dict, original):
    """Rebuild a ShellContext-like object from the redacted payload for prompts."""
    from pwc.context import ShellContext
    c = ShellContext(**{k: v for k, v in {
        "cwd": payload.get("cwd", ""),
        "shell": payload.get("shell", ""),
        "user": payload.get("user", ""),
        "hostname": payload.get("hostname", ""),
        "last_command": payload.get("last_command", ""),
        "exit_code": payload.get("exit_code"),
        "recent_history": payload.get("recent_history", []),
        "git_branch": payload.get("git_branch"),
        "git_repo": payload.get("git_repo"),
        "virtualenv": payload.get("virtualenv"),
        "stderr_snippet": payload.get("stderr_snippet", ""),
    }.items()})
    return c


# ---------- argparse ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwc",
                                description="Pentest Workspace Copilot (authorized use only).")
    p.add_argument("--version", action="version", version=f"pwc {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="bootstrap an engagement workspace")
    sp.add_argument("name", nargs="?"); sp.add_argument("--type", default="")
    sp.add_argument("--scope", default=""); sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("target", help="manage targets")
    tsub = sp.add_subparsers(dest="target_cmd", required=True)
    ta = tsub.add_parser("add"); ta.add_argument("target")
    ta.add_argument("--type", default="host"); ta.set_defaults(func=cmd_target_add)

    sp = sub.add_parser("start", help="create/attach the tmux workbench for the active target")
    sp.add_argument("--no-attach", action="store_true",
                    help="create the session but don't attach (just print the command)")
    sp.set_defaults(func=cmd_start)

    sp = sub.add_parser("ask", help="natural language -> proposed command")
    sp.add_argument("query"); sp.set_defaults(func=cmd_ask)

    sp = sub.add_parser("run", help="natural language -> command, offer to run (gated)")
    sp.add_argument("query"); sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("fix", help="propose a fix for the failed previous command")
    sp.add_argument("--stderr", default=""); sp.set_defaults(func=cmd_fix)

    sub.add_parser("next", help="suggest the next useful command").set_defaults(func=cmd_next)

    sp = sub.add_parser("explain", help="explain a command")
    sp.add_argument("command", nargs="?"); sp.set_defaults(func=cmd_explain)

    sp = sub.add_parser("review", help="risk-review a command")
    sp.add_argument("command", nargs="?"); sp.set_defaults(func=cmd_review)

    sp = sub.add_parser("capture", help="capture the last command as evidence")
    sp.add_argument("--tag", default="recon", choices=sorted(capture._TAGS),
                    help="evidence category (controls which folder it lands in)")
    sp.set_defaults(func=cmd_capture)

    sp = sub.add_parser("note", help="append a note to the engagement")
    sp.add_argument("text", nargs="?"); sp.set_defaults(func=cmd_note)

    sp = sub.add_parser("finding", help="findings scratchpad")
    fsub = sp.add_subparsers(dest="finding_cmd", required=True)
    fn = fsub.add_parser("new"); fn.add_argument("title", nargs="?")
    fn.add_argument("--severity", default="informational")
    fa = fsub.add_parser("attach"); fa.add_argument("id"); fa.add_argument("evidence")
    fsub.add_parser("list")
    sp.set_defaults(func=cmd_finding)

    sub.add_parser("doctor", help="diagnostics").set_defaults(func=cmd_doctor)

    sp = sub.add_parser("config", help="config management")
    csub = sp.add_subparsers(dest="config_cmd")
    ci = csub.add_parser("init"); ci.add_argument("--force", action="store_true")
    csub.add_parser("show")
    sp.set_defaults(func=cmd_config)

    sp = sub.add_parser("history", help="show local audit history")
    sp.add_argument("--limit", type=int, default=30); sp.set_defaults(func=cmd_history)

    sub.add_parser("status", help="active engagement/target + knowledge").set_defaults(func=cmd_status)
    sub.add_parser("resume", help="list sessions / active state").set_defaults(func=cmd_resume)

    sp = sub.add_parser("kill", help="kill a pwc tmux session (default: active engagement's)")
    sp.add_argument("session", nargs="?", help="session name (default: active)")
    sp.set_defaults(func=cmd_kill)

    sp = sub.add_parser("provider", help="provider management")
    prsub = sp.add_subparsers(dest="provider_cmd", required=True)
    prsub.add_parser("list"); prsub.add_parser("test")
    sp.set_defaults(func=cmd_provider)

    sp = sub.add_parser("policy", help="policy display")
    psub = sp.add_subparsers(dest="policy_cmd")
    psub.add_parser("show")
    sp.set_defaults(func=cmd_policy)

    sub.add_parser("shell-init", help="print shell hook source lines").set_defaults(func=cmd_shell_init)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    cfg, audit, policy = _load()
    try:
        return args.func(args, cfg, audit, policy)
    except KeyboardInterrupt:
        print()
        render.warn("interrupted")
        return 130
