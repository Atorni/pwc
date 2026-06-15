import builtins
from pwc import execution
from pwc.audit import AuditLog
from pwc.policy import PolicyEngine
from pwc.risk import assess


def _engine(deny=None, allow=None):
    return PolicyEngine(denylist=deny or [], allowlist=allow or [],
                        confirm_dangerous=True, double_confirm_dangerous=True)


def _audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


def test_policy_block_denies_without_prompting(tmp_path, monkeypatch):
    # If a denied command somehow reached approve(), it must not prompt or run.
    called = {"prompted": False}
    monkeypatch.setattr(builtins, "input",
                        lambda *_: called.__setitem__("prompted", True) or "y")
    cmd = "rm -rf /*"
    decision = _engine(deny=["rm -rf /*"]).evaluate(cmd, assess(cmd))
    ok = execution.approve(cmd, assess(cmd), decision, _audit(tmp_path))
    assert ok is False
    assert called["prompted"] is False


def test_simple_approval_yes(tmp_path, monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_: "y")
    cmd = "ls -la"
    dec = _engine().evaluate(cmd, assess(cmd))
    assert execution.approve(cmd, assess(cmd), dec, _audit(tmp_path)) is True


def test_simple_approval_default_no(tmp_path, monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_: "")
    cmd = "ls -la"
    dec = _engine().evaluate(cmd, assess(cmd))
    assert execution.approve(cmd, assess(cmd), dec, _audit(tmp_path)) is False


def test_dangerous_requires_exact_phrase(tmp_path, monkeypatch):
    cmd = "rm -rf /tmp/x"
    risk = assess(cmd)
    dec = _engine().evaluate(cmd, risk)
    # A plain 'y' must NOT approve a dangerous double-confirm command.
    monkeypatch.setattr(builtins, "input", lambda *_: "y")
    assert execution.approve(cmd, risk, dec, _audit(tmp_path)) is False
    # The exact phrase approves.
    monkeypatch.setattr(builtins, "input", lambda *_: execution._CONFIRM_PHRASE)
    assert execution.approve(cmd, risk, dec, _audit(tmp_path)) is True


def test_run_captures_exit_code(tmp_path):
    res = execution.run("true", audit=_audit(tmp_path))
    assert res.ran and res.exit_code == 0
    res2 = execution.run("false", audit=_audit(tmp_path))
    assert res2.exit_code == 1


def test_gate_and_run_blocked_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_: "yes, run it")
    out = execution.gate_and_run("rm -rf /*", _engine(deny=["rm -rf /*"]),
                                 _audit(tmp_path))
    assert out is None
