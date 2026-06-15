import json
from pwc.audit import AuditLog


def test_audit_appends_jsonl(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.suggestion(action="ask", command="nmap -sV x", risk="caution",
                   confidence=0.6, target="x")
    log.approval(command="nmap -sV x", approved=True, risk="caution")
    log.execution(command="nmap -sV x", exit_code=0, stdout_bytes=10,
                  stderr_bytes=0, target="x")
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 3
    for line in lines:
        rec = json.loads(line)
        assert "ts" in rec and "event" in rec


def test_audit_read_limit(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(10):
        log.policy_block(command=f"cmd{i}", rule="deny")
    assert len(log.read(limit=3)) == 3


def test_audit_read_missing_file(tmp_path):
    assert AuditLog(tmp_path / "none.jsonl").read() == []
