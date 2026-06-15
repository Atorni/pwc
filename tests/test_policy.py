from pwc.policy import PolicyEngine
from pwc.risk import assess


def _engine(deny=None, allow=None, double=True):
    return PolicyEngine(denylist=deny or [], allowlist=allow or [],
                        confirm_dangerous=True, double_confirm_dangerous=double)


def test_denylist_blocks():
    eng = _engine(deny=["rm -rf /*"])
    d = eng.evaluate("rm -rf /*", assess("rm -rf /*"))
    assert not d.allowed
    assert "denylist" in d.blocked_reason


def test_denylist_substring_match():
    eng = _engine(deny=["mkfs"])
    d = eng.evaluate("mkfs.ext4 /dev/sdb1", assess("mkfs.ext4 /dev/sdb1"))
    assert not d.allowed


def test_dangerous_requires_double_confirm():
    eng = _engine(double=True)
    d = eng.evaluate("rm -rf /tmp/x", assess("rm -rf /tmp/x"))
    assert d.allowed
    assert d.require_double_confirm


def test_allowlist_warns_when_outside():
    eng = _engine(allow=["nmap*"])
    d = eng.evaluate("curl http://x", assess("curl http://x"))
    assert d.allowed
    assert any("allowlist" in w for w in d.warnings)


def test_allowlist_no_warning_when_inside():
    eng = _engine(allow=["nmap*"])
    d = eng.evaluate("nmap -sV 10.0.0.1", assess("nmap -sV 10.0.0.1"))
    assert not any("allowlist" in w for w in d.warnings)
