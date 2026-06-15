from pwc import findings


def test_new_finding_is_draft(tmp_path):
    f = findings.new(tmp_path, "SQL injection in login", target="10.0.0.5", severity="high")
    assert f.status == "draft"
    assert f.severity == "high"
    assert (tmp_path / f"{f.id}.json").exists()
    assert (tmp_path / f"{f.id}.md").exists()


def test_attach_evidence_is_idempotent(tmp_path):
    f = findings.new(tmp_path, "Open SMB share")
    findings.attach(tmp_path, f.id, "scans/smb.out")
    f2 = findings.attach(tmp_path, f.id, "scans/smb.out")
    assert f2.evidence == ["scans/smb.out"]


def test_list_all(tmp_path):
    findings.new(tmp_path, "A")
    findings.new(tmp_path, "B")
    assert len(findings.list_all(tmp_path)) == 2


def test_attach_unknown_finding(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        findings.attach(tmp_path, "nope", "x")
