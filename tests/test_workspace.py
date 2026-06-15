import json
from pwc import workspace as ws


def test_slug_normalizes():
    assert ws.slug("Acme Corp / Q3!") == "acme-corp-q3"
    assert ws.slug("") == "engagement"


def test_init_creates_full_tree(tmp_path):
    d = ws.init_engagement(str(tmp_path), "Acme Corp", scope_notes="lab",
                           target_type="host", authorization="TICKET-1")
    for folder in ws.FOLDERS:
        assert (d / folder).is_dir()
    meta = ws.load_meta(d)
    assert meta.name == "Acme Corp"
    assert meta.authorization == "TICKET-1"
    assert (d / "scope" / "scope.md").exists()


def test_add_target_registers_and_creates_knowledge(tmp_path):
    ws.init_engagement(str(tmp_path), "eng")
    tdir = ws.add_target(str(tmp_path), "eng", "10.0.0.5")
    assert tdir.is_dir()
    meta = ws.load_meta(ws.engagement_dir(str(tmp_path), "eng"))
    assert "10.0.0.5" in meta.targets
    k = json.loads((tdir / "knowledge.json").read_text())
    assert k["target"] == "10.0.0.5"


def test_add_target_unknown_engagement(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        ws.add_target(str(tmp_path), "nope", "1.2.3.4")


def test_active_state_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(ws, "_STATE_FILE", tmp_path / "active.json")
    ws.set_active("eng", "10.0.0.5")
    assert ws.get_active() == ("eng", "10.0.0.5")


def test_active_state_missing_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(ws, "_STATE_FILE", tmp_path / "missing.json")
    assert ws.get_active() == (None, None)


def test_target_knowledge_survives_load(tmp_path):
    # Regression: knowledge.json carries a `type` key; loading it must not wipe state.
    from pwc import knowledge as k
    ws.init_engagement(str(tmp_path), "e")
    tdir = ws.add_target(str(tmp_path), "e", "10.0.0.5", target_type="host")
    tk = k.TargetKnowledge.load(tdir / "knowledge.json")
    assert tk.target == "10.0.0.5"
    assert tk.hosts == ["10.0.0.5"]
    assert tk.type == "host"
