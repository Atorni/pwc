from pathlib import Path
from pwc import tmuxmgr


def test_session_name_target_aware():
    assert tmuxmgr.session_name("acme", None) == "pwc-acme"
    assert tmuxmgr.session_name("acme", "10.0.0.5") == "pwc-acme-10_0_0_5"


def test_build_create_commands_are_argv_safe():
    cmds = tmuxmgr.build_create_commands("pwc-acme", Path("/tmp/eng"))
    # First command starts the detached session.
    assert cmds[0][:3] == ["new-session", "-d", "-s"]
    # Every remaining window in WINDOWS gets created.
    created = {c[c.index("-n") + 1] for c in cmds if c[0] == "new-window"}
    assert created == {w for w, _ in tmuxmgr.WINDOWS[1:]}
    # Split windows get a split-window + layout.
    splits = {c[c.index("-t") + 1].split(":")[1] for c in cmds if c[0] == "split-window"}
    assert splits == tmuxmgr._SPLIT_WINDOWS
    # No element contains shell metacharacters that imply shell interpretation.
    for argv in cmds:
        assert all(isinstance(tok, str) for tok in argv)


def test_purpose_label_recorded_for_every_window():
    cmds = tmuxmgr.build_create_commands("pwc-x", Path("/tmp"))
    labelled = {c[c.index("-t") + 1].split(":")[1]
                for c in cmds if c[0] == "set-option" and "@pwc_purpose" in c}
    assert labelled == {w for w, _ in tmuxmgr.WINDOWS}
