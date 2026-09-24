"""backfill.py: one command that checks, previews and loads one person's sessions.

https://github.com/beril-doe/langfuse-retro-load/issues/38
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
pytest.importorskip("langfuse")
import backfill  # noqa: E402
import inventory  # noqa: E402
import retro_load  # noqa: E402


def turn(sid, text, when):
    return [
        {"type": "user", "sessionId": sid, "uuid": f"{sid}-u", "timestamp": when,
         "message": {"role": "user", "content": text}},
        {"type": "assistant", "sessionId": sid, "uuid": f"{sid}-a", "timestamp": when,
         "message": {"role": "assistant", "model": "claude",
                     "content": [{"type": "text", "text": "ok"}]}},
    ]


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    monkeypatch.setattr(retro_load, "MARKER_DIR", tmp_path / "markers")
    root = tmp_path / "projects"
    (root / "proj").mkdir(parents=True)
    for sid, text in (("s-1", "write to someone@gmail.com please"), ("s-2", "nothing here")):
        lines = turn(sid, text, "2026-05-07T12:00:00Z")
        (root / "proj" / f"{sid}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in lines))
    people = tmp_path / "people.json"
    people.write_text(json.dumps([{
        "person": "someone", "user_id": "someone",
        "orcid": "https://orcid.org/0000-0002-1825-0097", "role": None, "group": None,
        "sources": [{"type": "workshop-frozen-corpus", "find_root": str(root),
                     "consent_bin": "opt_in", "force_event_day": []}]}]))
    monkeypatch.setattr(backfill, "HERE", tmp_path)
    # CI has no gitleaks. Stand in for it with "installed, found nothing", so every test
    # here runs everywhere; the setup test below replaces this with "not installed".
    monkeypatch.setattr(backfill.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda path: [])
    return people


def run(monkeypatch, people, *argv):
    monkeypatch.setattr(sys, "argv", ["backfill.py", "someone", "--people", str(people),
                                      "--skip-git-check", *argv])
    return backfill.main()


def test_the_preview_builds_a_plan_and_sends_nothing(corpus, monkeypatch, capsys):
    sent = []
    monkeypatch.setattr(backfill, "run_load", lambda cmd: sent.append(cmd) or 0)
    assert run(monkeypatch, corpus) == 0
    out = capsys.readouterr().out
    assert sent == [], "the preview ran a load"
    assert "user_id  : 0000-0002-1825-0097" in out
    assert "workshop-frozen-corpus (consent: opt_in): 2 sessions" in out
    assert "email" in out, "the plan summary should show the email it will mask"
    assert "Nothing sent" in out
    assert list((corpus.parent / "plans").glob("someone-*.jsonl"))


def test_load_passes_only_the_previewed_sessions_to_run_manifest(corpus, monkeypatch):
    seen = {}

    def fake_load(cmd):
        manifest = json.loads(Path(cmd[cmd.index("--manifest") + 1]).read_text())
        seen["sessions"] = sorted(e["session_id"] for e in manifest)
        seen["user_ids"] = {e["user_id"] for e in manifest}
        seen["cmd"] = cmd
        return 0

    monkeypatch.setattr(backfill, "run_load", fake_load)
    assert run(monkeypatch, corpus, "--load", "--session", "s-2", "--force",
               "--batch-tag", "backfill-test") == 0
    assert seen["sessions"] == ["s-2"]
    assert seen["user_ids"] == {"0000-0002-1825-0097"}
    cmd = seen["cmd"]
    assert cmd[cmd.index("--batch-tag") + 1] == "backfill-test"
    assert "--force" in cmd and "--plan" in cmd
    assert cmd[cmd.index("--min-idle-days") + 1] == "1.0", "a session in use could load half done"


def test_setup_problems_stop_it_before_anything_is_read(corpus, monkeypatch, capsys):
    monkeypatch.setattr(backfill.shutil, "which", lambda name: None)

    def must_not_run(*a, **k):
        raise AssertionError("looked for transcripts before the setup was fixed")

    monkeypatch.setattr(backfill, "discover", must_not_run)
    assert run(monkeypatch, corpus) == 2
    err = capsys.readouterr().err
    assert "gitleaks is not installed" in err and "Fix:" in err


def test_a_stale_branch_is_reported_with_its_fix(monkeypatch):
    answers = {("rev-parse", "--abbrev-ref", "HEAD"): "sensitivity-inventory",
               ("rev-parse", "HEAD"): "aaa", ("rev-parse", "origin/main"): "bbb"}
    monkeypatch.setattr(backfill, "git", lambda *a: subprocess.CompletedProcess(
        a, 0, stdout=answers.get(a, "") + "\n", stderr=""))
    problems = backfill.setup_problems()
    assert any("on 'sensitivity-inventory', not main" in p and "switch main" in p
               for p in problems)


def test_main_behind_origin_is_reported(monkeypatch):
    answers = {("rev-parse", "--abbrev-ref", "HEAD"): "main",
               ("rev-parse", "HEAD"): "aaa", ("rev-parse", "origin/main"): "bbb"}
    monkeypatch.setattr(backfill, "git", lambda *a: subprocess.CompletedProcess(
        a, 0, stdout=answers.get(a, "") + "\n", stderr=""))
    assert any("main is not current" in p for p in backfill.setup_problems())


def test_an_unknown_session_is_an_error_not_an_empty_load(corpus, monkeypatch):
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    with pytest.raises(SystemExit, match="not found"):
        run(monkeypatch, corpus, "--load", "--session", "no-such-session")


def test_an_unknown_person_lists_who_is_known(corpus, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["backfill.py", "nobody", "--people", str(corpus),
                                      "--skip-git-check"])
    with pytest.raises(SystemExit, match="Known: someone"):
        backfill.main()
