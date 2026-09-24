"""artifacts.py: rebuild BERIL artifacts from transcripts and upload them as the live hook does."""
import contextlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
pytest.importorskip("langfuse")
import artifacts  # noqa: E402
import inventory  # noqa: E402

P = "/home/u/BERIL/projects/demo/"


def tool(tid, name, inp, ts):
    return {"type": "assistant", "timestamp": ts,
            "message": {"content": [{"type": "tool_use", "id": tid, "name": name, "input": inp}]}}


def result(tid, ts, error=False):
    return {"type": "user", "timestamp": ts,
            "message": {"content": [{"type": "tool_result", "tool_use_id": tid, "is_error": error,
                                     "content": "ok"}]}}


def session(tmp_path, sid, records):
    path = tmp_path / "projects" / "proj" / f"{sid}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


# --- replay --------------------------------------------------------------------------------

def test_write_then_edits_replay_exactly():
    s = artifacts.apply(None, "Write", {"content": "a b a"})
    s = artifacts.apply(s, "Edit", {"old_string": "a", "new_string": "x"})
    assert s == "x b a"
    s = artifacts.apply(s, "Edit", {"old_string": "a", "new_string": "y", "replace_all": True})
    assert s == "x b y"
    s = artifacts.apply(s, "MultiEdit", {"edits": [{"old_string": "x", "new_string": "1"},
                                                   {"old_string": "y", "new_string": "2"}]})
    assert s == "1 b 2"


def test_an_edit_that_cannot_apply_makes_the_state_unknown():
    assert artifacts.apply("abc", "Edit", {"old_string": "zzz", "new_string": "q"}) is None
    assert artifacts.apply(None, "Edit", {"old_string": "a", "new_string": "q"}) is None


def test_snapshots_carry_the_project_state_at_each_session_end(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
        tool("t2", "Edit", {"file_path": P + "REPORT.md", "old_string": "v1", "new_string": "v2"},
             "2026-05-07T10:05:00Z"),
        result("t2", "2026-05-07T10:05:01Z"),
    ])
    s2 = session(tmp_path, "s2", [
        tool("t3", "Write", {"file_path": P + "RESEARCH_PLAN.md", "content": "plan"},
             "2026-05-08T09:00:00Z"),
        result("t3", "2026-05-08T09:00:01Z"),
    ])
    snaps = {s.session_id: s for s in artifacts.snapshots([s1, s2])}
    assert snaps["s1"].files == {"REPORT.md": "v2"}
    assert snaps["s2"].files == {"REPORT.md": "v2", "RESEARCH_PLAN.md": "plan"}, \
        "the live hook uploads every artifact the project has at session end"
    assert snaps["s1"].ended == "2026-05-07T10:05:01Z"


def test_a_failed_tool_call_does_not_change_the_file(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
        tool("t2", "Write", {"file_path": P + "REPORT.md", "content": "never written"},
             "2026-05-07T10:01:00Z"),
        result("t2", "2026-05-07T10:01:01Z", error=True),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {"REPORT.md": "v1"}


def test_a_shell_write_makes_the_file_unknown(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
        tool("t2", "Bash", {"command": f"sed -i 's/v1/v2/' {P}REPORT.md"}, "2026-05-07T10:02:00Z"),
        result("t2", "2026-05-07T10:02:01Z"),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {} and snap.unknown == ["REPORT.md"]


def test_a_shell_read_does_not(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
        tool("t2", "Bash", {"command": f"wc -l {P}REPORT.md"}, "2026-05-07T10:02:00Z"),
        result("t2", "2026-05-07T10:02:01Z"),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {"REPORT.md": "v1"}


def test_files_outside_a_project_or_with_other_names_are_ignored(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": "/home/u/REPORT.md", "content": "x"}, "2026-05-07T10:00:00Z"),
        tool("t2", "Write", {"file_path": P + "REVIEW_1.md", "content": "x"}, "2026-05-07T10:00:00Z"),
    ])
    assert artifacts.snapshots([s1]) == []


# --- masking -------------------------------------------------------------------------------

def test_masking_replaces_personal_details(monkeypatch):
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [])
    clean, n = artifacts.mask("Contact someone.person@gmail.com for data", "REPORT.md")
    assert "someone.person@gmail.com" not in clean and n == 1


def test_a_file_gitleaks_still_flags_is_refused(monkeypatch):
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [{"RuleID": "x"}])
    with pytest.raises(artifacts.Refused, match="still finds"):
        artifacts.mask("text", "REPORT.md")


def test_no_gitleaks_means_no_upload(monkeypatch):
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: None)
    with pytest.raises(artifacts.Refused, match="not installed"):
        artifacts.mask("text", "REPORT.md")


# --- the upload's shape --------------------------------------------------------------------

def test_the_span_matches_the_live_hook(monkeypatch):
    import langfuse
    import langfuse_hook_official as hook
    seen = {}

    @contextlib.contextmanager
    def attrs(**kw):
        seen["attrs"] = kw
        yield

    class Span:
        def end(self, end_time=None):
            seen["ended"] = end_time

    def start(client, **kw):
        seen["span"] = kw
        return Span()

    monkeypatch.setattr(langfuse, "propagate_attributes", attrs)
    monkeypatch.setattr(hook, "_start_backdated", start)
    snap = artifacts.Snapshot("s1", "demo", "2026-05-07T10:05:01Z")
    artifacts.upload(object(), snap, {"REPORT.md": "text"}, "0000-0002-1825-0097")
    assert seen["attrs"] == {"session_id": "s1", "user_id": "0000-0002-1825-0097",
                             "tags": ["beril", "artifacts", "demo", "retro-load"]}
    assert seen["span"]["name"] == "BERIL artifacts — demo"
    assert seen["span"]["input"] == {"project": "demo", "files": ["REPORT.md"]}
    assert set(seen["span"]["metadata"]) == {"REPORT.md"}
    assert seen["span"]["start_time"].isoformat().startswith("2026-05-07T10:05:01")


# --- the command ---------------------------------------------------------------------------

@pytest.fixture
def roster(tmp_path, monkeypatch):
    session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
    ])
    people = tmp_path / "roster.json"
    people.write_text(json.dumps([{"person": "someone", "user_id": "someone",
                                   "orcid": "https://orcid.org/0000-0002-1825-0097",
                                   "sources": [{"type": "t", "find_root": str(tmp_path / "projects")}]}]))
    monkeypatch.setattr(artifacts.backfill, "setup_problems", lambda skip_git=False: [])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [])
    monkeypatch.setattr(artifacts, "MARKER_DIR", tmp_path / "markers")
    return people


def test_the_preview_sends_nothing(roster, monkeypatch, capsys):
    monkeypatch.setattr(artifacts, "upload", lambda *a: pytest.fail("the preview uploaded"))
    monkeypatch.setattr(sys, "argv", ["artifacts.py", "someone", "--people", str(roster)])
    assert artifacts.main() == 0
    out = capsys.readouterr().out
    assert "s1 demo: REPORT.md (2 chars, 0 masked)" in out and "Nothing sent" in out


def test_nobody_is_loaded_without_an_orcid(roster, monkeypatch):
    people = json.loads(roster.read_text())
    del people[0]["orcid"]
    roster.write_text(json.dumps(people))
    monkeypatch.setattr(sys, "argv", ["artifacts.py", "someone", "--people", str(roster)])
    with pytest.raises(SystemExit, match="no orcid"):
        artifacts.main()


def test_a_snapshot_is_sent_once(roster, monkeypatch, capsys):
    import retro_load

    class Client:
        def flush(self): pass
        def shutdown(self): pass

    sent = []
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")
    monkeypatch.setattr(retro_load, "make_client", lambda *a, **k: Client())
    monkeypatch.setattr(artifacts, "upload", lambda client, snap, masked, uid: sent.append((snap.session_id, uid)))
    monkeypatch.setattr(sys, "argv", ["artifacts.py", "someone", "--people", str(roster), "--load"])
    assert artifacts.main() == 0
    assert artifacts.main() == 0
    assert sent == [("s1", "0000-0002-1825-0097")], "the second run must skip what the first sent"
    assert "already sent, skipped" in capsys.readouterr().out
