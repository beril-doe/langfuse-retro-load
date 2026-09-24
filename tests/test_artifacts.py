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
    assert snaps["s1"].ended == "2026-05-07T10:05:01+00:00"


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


@pytest.mark.parametrize("command, writes", [
    (f"grep -n x {P}REPORT.md 2>&1 | head", set()),
    (f"cat {P}REPORT.md > /tmp/copy.md", set()),
    (f"cp {P}REPORT.md /tmp/backup.md", set()),
    (f"echo done > {P}REPORT.md", {("demo", "REPORT.md")}),
    (f"echo more >> {P}WORKLOG.md", {("demo", "WORKLOG.md")}),
    (f"cat x | tee {P}REPORT.md", {("demo", "REPORT.md")}),
    (f"sed -i 's/a/b/' {P}REPORT.md", {("demo", "REPORT.md")}),
    (f"cp /tmp/new.md {P}REPORT.md", {("demo", "REPORT.md")}),
    (f"cp /tmp/REPORT.md {P}", {("demo", "REPORT.md")}),
    (f"cd x && rm {P}RESEARCH_PLAN.md", {("demo", "RESEARCH_PLAN.md")}),
    (f"git checkout -- {P}REPORT.md", {("demo", "REPORT.md")}),
    (f"git add {P}REPORT.md && git commit -m x", set()),
])
def test_shell_writes_are_told_apart_from_reads(command, writes):
    assert artifacts.shell_writes(command) == writes


def test_reading_another_projects_report_creates_no_snapshot(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Bash", {"command": "cat /home/u/BERIL/projects/other/REPORT.md 2>&1"},
             "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
    ])
    assert artifacts.snapshots([s1]) == []


# --- first Copilot review of PR 47 ------------------------------------------------------------

def test_a_short_value_under_a_credential_key_is_masked(monkeypatch):
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [])
    clean, n = artifacts.mask("Setup:\nexport KBASE_AUTH_TOKEN=s3cret\ndone", "REPORT.md")
    assert "s3cret" not in clean and "KBASE_AUTH_TOKEN=" in clean and n == 1


def test_a_reference_under_a_credential_key_is_left_alone(monkeypatch):
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [])
    clean, n = artifacts.mask("export KBASE_AUTH_TOKEN=$KBASE_TOKEN", "REPORT.md")
    assert clean == "export KBASE_AUTH_TOKEN=$KBASE_TOKEN" and n == 0


@pytest.mark.parametrize("command", [f"make 2> {P}REPORT.md", f"make 2>> {P}REPORT.md"])
def test_a_stderr_redirect_onto_an_artifact_is_a_write(command):
    assert artifacts.shell_writes(command) == {("demo", "REPORT.md")}


def test_an_unreadable_end_time_makes_the_snapshot_unknown(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "not a time"),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {} and snap.unknown == ["REPORT.md"] and "end time" in snap.reason


def test_a_zone_less_end_time_is_refused_too(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01"),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {}


def test_a_change_by_another_session_before_this_one_ends_is_included(tmp_path):
    """s1 edits at 10:00 and ends at 12:00; s2 edits the same project at 11:00."""
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
        {"type": "user", "timestamp": "2026-05-07T12:00:00Z", "message": {"content": "later"}},
    ])
    s2 = session(tmp_path, "s2", [
        tool("t2", "Edit", {"file_path": P + "REPORT.md", "old_string": "v1", "new_string": "v2"},
             "2026-05-07T11:00:00Z"),
        result("t2", "2026-05-07T11:00:01Z"),
    ])
    snaps = {s.session_id: s for s in artifacts.snapshots([s1, s2])}
    assert snaps["s1"].files == {"REPORT.md": "v2"}, "the state at s1's end, not at its last edit"


def test_one_session_id_in_two_sources_is_refused(tmp_path):
    a = session(tmp_path, "s1", [])
    b = tmp_path / "other" / "s1.jsonl"
    b.parent.mkdir(parents=True)
    b.write_text("")
    with pytest.raises(ValueError, match="more than one source"):
        artifacts.snapshots([a, b])


def test_the_marker_depends_on_the_langfuse_project():
    assert artifacts.marker("h", "pk-a", "s1", "demo") != artifacts.marker("h", "pk-b", "s1", "demo")


def test_a_partial_or_foreign_marker_does_not_count_as_sent(tmp_path):
    expected = {"session_id": "s1", "project": "demo", "host": "h", "public_key": "pk"}
    path = tmp_path / "m.json"
    path.write_text('{"session_id": "s1"')
    assert not artifacts.already_sent(path, expected)
    path.write_text(json.dumps({**expected, "public_key": "other"}))
    assert not artifacts.already_sent(path, expected)
    artifacts.write_marker(path, expected)
    assert artifacts.already_sent(path, expected) and not path.with_suffix(".tmp").exists()


def test_the_marker_is_written_only_after_flushing(roster, monkeypatch):
    import retro_load
    order = []

    class Client:
        def flush(self): order.append("flush")
        def shutdown(self): pass

    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")
    monkeypatch.setattr(retro_load, "make_client", lambda *a, **k: Client())
    monkeypatch.setattr(artifacts, "upload", lambda *a: order.append("upload"))
    real = artifacts.write_marker
    monkeypatch.setattr(artifacts, "write_marker", lambda p, r: (order.append("marker"), real(p, r)))
    monkeypatch.setattr(sys, "argv", ["artifacts.py", "someone", "--people", str(roster), "--load"])
    assert artifacts.main() == 0
    assert order == ["upload", "flush", "marker"]


# --- second Copilot review of PR 47 -----------------------------------------------------------

@pytest.mark.parametrize("command", [f"git -C /home/u/BERIL checkout -- {P}REPORT.md",
                                     f"git -c core.x=1 restore {P}REPORT.md"])
def test_git_global_options_do_not_hide_the_subcommand(command):
    assert artifacts.shell_writes(command) == {("demo", "REPORT.md")}


def test_an_edit_with_no_recorded_result_makes_the_file_unknown(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
        tool("t2", "Edit", {"file_path": P + "REPORT.md", "old_string": "v1", "new_string": "v2"},
             "2026-05-07T10:05:00Z"),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {} and snap.unknown == ["REPORT.md"]



@pytest.mark.parametrize("command", [f"git --git-dir /home/u/BERIL/.git checkout {P}REPORT.md",
                                     f"git --work-tree=/home/u/BERIL checkout {P}REPORT.md",
                                     f"git -C /home/u/BERIL -c a=b stash push {P}REPORT.md"])
def test_more_git_global_option_forms(command):
    assert artifacts.shell_writes(command) == {("demo", "REPORT.md")}


def test_an_undated_change_keeps_the_file_unknown_after_later_writes(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t0", "Bash", {"command": f"echo x > {P}REPORT.md"}, None),
        result("t0", "2026-05-07T09:00:01Z"),
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {} and snap.unknown == ["REPORT.md"]


def test_a_missing_tool_id_does_not_confirm_an_edit(tmp_path):
    s1 = session(tmp_path, "s1", [
        tool("t1", "Write", {"file_path": P + "REPORT.md", "content": "v1"}, "2026-05-07T10:00:00Z"),
        result("t1", "2026-05-07T10:00:01Z"),
        tool(None, "Edit", {"file_path": P + "REPORT.md", "old_string": "v1", "new_string": "v2"},
             "2026-05-07T10:05:00Z"),
        result(None, "2026-05-07T10:05:01Z"),
    ])
    [snap] = artifacts.snapshots([s1])
    assert snap.files == {} and snap.unknown == ["REPORT.md"]
