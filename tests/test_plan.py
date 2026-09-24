"""The redaction plan: built at scan time, checked against the transcript, applied at load."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import inventory  # noqa: E402
import plan  # noqa: E402
import redaction  # noqa: E402

FAKE = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
SHAPELESS = "Zq" + "9vLm2Tx8" * 3   # a token no local pattern recognises


def _transcript(tmp_path, records, name="s-1.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def test_a_local_finding_is_planned_with_offsets_and_applied_to_just_that_span(tmp_path):
    record = {"type": "user", "message": {"content": "before token=" + FAKE + " after"}}
    path = _transcript(tmp_path, [record])
    header, masks = plan.build(path, use_gitleaks=False)
    assert header.subject == "s-1" and header.records == 1
    assert [(m.record, m.pointer, m.pattern) for m in masks] == [(0, "/message/content", "github_pat")]
    out = plan.apply([record], masks)[0]["message"]["content"]
    assert FAKE not in out and out.startswith("before token=") and out.endswith(" after")


def test_the_plan_holds_no_values(tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "token=" + FAKE}}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    assert FAKE not in out.read_text()


def test_a_gitleaks_only_match_is_pinned_to_its_field(monkeypatch, tmp_path):
    record = {"type": "user", "message": {"content": "deploy key " + SHAPELESS + " ok"}}
    path = _transcript(tmp_path, [{"type": "summary"}, record])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "generic-api-key", "Secret": SHAPELESS, "StartLine": 2}])
    header, masks = plan.build(path)
    assert "gitleaks" in header.detectors
    assert [(m.record, m.pointer, m.detector) for m in masks] == [(1, "/message/content", "gitleaks")]
    out = plan.apply([{"type": "summary"}, record], masks)[1]["message"]["content"]
    assert SHAPELESS not in out and out.endswith(" ok")


def test_a_gitleaks_match_it_cannot_find_is_kept_and_refused(monkeypatch, tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "nothing here"}}])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": "not-in-the-record", "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path)])
    with pytest.raises(plan.PlanError, match="could not be pinned"):
        plan.for_transcript(out, path)


def test_a_transcript_that_changed_after_planning_is_refused(tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "token=" + FAKE}}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    path.write_text(path.read_text() + json.dumps({"message": {"content": "later"}}) + "\n")
    with pytest.raises(plan.PlanError, match="changed after its plan"):
        plan.for_transcript(out, path)


def test_a_transcript_with_no_plan_entry_is_refused(tmp_path):
    a = _transcript(tmp_path, [{"x": 1}], "a.jsonl")
    b = _transcript(tmp_path, [{"x": 2}], "b.jsonl")
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(a, use_gitleaks=False)])
    with pytest.raises(plan.PlanError, match="no entry"):
        plan.for_transcript(out, b)


def test_a_clean_transcript_still_has_a_header(tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "nothing to see"}}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    assert plan.for_transcript(out, path) == []


def test_a_clearance_removes_exactly_what_it_names(tmp_path):
    record = {"message": {"content": "token=" + FAKE + " mail a.b@gmail.com"}}
    path = _transcript(tmp_path, [record])
    _, masks = plan.build(path, use_gitleaks=False, clearances=[{"pattern": "email_personal"}])
    assert [m.pattern for m in masks if not m.cleared] == ["github_pat"]
    assert [m.pattern for m in masks if m.cleared] == ["email_personal"]
    out = plan.apply([record], masks)[0]["message"]["content"]
    assert "a.b@gmail.com" in out and FAKE not in out


def test_fingerprints_are_stable_across_scans_of_the_same_transcript(tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "token=" + FAKE}}])
    _, first = plan.build(path, use_gitleaks=False)
    _, second = plan.build(path, use_gitleaks=False)
    assert [m.fingerprint for m in first] == [m.fingerprint for m in second]


def test_overlapping_spans_from_both_detectors_are_merged(tmp_path):
    record = {"m": "x " + FAKE + " y"}
    start = record["m"].index(FAKE)
    local = plan.Mask("s", 0, "/m", start, start + len(FAKE), "github_pat", "secret", "redaction", "aaaa")
    wider = plan.Mask("s", 0, "/m", start - 2, start + len(FAKE), "gitleaks:x", "secret", "gitleaks", "bbbb")
    out = plan.apply([record], [local, wider])[0]["m"]
    assert FAKE not in out and out.count("[REDACTED:") == 1 and out.endswith(" y")


def test_a_second_redaction_pass_leaves_plan_placeholders_alone(tmp_path):
    record = {"message": {"content": "key " + SHAPELESS}}
    start = record["message"]["content"].index(SHAPELESS)
    mask = plan.Mask("s", 0, "/message/content", start, start + len(SHAPELESS),
                     "gitleaks:x", "secret", "gitleaks", "cafebabe")
    once = plan.apply([record], [mask])[0]
    twice, found = redaction.redact_tree(once, key=b"k")
    assert twice == once and found == []


@pytest.mark.parametrize("mask", [
    plan.Mask("s", 0, "/nope", 0, 3, "p", "secret", "redaction", "f"),
    plan.Mask("s", 0, "/m", 0, 999, "p", "secret", "redaction", "f"),
    plan.Mask("s", 5, "/m", 0, 1, "p", "secret", "redaction", "f"),
])
def test_a_mask_that_does_not_fit_raises(mask):
    with pytest.raises(plan.PlanError):
        plan.apply([{"m": "short"}], [mask])


def test_a_malformed_plan_line_is_a_plan_error(tmp_path):
    out = tmp_path / "plan.jsonl"
    out.write_text('{"kind": "mask", "subject": "s"}\n')
    with pytest.raises(plan.PlanError):
        plan.read(out)


def test_build_uses_real_gitleaks_when_installed(tmp_path):
    """End to end with the real binary, skipped where it is not installed."""
    import shutil
    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks not installed")
    record = {"message": {"content": "export GITHUB_TOKEN=" + FAKE}}
    path = _transcript(tmp_path, [record])
    header, masks = plan.build(path)
    assert "gitleaks" in header.detectors
    assert {m.detector for m in masks} == {"redaction", "gitleaks"}
    out = plan.apply([record], masks)[0]["message"]["content"]
    assert FAKE not in out


# --- the loader's side ---------------------------------------------------------------------

@pytest.fixture
def loader(monkeypatch, tmp_path):
    pytest.importorskip("dotenv")
    import retro_load
    monkeypatch.setattr(retro_load, "MARKER_DIR", tmp_path / "markers")
    for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST", "LANGFUSE_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    return retro_load


def _run(module, monkeypatch, *argv) -> int:
    monkeypatch.setattr(sys, "argv", ["retro_load.py", *argv])
    return module.main()


def _session(tmp_path, content) -> Path:
    return _transcript(tmp_path, [{"type": "user", "uuid": "u-1",
                                   "timestamp": "2026-01-01T00:00:00Z",
                                   "message": {"role": "user", "content": content}}])


def test_a_real_load_without_a_plan_is_refused(loader, monkeypatch, tmp_path):
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")
    monkeypatch.setattr(loader.presence, "session_observation_count", lambda *a, **k: 0)
    assert _run(loader, monkeypatch, str(_session(tmp_path, "hi"))) == 1


def test_a_plan_for_a_changed_transcript_is_refused(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "hi")
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    path.write_text(path.read_text().replace("hi", "hello"))
    assert _run(loader, monkeypatch, "--dry-run", "--plan", str(out), str(path)) == 1


def test_the_plan_removes_a_secret_only_gitleaks_found(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "deploy key " + SHAPELESS)
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "generic-api-key", "Secret": SHAPELESS, "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path)])
    seen = []
    monkeypatch.setattr(loader, "build_turns", lambda msgs: seen.extend(msgs) or [])
    assert _run(loader, monkeypatch, "--dry-run", "--plan", str(out), str(path)) == 0
    assert SHAPELESS not in json.dumps(seen)


def test_without_a_plan_the_same_secret_would_go_out(loader, monkeypatch, tmp_path):
    """The control: our own patterns don't know this shape, which is why the plan exists."""
    path = _session(tmp_path, "deploy key " + SHAPELESS)
    seen = []
    monkeypatch.setattr(loader, "build_turns", lambda msgs: seen.extend(msgs) or [])
    assert _run(loader, monkeypatch, "--dry-run", str(path)) == 0
    assert SHAPELESS in json.dumps(seen)


# --- the viewer ------------------------------------------------------------------------------

def test_reveal_shows_the_plan_without_printing_the_value(monkeypatch, tmp_path, capsys):
    pytest.importorskip("dotenv")
    import reveal
    path = _session(tmp_path, "deploy key " + SHAPELESS + " end")
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "generic-api-key", "Secret": SHAPELESS, "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path)])
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out)])
    assert reveal.main() == 0
    printed = capsys.readouterr().out
    assert "record 0  /message/content  gitleaks:generic-api-key" in printed
    assert SHAPELESS not in printed and "deploy key" in printed


def test_reveal_refuses_a_stale_plan(monkeypatch, tmp_path):
    pytest.importorskip("dotenv")
    import reveal
    path = _session(tmp_path, "hi")
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    path.write_text(path.read_text().replace("hi", "hello"))
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out)])
    assert reveal.main() == 1


# --- first Copilot review of PR 27 ------------------------------------------------------------

def _cli(monkeypatch, *argv) -> int:
    monkeypatch.setattr(sys, "argv", ["plan.py", *argv])
    return plan.main()


def test_build_refuses_two_inputs_with_the_same_session_id(monkeypatch, tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = _transcript(tmp_path / "a", [{"x": 1}], "s.jsonl")
    b = _transcript(tmp_path / "b", [{"x": 2}], "s.jsonl")
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "build", "--no-gitleaks", "--out", str(tmp_path / "p.jsonl"), str(a), str(b))


def test_build_refuses_to_overwrite_a_transcript(monkeypatch, tmp_path):
    path = _transcript(tmp_path, [{"x": 1}])
    before = path.read_bytes()
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "build", "--no-gitleaks", "--out", str(path), str(path))
    assert path.read_bytes() == before


def test_build_refuses_when_gitleaks_is_missing(monkeypatch, tmp_path):
    path = _transcript(tmp_path, [{"x": 1}])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: None)
    with pytest.raises(plan.PlanError, match="gitleaks is not installed"):
        plan.build(path)


def test_the_loader_refuses_a_plan_built_without_gitleaks(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "hi")
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    assert _run(loader, monkeypatch, "--dry-run", "--plan", str(out), str(path)) == 1
    assert _run(loader, monkeypatch, "--dry-run", "--allow-plan-without-gitleaks",
                "--plan", str(out), str(path)) == 0


def test_a_clearance_survives_the_loaders_second_pass(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "mail a.b@gmail.com please")
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False, clearances=[{"pattern": "email_personal"}])])
    seen = []
    monkeypatch.setattr(loader, "build_turns", lambda msgs: seen.extend(msgs) or [])
    assert _run(loader, monkeypatch, "--dry-run", "--allow-plan-without-gitleaks",
                "--plan", str(out), str(path)) == 0
    assert "a.b@gmail.com" in json.dumps(seen)


def test_a_finding_the_plan_missed_blocks_the_load(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "token=" + FAKE)
    out = tmp_path / "plan.jsonl"
    header, _ = plan.build(path, use_gitleaks=False)
    plan.write(out, [(header, [])])        # a plan that masks nothing
    assert _run(loader, monkeypatch, "--dry-run", "--allow-plan-without-gitleaks",
                "--plan", str(out), str(path)) == 1


def test_plan_and_no_redact_together_are_refused(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "hi")
    with pytest.raises(SystemExit):
        _run(loader, monkeypatch, "--dry-run", "--no-redact", "--plan", str(tmp_path / "p"), str(path))


def test_a_gitleaks_match_only_in_a_structural_field_is_not_placed(monkeypatch, tmp_path):
    record = {"type": "user", "uuid": SHAPELESS, "message": {"content": "nothing"}}
    path = _transcript(tmp_path, [record])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": SHAPELESS, "StartLine": 1}])
    _, masks = plan.build(path)
    assert [(m.pointer, m.detector) for m in masks] == [(None, "gitleaks")]


def test_the_manifest_passes_the_plan_to_each_load(loader, monkeypatch, tmp_path):
    import run_manifest
    path = _session(tmp_path, "hi")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([{"session_id": "s-1", "user_id": "u", "event_day": False,
                                     "source": "t", "find_root": str(tmp_path)}]))
    monkeypatch.setattr(run_manifest, "resolve_path", lambda root, sid: path)
    calls = []
    monkeypatch.setattr(run_manifest.subprocess, "run",
                        lambda cmd, **k: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""))
    monkeypatch.setattr(sys, "argv", ["run_manifest.py", "--manifest", str(manifest),
                                      "--plan", str(tmp_path / "plan.jsonl")])
    run_manifest.main()
    assert "--plan" in calls[0] and str(tmp_path / "plan.jsonl") in calls[0]


# --- second Copilot review of PR 27 -----------------------------------------------------------

def test_a_gitleaks_value_also_in_a_structural_field_blocks(monkeypatch, tmp_path):
    record = {"type": "user", "uuid": SHAPELESS, "message": {"content": "key " + SHAPELESS}}
    path = _transcript(tmp_path, [record])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": SHAPELESS, "StartLine": 1}])
    _, masks = plan.build(path)
    assert [(m.pointer, m.detector) for m in masks] == [(None, "gitleaks")]


def test_clearances_cannot_be_a_transcript(monkeypatch, tmp_path):
    path = _transcript(tmp_path, [{"x": 1}])
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "build", "--no-gitleaks", "--clearances", str(path),
             "--out", str(tmp_path / "p.jsonl"), str(path))


def test_a_second_uncleared_value_of_the_same_kind_in_the_field_blocks(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "mail a.b@gmail.com and c.d@gmail.com")
    header, masks = plan.build(path, use_gitleaks=False)
    first = next(m for m in masks if m.pattern == "email_personal")
    # Clear only the first address by fingerprint, and drop the second from the plan.
    kept = [plan.replace(first, cleared=True)]
    out = tmp_path / "plan.jsonl"
    plan.write(out, [(header, kept)])
    assert _run(loader, monkeypatch, "--dry-run", "--allow-plan-without-gitleaks",
                "--plan", str(out), str(path)) == 1


def test_plan_and_without_plan_together_are_refused(loader, monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        _run(loader, monkeypatch, "--dry-run", "--plan", str(tmp_path / "p"), "--without-plan",
             str(_session(tmp_path, "hi")))


def test_reveal_shows_a_cleared_unplaceable_row_as_cleared(monkeypatch, tmp_path, capsys):
    pytest.importorskip("dotenv")
    import reveal
    path = _session(tmp_path, "nothing")
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": "absent", "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, clearances=[{"pattern": "gitleaks:x"}])])
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out)])
    assert reveal.main() == 0
    printed = capsys.readouterr().out
    assert "CLEARED" in printed and "will refuse" not in printed


def test_reveal_never_prints_a_neighbouring_planned_value(monkeypatch, tmp_path, capsys):
    pytest.importorskip("dotenv")
    import reveal
    other = "Qw" + "7rTy3Up" * 3        # gitleaks-only, no local pattern knows it
    path = _session(tmp_path, "token=" + FAKE + " and " + other + " end")
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": other, "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path)])
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out)])
    assert reveal.main() == 0
    printed = capsys.readouterr().out
    assert other not in printed and FAKE not in printed and "[another planned mask]" in printed


def test_show_values_shows_the_neighbouring_planned_value_too(monkeypatch, tmp_path, capsys):
    """Asked for 2026-09-24: with --show-values the context should read as the transcript
    does, not hide the email beside a name behind a placeholder."""
    pytest.importorskip("dotenv")
    import reveal
    other = "Qw" + "7rTy3Up" * 3
    path = _session(tmp_path, "token=" + FAKE + " and " + other + " end")
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": other, "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path)])
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out),
                                      "--show-values"])
    assert reveal.main() == 0
    printed = capsys.readouterr().out
    assert other in printed and FAKE in printed
    assert "[another planned mask]" not in printed


def test_show_values_does_not_re_redact_a_neighbouring_local_finding(monkeypatch, tmp_path, capsys):
    """Two personal emails in one field: the second was printed as [REDACTED:...] by the
    context's own redaction pass even after the placeholder was dropped (first Copilot
    review of https://github.com/beril-doe/langfuse-retro-load/pull/43)."""
    pytest.importorskip("dotenv")
    import reveal
    first, second = "alpha.person@gmail.com", "beta.person@gmail.com"
    path = _session(tmp_path, f"write to {first} and {second} today")
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path)])
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out),
                                      "--show-values"])
    assert reveal.main() == 0
    printed = capsys.readouterr().out
    assert printed.count(first) == 2 and printed.count(second) == 2, printed
    assert "[REDACTED" not in printed


# --- third Copilot review of PR 27 ------------------------------------------------------------

def test_a_gitleaks_value_that_is_also_an_object_key_blocks(monkeypatch, tmp_path):
    record = {"type": "user", "message": {"content": "key " + SHAPELESS, "meta": {SHAPELESS: 1}}}
    path = _transcript(tmp_path, [record])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": SHAPELESS, "StartLine": 1}])
    _, masks = plan.build(path)
    assert [(m.pointer, m.detector) for m in masks] == [(None, "gitleaks")]


def test_the_manifest_refuses_a_real_run_without_a_plan(monkeypatch, tmp_path):
    import run_manifest
    manifest = tmp_path / "manifest.json"
    manifest.write_text("[]")
    monkeypatch.setattr(sys, "argv", ["run_manifest.py", "--manifest", str(manifest)])
    with pytest.raises(SystemExit):
        run_manifest.main()


def test_the_inventory_records_what_the_plan_masked(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "deploy key " + SHAPELESS)
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "generic-api-key", "Secret": SHAPELESS, "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path)])
    inv = tmp_path / "load-inv.jsonl"
    monkeypatch.setattr(loader, "build_turns", lambda msgs: [])
    assert _run(loader, monkeypatch, "--dry-run", "--plan", str(out), "--inventory", str(inv),
                str(path)) == 0
    rows = [json.loads(line) for line in inv.read_text().splitlines()]
    assert [(r["detector"], r["pattern"]) for r in rows if r["category"] == "secret"] == [
        ("gitleaks", "gitleaks:generic-api-key")]
    assert SHAPELESS not in inv.read_text()


# --- fourth Copilot review of PR 27 -----------------------------------------------------------

def test_a_plan_cut_short_after_its_header_is_refused(tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "token=" + FAKE}}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    header_line = out.read_text().splitlines()[0]
    out.write_text(header_line + "\n")          # the mask rows never made it
    with pytest.raises(plan.PlanError, match="incomplete"):
        plan.for_transcript(out, path)


def test_the_plan_is_written_atomically(monkeypatch, tmp_path):
    path = _transcript(tmp_path, [{"x": 1}])
    out = tmp_path / "plan.jsonl"
    out.write_text("previous plan\n")
    monkeypatch.setattr(plan.json, "dumps", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        plan.write(out, [plan.build(path, use_gitleaks=False)])
    assert out.read_text() == "previous plan\n"


def test_an_unplanned_marker_does_not_satisfy_a_planned_run(loader):
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a",
             "turns_emitted": 3, "tags": [], "redacted": {}, "planned": False}
    assert loader.marker_matches(prior, "https://a.test", "pk-a", "s-1") is True
    assert loader.marker_matches(prior, "https://a.test", "pk-a", "s-1", planned=True) is False


def test_reveal_hides_the_whole_of_an_overlapping_wider_span():
    import reveal
    leaf = "prefix LEFTPARTsecretRIGHTPART suffix"
    s = leaf.index("secret")
    narrow = plan.Mask("s", 0, "/m", s, s + 6, "p", "secret", "redaction", "a")
    wide = plan.Mask("s", 0, "/m", leaf.index("LEFTPART"), leaf.index(" suffix"), "gitleaks:x",
                     "secret", "gitleaks", "b")
    text, start, end = reveal.hide_others(leaf, narrow, [wide])
    shown = reveal.context_for(text, start, end, show_values=False)
    assert "LEFTPART" not in shown and "RIGHTPART" not in shown


def test_a_gitleaks_match_under_a_credential_keys_structural_name_is_placed(monkeypatch, tmp_path):
    record = {"type": "user", "message": {"content": {"token": {"id": SHAPELESS}}}}
    path = _transcript(tmp_path, [record])
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": SHAPELESS, "StartLine": 1}])
    _, masks = plan.build(path)
    placed = [m for m in masks if m.detector == "gitleaks"]
    assert placed and all(m.pointer == "/message/content/token/id" for m in placed)


# --- fifth Copilot review of PR 27 ------------------------------------------------------------

def test_writing_a_plan_never_touches_an_input_named_like_the_staging_file(tmp_path):
    path = _transcript(tmp_path, [{"x": 1}])
    decoy = tmp_path / "plan.jsonl.partial"
    decoy.write_text("an input transcript\n")
    plan.write(tmp_path / "plan.jsonl", [plan.build(path, use_gitleaks=False)])
    assert decoy.read_text() == "an input transcript\n"
    assert not list(tmp_path.glob(".plan.jsonl.*.partial"))


def test_a_local_only_plan_does_not_mark_the_load_fully_planned(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "hi")
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    written = {}
    monkeypatch.setattr(loader, "write_marker", lambda *a, **k: written.update(k))
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")
    monkeypatch.setattr(loader.presence, "session_observation_count", lambda *a, **k: 0)
    monkeypatch.setattr(loader, "build_turns", lambda msgs: [])
    import types
    fake = types.ModuleType("langfuse")
    fake.Langfuse = lambda **k: types.SimpleNamespace(flush=lambda: None, shutdown=lambda: None)
    fake.propagate_attributes = lambda **k: __import__("contextlib").nullcontext()
    monkeypatch.setitem(sys.modules, "langfuse", fake)
    assert _run(loader, monkeypatch, "--min-idle-days", "0", "--allow-plan-without-gitleaks",
                "--plan", str(out), str(path)) == 0
    assert written.get("planned") is False


def test_reveal_refuses_a_plan_cut_short_after_its_header(monkeypatch, tmp_path):
    pytest.importorskip("dotenv")
    import reveal
    path = _session(tmp_path, "token=" + FAKE)
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    out.write_text(out.read_text().splitlines()[0] + "\n")
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out)])
    assert reveal.main() == 1


# --- sixth Copilot review of PR 27 ------------------------------------------------------------

@pytest.mark.parametrize("clearance", [{}, {"patern": "email_personal"}, {"pattern": None}, "x"])
def test_a_clearance_that_names_nothing_is_rejected(tmp_path, clearance):
    path = _transcript(tmp_path, [{"message": {"content": "token=" + FAKE}}])
    with pytest.raises(plan.PlanError):
        plan.build(path, use_gitleaks=False, clearances=[clearance])


def test_the_hash_is_checked_against_the_bytes_that_are_applied(tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "token=" + FAKE}}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    parsed_earlier = path.read_bytes()
    path.write_text(json.dumps({"message": {"content": "different"}}) + "\n")
    assert plan.load(out, path, data=parsed_earlier)[1]          # the bytes that were parsed
    with pytest.raises(plan.PlanError, match="changed"):
        plan.load(out, path)                                     # the file as it is now


def test_records_split_the_same_way_in_the_loader_and_the_plan(loader, tmp_path):
    text = json.dumps({"a": "line separator"}, ensure_ascii=False) + "\n" + json.dumps({"b": 2}) + "\n"
    path = tmp_path / "s-1.jsonl"
    path.write_text(text, encoding="utf-8")
    assert loader.parse_jsonl(path.read_bytes()) == plan._records(path)


def test_reveal_hides_cleared_neighbours_too(monkeypatch, tmp_path, capsys):
    pytest.importorskip("dotenv")
    import reveal
    other = "Qw" + "7rTy3Up" * 3
    path = _session(tmp_path, "token=" + FAKE + " and " + other + " end")
    monkeypatch.setattr(inventory, "gitleaks_findings", lambda p: [
        {"RuleID": "x", "Secret": other, "StartLine": 1}])
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, clearances=[{"pattern": "gitleaks:x"}])])
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out),
                                      "--pattern", "github_pat"])
    assert reveal.main() == 0
    assert other not in capsys.readouterr().out


def test_planned_inventory_rows_keep_the_record_uuid(loader, monkeypatch, tmp_path):
    path = _session(tmp_path, "token=" + FAKE)
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    inv = tmp_path / "load-inv.jsonl"
    monkeypatch.setattr(loader, "build_turns", lambda msgs: [])
    assert _run(loader, monkeypatch, "--dry-run", "--allow-plan-without-gitleaks", "--plan", str(out),
                "--inventory", str(inv), str(path)) == 0
    rows = [json.loads(line) for line in inv.read_text().splitlines()]
    assert rows and all(r["record_uuid"] == "u-1" for r in rows if r["category"] == "secret")


# --- seventh Copilot review of PR 27 ----------------------------------------------------------

def test_a_transcript_replaced_during_the_scan_is_refused(monkeypatch, tmp_path):
    path = _transcript(tmp_path, [{"message": {"content": "token=" + FAKE}}])

    def swap(p):
        p.write_text(json.dumps({"message": {"content": "something else"}}) + "\n")
        return []
    monkeypatch.setattr(inventory, "gitleaks_findings", swap)
    with pytest.raises(plan.PlanError, match="changed while"):
        plan.build(path)


def test_reveal_shows_the_records_it_hashed(monkeypatch, tmp_path, capsys):
    pytest.importorskip("dotenv")
    import reveal
    path = _session(tmp_path, "token=" + FAKE + " end")
    out = tmp_path / "plan.jsonl"
    plan.write(out, [plan.build(path, use_gitleaks=False)])
    seen = {}
    real = reveal.show_plan
    monkeypatch.setattr(reveal, "show_plan",
                        lambda args, records, data: seen.update(n=len(records), d=data) or real(args, records, data))
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan", str(out)])
    assert reveal.main() == 0
    assert seen["d"] == path.read_bytes() and seen["n"] == 1


def test_reveal_rejects_turn_with_plan(monkeypatch, tmp_path):
    pytest.importorskip("dotenv")
    import reveal
    path = _session(tmp_path, "hi")
    monkeypatch.setattr(sys, "argv", ["reveal.py", "--transcript", str(path), "--plan",
                                      str(tmp_path / "p.jsonl"), "--turn", "1"])
    assert reveal.main() == 2
