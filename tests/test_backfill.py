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


def preview_plan(monkeypatch, corpus, capsys, *argv):
    """Run a preview and return the plan path and the load command it printed."""
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("the preview loaded"))
    assert run(monkeypatch, corpus, *argv) == 0
    out = capsys.readouterr().out
    command = out.strip().splitlines()[-1].strip()
    plan_path = command.split("--plan ")[1].strip("'")
    preview_plan.output = out
    return Path(plan_path), command


def test_load_passes_only_the_previewed_sessions_to_run_manifest(corpus, monkeypatch, capsys):
    plan_path, _ = preview_plan(monkeypatch, corpus, capsys, "--session", "s-2")
    seen = {}

    def fake_load(cmd):
        manifest = json.loads(Path(cmd[cmd.index("--manifest") + 1]).read_text())
        seen["sessions"] = sorted(e["session_id"] for e in manifest)
        seen["user_ids"] = {e["user_id"] for e in manifest}
        seen["cmd"] = cmd
        return 0

    monkeypatch.setattr(backfill, "run_load", fake_load)
    assert run(monkeypatch, corpus, "--load", "--plan", str(plan_path), "--session", "s-2",
               "--force", "--batch-tag", "backfill-test") == 0
    assert seen["sessions"] == ["s-2"]
    assert seen["user_ids"] == {"0000-0002-1825-0097"}
    cmd = seen["cmd"]
    assert cmd[cmd.index("--batch-tag") + 1] == "backfill-test"
    assert "--force" in cmd
    assert cmd[cmd.index("--plan") + 1] == str(plan_path), "loaded with a plan nobody reviewed"
    assert cmd[cmd.index("--min-idle-days") + 1] == "1.0", "a session in use could load half done"


def test_setup_problems_stop_it_before_anything_is_read(corpus, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(backfill.shutil, "which", lambda name: None)
    monkeypatch.setattr(backfill, "LOCAL_BIN", tmp_path / "empty-bin")

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
        run(monkeypatch, corpus, "--session", "no-such-session")


def test_an_unknown_person_lists_who_is_known(corpus, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["backfill.py", "nobody", "--people", str(corpus),
                                      "--skip-git-check"])
    with pytest.raises(SystemExit, match="Known: someone"):
        backfill.main()


def test_load_without_a_reviewed_plan_is_refused(corpus, monkeypatch):
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    with pytest.raises(SystemExit):
        run(monkeypatch, corpus, "--load")


def test_the_printed_command_keeps_the_previewed_selection(corpus, monkeypatch, capsys):
    """Following the printed command must not load sessions that were not previewed."""
    _, command = preview_plan(monkeypatch, corpus, capsys, "--session", "s-2")
    assert "--session s-2" in command and "--load" in command and "--plan" in command


def test_a_plan_missing_a_session_is_refused(corpus, monkeypatch, capsys):
    plan_path, _ = preview_plan(monkeypatch, corpus, capsys, "--session", "s-2")
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    assert run(monkeypatch, corpus, "--load", "--plan", str(plan_path)) == 2
    assert "does not cover s-1" in capsys.readouterr().err


def test_a_session_that_failed_to_parse_blocks_the_load(corpus, monkeypatch, capsys):
    plan_path, _ = preview_plan(monkeypatch, corpus, capsys)
    real = backfill.build_manifest.dry_run_summary

    def s1_fails(path, event_day):
        result = real(path, event_day)
        return dict(result, failed=True) if path.stem == "s-1" else result

    monkeypatch.setattr(backfill.build_manifest, "dry_run_summary", s1_fails)
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    assert run(monkeypatch, corpus, "--load", "--plan", str(plan_path)) == 2
    assert "failed to parse" in capsys.readouterr().err


def test_a_failed_fetch_is_a_setup_problem(monkeypatch):
    """A stale origin/main can equal HEAD, so without a fetch the check proves nothing."""
    def fake_git(*a):
        if a[0] == "fetch":
            return subprocess.CompletedProcess(a, 1, stdout="", stderr="network unreachable")
        return subprocess.CompletedProcess(a, 0, stdout={"--abbrev-ref": "main"}.get(a[1], "same")
                                           + "\n", stderr="")
    monkeypatch.setattr(backfill, "git", fake_git)
    assert any("could not fetch origin" in p for p in backfill.setup_problems())


def test_a_langfuse_outside_4x_is_a_setup_problem(monkeypatch):
    import langfuse
    monkeypatch.setattr(langfuse, "__version__", "5.0.0", raising=False)
    assert any("needs 4.x" in p for p in backfill.setup_problems(skip_git=True))


def test_every_session_gets_a_review_command(corpus, monkeypatch, capsys):
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    assert run(monkeypatch, corpus) == 0
    out = capsys.readouterr().out
    reviewed = [line for line in out.splitlines() if "reveal.py --plan" in line]
    assert len(reviewed) == 2 and any("s-1.jsonl" in r for r in reviewed) \
        and any("s-2.jsonl" in r for r in reviewed)


def test_one_session_id_in_two_sources_is_refused(corpus, monkeypatch, tmp_path):
    other = tmp_path / "other" / "proj"
    other.mkdir(parents=True)
    other.joinpath("s-1.jsonl").write_text((tmp_path / "projects" / "proj" / "s-1.jsonl").read_text())
    people = json.loads(corpus.read_text())
    people[0]["sources"].append({"type": "pod-live", "find_root": str(other.parent),
                                 "consent_bin": None, "force_event_day": []})
    corpus.write_text(json.dumps(people))
    monkeypatch.setattr(backfill, "build_plan", lambda *a: pytest.fail("planned a duplicate"))
    with pytest.raises(SystemExit, match="more than one source.*drop that source"):
        run(monkeypatch, corpus)


def test_the_printed_command_pins_the_default_batch_tag(corpus, monkeypatch, capsys):
    """A load after midnight UTC must carry the tag the preview showed, not the next day's."""
    _, command = preview_plan(monkeypatch, corpus, capsys)
    assert "--batch-tag backfill-someone-" in command
    assert command.startswith(sys.executable), "the load should use the preview's Python"


def test_markers_are_found_through_a_symlinked_corpus(corpus, monkeypatch, capsys, tmp_path):
    """The pod's frozen corpus is reached through a symlink, and retro_load.py keys each
    marker by the resolved path. Looking markers up by the linked path found none of 14."""
    # The link sits partway along the path, as claudefiles does on the pod.
    real = tmp_path / "projects"
    link = tmp_path / "linked"
    link.symlink_to(tmp_path)
    people = json.loads(corpus.read_text())
    people[0]["sources"][0]["find_root"] = str(link / "projects")
    corpus.write_text(json.dumps(people))
    target = (real / "proj" / "s-1.jsonl").resolve()
    retro_load.write_marker(target, "s-1", 1, ["claude-code"], {}, host="https://h.test",
                            public_key="pk", planned=True)
    _, command = preview_plan(monkeypatch, corpus, capsys)
    assert "--force" in command
    assert "2 sessions, 2 turns, 1 already marked as sent" in preview_plan.output


def test_a_person_without_an_orcid_is_refused_before_any_scan(corpus, monkeypatch):
    people = json.loads(corpus.read_text())
    del people[0]["orcid"]
    corpus.write_text(json.dumps(people))
    monkeypatch.setattr(backfill, "discover", lambda *a: pytest.fail("scanned without an ORCID"))
    with pytest.raises(SystemExit, match="no orcid"):
        run(monkeypatch, corpus)


def test_a_malformed_orcid_is_a_clean_refusal(corpus, monkeypatch):
    people = json.loads(corpus.read_text())
    people[0]["orcid"] = "0000-0002-1825-0098"   # wrong check digit
    corpus.write_text(json.dumps(people))
    monkeypatch.setattr(backfill, "discover", lambda *a: pytest.fail("scanned with a bad ORCID"))
    with pytest.raises(SystemExit, match="not a valid ORCID"):
        run(monkeypatch, corpus)


def test_gitleaks_in_local_bin_is_found_and_put_on_path(monkeypatch, tmp_path):
    # The pod's PATH leaves out ~/.local/bin, so a load printed without a PATH prefix
    # used to refuse when the child processes could not find gitleaks.
    local = tmp_path / "bin"
    local.mkdir()
    exe = local / "gitleaks"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(backfill.shutil, "which", lambda name: None)
    monkeypatch.setattr(backfill, "LOCAL_BIN", local)
    monkeypatch.setenv("PATH", "/usr/bin")
    assert backfill.find_gitleaks() == str(exe)
    assert backfill.os.environ["PATH"].split(backfill.os.pathsep)[0] == str(local)


def test_a_non_executable_file_in_local_bin_is_not_gitleaks(monkeypatch, tmp_path):
    (tmp_path / "gitleaks").write_text("not a program")
    monkeypatch.setattr(backfill.shutil, "which", lambda name: None)
    monkeypatch.setattr(backfill, "LOCAL_BIN", tmp_path)
    monkeypatch.setenv("PATH", "/usr/bin")
    assert backfill.find_gitleaks() is None
    assert backfill.os.environ["PATH"] == "/usr/bin"


def test_a_missing_find_root_is_a_clean_error(corpus, monkeypatch, capsys):
    people = json.loads(corpus.read_text())
    people[0]["sources"][0]["find_root"] = str(corpus.parent / "no-such-dir")
    corpus.write_text(json.dumps(people))
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, corpus)
    message = str(exc.value.code)
    assert "someone's transcripts" in message and "no-such-dir" in message
    assert "nothing was sent" in message


def test_the_preview_totals_masks_by_category(corpus, monkeypatch, capsys):
    preview_plan(monkeypatch, corpus, capsys)
    out = preview_plan.output
    assert "1 value(s) to mask: person 1" in out
    assert "by pattern: email_personal 1" in out


def test_an_empty_path_keeps_the_system_default(monkeypatch, tmp_path):
    exe = tmp_path / "gitleaks"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(backfill.shutil, "which", lambda name: None)
    monkeypatch.setattr(backfill, "LOCAL_BIN", tmp_path)
    monkeypatch.setenv("PATH", "")
    backfill.find_gitleaks()
    assert backfill.os.environ["PATH"] == f"{tmp_path}{backfill.os.pathsep}{backfill.os.defpath}"


@pytest.mark.parametrize("error", [inventory.GitleaksFailed("gitleaks exited 1"),
                                   OSError(8, "Exec format error")])
def test_a_gitleaks_failure_is_a_clean_error(corpus, monkeypatch, error):
    def broken(path):
        raise error

    monkeypatch.setattr(inventory, "gitleaks_findings", broken)
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, corpus)
    assert "could not build the redaction plan" in str(exc.value.code)
    assert not list((corpus.parent / "plans").glob("*.jsonl")), "a plan was written anyway"
