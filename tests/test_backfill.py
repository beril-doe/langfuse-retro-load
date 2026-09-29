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
    monkeypatch.setattr(inventory, "gitleaks_version", lambda: inventory.MIN_GITLEAKS)
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


@pytest.mark.real_langfuse_check
def test_a_langfuse_outside_4x_is_a_setup_problem(monkeypatch, tmp_path):
    import langfuse
    monkeypatch.setattr(langfuse, "__version__", "5.0.0", raising=False)
    monkeypatch.setattr(backfill, "HERE", tmp_path)  # no uv.lock here
    problems = [p for p in backfill.setup_problems(skip_git=True) if "needs 4.x" in p]
    assert problems and "--locked" not in problems[0], "--locked cannot work without a lock"


@pytest.mark.parametrize("content", [
    b"\xff\xfe not utf-8",
    b'version = 1\n[[package]]\nname = "other"\n',
    b'version = 1\n[[package]]\nname = "langfuse"\nversion = "4.15.2"\n[broken\n',
    b"version = 1\npackage = 1\n",
    b'version = 1\n[[package]]\nname = "langfuse"\nversion = ""\n',
    b'version = 1\n[[package]]\nname = "langfuse"\nversion = "1"\n[[package]]\nname = "langfuse"\nversion = "2"\n',
])
@pytest.mark.real_langfuse_check
def test_an_unreadable_or_incomplete_lock_is_a_setup_problem(monkeypatch, tmp_path, content):
    """Fail closed: only a missing lock uses the 4.x fallback (second Copilot review of
    https://github.com/beril-doe/langfuse-retro-load/pull/54)."""
    (tmp_path / "uv.lock").write_bytes(content)
    monkeypatch.setattr(backfill, "HERE", tmp_path)
    monkeypatch.setattr(backfill, "find_gitleaks", lambda: None)
    problems = backfill.setup_problems(skip_git=True)
    assert any("exact langfuse pin cannot be checked" in p for p in problems)
    assert any("gitleaks is not installed" in p for p in problems), "later checks still run"


def test_the_repo_lock_pins_langfuse():
    assert backfill.locked_version("langfuse") is not None


@pytest.mark.real_langfuse_check
def test_a_langfuse_other_than_the_locked_one_is_a_setup_problem(monkeypatch):
    """The pod's .venv had langfuse 4.15.4 against a lock of 4.15.2 on 2026-09-28
    (https://github.com/beril-doe/langfuse-retro-load/issues/15)."""
    import langfuse
    locked = backfill.locked_version("langfuse")
    monkeypatch.setattr(langfuse, "__version__", locked + ".post1", raising=False)
    problems = backfill.setup_problems(skip_git=True)
    assert any(f"uv.lock pins {locked}" in p and "uv sync --locked" in p for p in problems)


@pytest.mark.real_langfuse_check
def test_the_locked_langfuse_is_not_a_setup_problem(monkeypatch):
    import langfuse
    monkeypatch.setattr(langfuse, "__version__", backfill.locked_version("langfuse"), raising=False)
    assert not any("langfuse" in p for p in backfill.setup_problems(skip_git=True))


def test_the_preview_records_its_state_and_prints_one_review_command(corpus, monkeypatch, capsys):
    """https://github.com/beril-doe/langfuse-retro-load/issues/62: one short review command
    instead of one reveal.py line per session."""
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    assert run(monkeypatch, corpus) == 0
    out = capsys.readouterr().out
    assert "1 of 2 session(s) have masks" in out
    assert "backfill.py someone --review" in out and "reveal.py --plan" not in out
    state = json.loads(backfill.state_path("someone").read_text())
    assert {s["subject"]: s["masks"] for s in state["sessions"]} == {"s-1": 1, "s-2": 0}
    assert state["load_command"].endswith(state["plan"])


def test_review_shows_only_sessions_with_masks(corpus, monkeypatch, capsys):
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    assert run(monkeypatch, corpus) == 0
    shown = []
    monkeypatch.setattr(backfill, "run_reveal", lambda cmd: shown.append(cmd) or 0)
    monkeypatch.setattr(backfill.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("paused after the last session"))
    assert run(monkeypatch, corpus, "--review") == 0
    assert len(shown) == 1 and shown[0][-2].endswith("s-1.jsonl") and shown[0][-1] == "--show-values"


def test_review_refuses_without_a_terminal(corpus, monkeypatch, capsys):
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    assert run(monkeypatch, corpus) == 0
    monkeypatch.setattr(backfill, "run_reveal", lambda cmd: pytest.fail("showed values into a pipe"))
    monkeypatch.setattr(backfill.sys.stdout, "isatty", lambda: False)
    assert run(monkeypatch, corpus, "--review") == 2
    assert "only runs in a terminal" in capsys.readouterr().err


def test_review_without_a_preview_says_what_to_run(corpus, monkeypatch, capsys):
    assert run(monkeypatch, corpus, "--review") == 2
    assert "run: backfill.py someone" in capsys.readouterr().err


def test_the_private_roster_is_the_default(monkeypatch, tmp_path):
    roster = tmp_path / "roster.json"
    roster.write_text("[]")
    monkeypatch.setattr(backfill, "DEFAULT_ROSTER", roster)
    monkeypatch.setattr(sys, "argv", ["backfill.py", "nobody", "--skip-git-check"])
    monkeypatch.setattr(backfill, "setup_problems", lambda skip_git=False: [])
    with pytest.raises(SystemExit) as exc:
        backfill.main()
    assert "nobody is not in roster.json" in str(exc.value)


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



def test_a_python_without_tomllib_refuses_rather_than_guessing(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_tomllib(name, *a, **k):
        if name == "tomllib":
            raise ImportError("no tomllib")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_tomllib)
    with pytest.raises(ValueError, match="has no tomllib"):
        backfill.locked_version("langfuse")



def test_a_dangling_lock_symlink_is_broken_not_missing(monkeypatch, tmp_path):
    (tmp_path / "uv.lock").symlink_to(tmp_path / "nowhere.lock")
    monkeypatch.setattr(backfill, "HERE", tmp_path)
    with pytest.raises(ValueError, match="could not be read"):
        backfill.locked_version("langfuse")


@pytest.mark.real_langfuse_check
def test_a_broken_lock_never_suggests_an_unlocked_sync(monkeypatch, tmp_path):
    (tmp_path / "uv.lock").write_bytes(b"[broken\n")
    monkeypatch.setattr(backfill, "HERE", tmp_path)
    monkeypatch.setitem(sys.modules, "langfuse", None)  # import langfuse now fails
    problems = backfill.setup_problems(skip_git=True)
    fixes = [p for p in problems if "no langfuse package" in p]
    assert fixes and "uv sync --locked" in fixes[0]



def test_a_lock_that_cannot_be_inspected_is_broken_not_missing(monkeypatch, tmp_path):
    (tmp_path / "uv.lock").write_text("")
    monkeypatch.setattr(backfill, "HERE", tmp_path)
    real_lstat = backfill.Path.lstat

    def denied(self):
        if self.name == "uv.lock":
            raise PermissionError(13, "Permission denied")
        return real_lstat(self)

    monkeypatch.setattr(backfill.Path, "lstat", denied)
    with pytest.raises(ValueError, match="could not be read"):
        backfill.locked_version("langfuse")



@pytest.mark.parametrize("version, ok", [((8, 19, 9), False), (None, False), ((8, 20, 0), True), ((8, 30, 1), True)])
def test_gitleaks_must_be_new_enough_for_the_allowlist(monkeypatch, version, ok):
    import inventory
    monkeypatch.setattr(backfill, "find_gitleaks", lambda: "/usr/local/bin/gitleaks")
    monkeypatch.setattr(inventory, "gitleaks_version", lambda: version)
    problems = [p for p in backfill.setup_problems(skip_git=True) if "gitleaks is" in p]
    assert (not problems) is ok



@pytest.mark.real_langfuse_check
def test_a_direct_load_refuses_a_langfuse_other_than_the_locked_one(monkeypatch, tmp_path, capsys):
    """https://github.com/beril-doe/langfuse-retro-load/issues/59"""
    pytest.importorskip("dotenv")
    import langfuse
    import retro_load
    monkeypatch.setattr(langfuse, "__version__", backfill.locked_version("langfuse") + ".post1",
                        raising=False)
    f = tmp_path / "s-1.jsonl"
    f.write_text('{"type": "user", "uuid": "u-1", "message": {"content": "hi"}}\n')
    monkeypatch.setattr(sys, "argv", ["retro_load.py", str(f), "--without-plan"])
    assert retro_load.main() == 2
    assert "uv.lock pins" in capsys.readouterr().err


@pytest.mark.real_langfuse_check
def test_a_dry_run_does_not_need_the_locked_langfuse(monkeypatch, tmp_path):
    pytest.importorskip("dotenv")
    import langfuse
    import retro_load
    monkeypatch.setattr(langfuse, "__version__", "0.0.0", raising=False)
    monkeypatch.setattr(retro_load, "MARKER_DIR", tmp_path / "markers")
    f = tmp_path / "s-1.jsonl"
    f.write_text('{"type": "user", "uuid": "u-1", "message": {"content": "hi"}}\n')
    monkeypatch.setattr(sys, "argv", ["retro_load.py", str(f), "--dry-run"])
    assert retro_load.main() == 0


def test_workshop_day_only_is_passed_to_the_load(corpus, monkeypatch, capsys):
    plan_path, command = preview_plan(monkeypatch, corpus, capsys, "--workshop-day-only")
    assert "--workshop-day-only" in command, "the printed load command keeps the filter"
    seen = {}
    monkeypatch.setattr(backfill, "run_load", lambda cmd: seen.setdefault("cmd", cmd) and 0)
    assert run(monkeypatch, corpus, "--workshop-day-only", "--load", "--plan", str(plan_path),
               "--force", "--batch-tag", "backfill-test") == 0
    cmd = seen["cmd"]
    assert cmd[cmd.index("--only-day") + 1] == "2026-05-07"


def test_without_the_flag_every_day_is_sent(corpus, monkeypatch, capsys):
    plan_path, _ = preview_plan(monkeypatch, corpus, capsys)
    seen = {}
    monkeypatch.setattr(backfill, "run_load", lambda cmd: seen.setdefault("cmd", cmd) and 0)
    assert run(monkeypatch, corpus, "--load", "--plan", str(plan_path), "--force",
               "--batch-tag", "backfill-test") == 0
    assert "--only-day" not in seen["cmd"]


def test_retro_load_only_day_keeps_that_days_turns(monkeypatch, tmp_path, capsys):
    pytest.importorskip("dotenv")
    import retro_load
    monkeypatch.setattr(retro_load, "MARKER_DIR", tmp_path / "markers")
    lines = turn("s-9", "before the workshop", "2026-05-05T17:00:00Z") + \
        turn("s-9", "on the day", "2026-05-07T17:00:00Z")
    f = tmp_path / "s-9.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in lines))
    monkeypatch.setattr(sys, "argv", ["retro_load.py", str(f), "--dry-run", "--only-day", "2026-05-07"])
    assert retro_load.main() == 0
    out = capsys.readouterr().out
    assert "1 of 2 turns dated that day" in out
    assert "turn 2: 2026-05-07" in out and "turn 1:" not in out, "turns keep their numbers"


def test_a_marker_only_completes_a_run_for_the_same_day():
    """Codex review of https://github.com/beril-doe/langfuse-retro-load/pull/64: a day-limited
    load must not satisfy a later run for another day, or for every day."""
    pytest.importorskip("dotenv")
    import retro_load
    base = {"session_id": "s", "host": "h", "public_key": "pk", "planned": True, "turns_emitted": 3,
            "tags": [], "redacted": {}}
    day = dict(base, only_day="2026-05-07")
    assert retro_load.marker_matches(day, "h", "pk", "s", planned=True, only_day="2026-05-07")
    assert not retro_load.marker_matches(day, "h", "pk", "s", planned=True, only_day=None)
    assert not retro_load.marker_matches(day, "h", "pk", "s", planned=True, only_day="2026-05-08")
    assert retro_load.marker_matches(base, "h", "pk", "s", planned=True, only_day=None), \
        "an older marker, without the field, still means every day was sent"


@pytest.mark.parametrize("bad", ["2026-5-7", "2026-02-30", "20260507"])
def test_only_day_rejects_non_canonical_dates(bad):
    """Codex review of https://github.com/beril-doe/langfuse-retro-load/pull/64: 2026-5-7
    parsed, then matched no turn, so a load sent nothing and marked the session done."""
    pytest.importorskip("dotenv")
    import argparse
    import retro_load
    with pytest.raises(argparse.ArgumentTypeError):
        retro_load._day(bad)


def test_the_workshop_preview_counts_the_turns_it_will_send(corpus, monkeypatch, capsys):
    preview_plan(monkeypatch, corpus, capsys, "--workshop-day-only")
    assert "--workshop-day-only: 2 turns dated 2026-05-07 (UTC) will be sent" in preview_plan.output


def test_dry_run_dates_turns_in_utc_so_the_count_matches_the_filter(monkeypatch, tmp_path, capsys):
    """Codex review of https://github.com/beril-doe/langfuse-retro-load/pull/64: an offset
    timestamp on the evening before is the next day in UTC, which is how --only-day decides."""
    pytest.importorskip("dotenv")
    import retro_load
    monkeypatch.setattr(retro_load, "MARKER_DIR", tmp_path / "markers")
    lines = turn("s-8", "evening, Pacific", "2026-05-06T20:00:00-07:00")
    f = tmp_path / "s-8.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in lines))
    monkeypatch.setattr(sys, "argv", ["retro_load.py", str(f), "--dry-run", "--only-day", "2026-05-07"])
    assert retro_load.main() == 0
    out = capsys.readouterr().out
    assert "1 of 1 turns dated that day" in out
    assert "turn 1: 2026-05-07T03:00:00+00:00" in out


@pytest.mark.parametrize("script", ["run_manifest", "backfill"])
def test_an_empty_day_is_refused_not_dropped(script):
    """Codex review of https://github.com/beril-doe/langfuse-retro-load/pull/64: an empty
    day from an unset variable was dropped, so a workshop-only load sent every day."""
    import argparse
    import importlib
    module = importlib.import_module(script)
    for bad in ("", "2026-5-7"):
        with pytest.raises(argparse.ArgumentTypeError):
            module._day(bad)


def test_review_of_a_mask_free_preview_still_prints_the_load_command(corpus, monkeypatch, capsys):
    """Codex review of https://github.com/beril-doe/langfuse-retro-load/pull/67."""
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    assert run(monkeypatch, corpus, "--session", "s-2") == 0
    capsys.readouterr()
    monkeypatch.setattr(backfill.sys.stdout, "isatty", lambda: True)
    assert run(monkeypatch, corpus, "--review") == 0
    out = capsys.readouterr().out
    assert "masks nothing" in out and "--load --plan" in out


def test_a_failed_state_write_keeps_the_previous_state(corpus, monkeypatch, tmp_path):
    """Codex review of https://github.com/beril-doe/langfuse-retro-load/pull/67."""
    target = backfill.state_path("someone")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"plan": "old"}\n')

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(backfill.os, "replace", boom)
    plan_path = tmp_path / "p.jsonl"
    plan_path.write_text("")
    with pytest.raises(OSError):
        backfill.write_state("someone", plan_path, [], "cmd")
    assert target.read_text() == '{"plan": "old"}\n'
    assert not list(target.parent.glob(".someone-latest.json.*.partial"))


def test_the_printed_load_command_pins_the_default_roster(corpus, monkeypatch, capsys):
    """Codex review of https://github.com/beril-doe/langfuse-retro-load/pull/67."""
    monkeypatch.setattr(backfill, "DEFAULT_ROSTER", corpus)
    monkeypatch.setattr(backfill, "run_load", lambda cmd: pytest.fail("loaded"))
    monkeypatch.setattr(sys, "argv", ["backfill.py", "someone", "--skip-git-check"])
    assert backfill.main() == 0
    command = capsys.readouterr().out.strip().splitlines()[-1]
    assert f"--people {corpus}" in command
