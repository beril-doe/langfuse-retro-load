#!/usr/bin/env python3
"""Backfill one person's Claude Code sessions into Langfuse with one command.

Run on the BERDL pod, from this repository:

    .venv/bin/python backfill.py mamillerpa                        # preview: sends nothing
    .venv/bin/python backfill.py mamillerpa --load --plan PLAN     # load with the reviewed plan

The preview checks the setup, finds the person's transcripts from people.json, writes a
redaction plan under plans/, and prints what a load would send and the exact command to
load it. Each setup problem is reported with the command that fixes it. Review the plan
(reveal.py --plan PLAN --transcript FILE shows what will be masked), then run the printed
command. `--load` uses that plan as reviewed, never a new one, and loads through
run_manifest.py and retro_load.py, the same path as a manual load.

A long load should survive a closed browser tab, so run it in the background:

    nohup .venv/bin/python backfill.py mamillerpa --load --plan PLAN > backfill-mamillerpa.log 2>&1 &

See https://github.com/beril-doe/langfuse-retro-load/issues/38.
"""
import argparse
import collections
import datetime
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Where a user install of gitleaks lands on the pod, which is not on the pod's PATH.
LOCAL_BIN = Path.home() / ".local" / "bin"
sys.path.insert(0, str(HERE))

import build_manifest  # noqa: E402


def git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(HERE), *args], capture_output=True, text=True,
                          check=False)


def run_load(cmd: list[str]) -> int:
    """Run the load in the foreground so its progress shows as it happens."""
    return subprocess.run(cmd, check=False).returncode


def find_gitleaks() -> str | None:
    """gitleaks on PATH, or in ~/.local/bin, which the pod's PATH leaves out.

    When it is only in ~/.local/bin, that directory is put on this process's PATH, so
    inventory.gitleaks_findings(), which runs gitleaks by name while the plan is built,
    finds the same binary.
    """
    found = shutil.which("gitleaks")
    if found:
        return found
    local = LOCAL_BIN / "gitleaks"
    if local.is_file() and os.access(local, os.X_OK):
        # An unset or empty PATH means the system default, so keep that rather than
        # leaving only ~/.local/bin, which would hide find and the other system tools.
        rest = os.environ.get("PATH") or os.defpath
        os.environ["PATH"] = f"{local.parent}{os.pathsep}{rest}"
        return str(local)
    return None


def setup_problems(skip_git: bool = False) -> list[str]:
    """Everything that would make a load fail or send the wrong thing, with its fix."""
    problems = []
    if not skip_git:
        branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        fetched = git("fetch", "-q", "origin", "main")
        head = git("rev-parse", "HEAD").stdout.strip()
        main = git("rev-parse", "origin/main").stdout.strip()
        if fetched.returncode != 0:
            # A stale origin/main can equal HEAD, so without a fetch "current" is unknown.
            problems.append(f"could not fetch origin to check that main is current "
                            f"({fetched.stderr.strip()[:200] or 'git fetch failed'}). Fix: "
                            f"check the network, then git -C {HERE} pull --ff-only")
        elif branch != "main":
            problems.append(f"this checkout is on '{branch}', not main. Fix: "
                            f"git -C {HERE} switch main && git -C {HERE} pull --ff-only")
        elif head != main:
            problems.append(f"main is not current. Fix: git -C {HERE} pull --ff-only")
    try:
        import langfuse
        version = getattr(langfuse, "__version__", "")
    except ImportError:
        version = None
    if version is None:
        problems.append(f"this Python has no langfuse package. Fix: run with "
                        f"{HERE / '.venv/bin/python'}, or create it with "
                        f"'uv sync' in {HERE}")
    elif not version.startswith("4."):
        # The vendored hook reaches into SDK 4.x internals to backdate spans.
        problems.append(f"this Python has langfuse {version or '(unknown version)'}, and the "
                        f"loader needs 4.x. Fix: run with {HERE / '.venv/bin/python'}")
    if find_gitleaks() is None:
        problems.append("gitleaks is not installed, and the redaction plan needs it. Fix: "
                        "install gitleaks 8.x from https://github.com/gitleaks/gitleaks/releases "
                        "into a directory on PATH, such as ~/.local/bin")
    return problems


def find_person(people_path: Path, name: str) -> dict:
    people = json.loads(people_path.read_text())
    for person in people:
        if person["person"] == name:
            return person
    known = ", ".join(p["person"] for p in people)
    raise SystemExit(f"{name} is not in {people_path.name}. Known: {known}")


def discover(person: dict, sessions: set[str], event_day: str) -> list[tuple[dict, Path]]:
    """(manifest entry, transcript path) for each of the person's sessions."""
    found = []
    for source in person["sources"]:
        try:
            paths = build_manifest.find_jsonl_files(source["find_root"])
        except build_manifest.DiscoveryFailed as exc:
            raise SystemExit(f"could not list {person['person']}'s transcripts: {exc}. Fix the "
                             "find_root in people.json, or its permissions; nothing was sent.") from exc
        for path in paths:
            if sessions and path.stem not in sessions:
                continue
            summary = build_manifest.dry_run_summary(path, event_day)
            found.append((build_manifest.manifest_entry(person, source, path.stem, summary,
                                                        event_day), path))
    ids = [entry["session_id"] for entry, _ in found]
    repeated = sorted({sid for sid in ids if ids.count(sid) > 1})
    if repeated:
        # A plan names each transcript by session id, so two files with one id would
        # share a header and one would load with the other's masks. plan.py refuses the
        # same thing.
        where = [str(path) for entry, path in found if entry["session_id"] in repeated]
        raise SystemExit(f"session id(s) {', '.join(repeated)} appear in more than one "
                         f"source: {', '.join(where)}. Decide which copy is right, then move "
                         "the other out of its find_root or drop that source from people.json. "
                         "--session cannot pick between them: it matches by id in every source.")
    missing = sessions - set(ids)
    if missing:
        raise SystemExit(f"not found under {person['person']}'s sources: "
                         f"{', '.join(sorted(missing))}")
    return found


def build_plan(paths: list[Path], out: Path) -> None:
    import inventory
    import plan
    try:
        entries = [plan.build(path) for path in paths]
    except (plan.PlanError, inventory.GitleaksFailed, OSError) as e:
        # OSError covers a gitleaks that cannot start, such as one built for another CPU.
        raise SystemExit(f"could not build the redaction plan: {e}") from e
    out.parent.mkdir(parents=True, exist_ok=True)
    plan.write(out, entries)


def summarize_plan(plan_path: Path, paths: list[Path]) -> dict:
    """Counts from the plan file, and every session the plan does not cover."""
    import inventory
    import plan
    try:
        headers, by_subject = plan.read(plan_path)
    except (OSError, ValueError, plan.PlanError) as e:
        raise SystemExit(f"could not read the plan {plan_path}: {e}") from e
    subjects = [inventory._subject_for(p) for p in paths]
    masks = [m for s in subjects for m in by_subject.get(s, []) if not m.cleared]
    return {"uncovered": [s for s in subjects if s not in headers],
            "by_category": collections.Counter(m.category for m in masks),
            "by_pattern": collections.Counter(m.pattern for m in masks),
            "by_detector": collections.Counter(m.detector for m in masks),
            "blocking": sum(1 for m in masks if m.pointer is None),
            "total": len(masks)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("person", help="the person's name in people.json, e.g. mamillerpa")
    ap.add_argument("--load", action="store_true",
                    help="load, using the plan named by --plan")
    ap.add_argument("--plan", type=Path, default=None,
                    help="the reviewed plan a preview wrote; required with --load")
    ap.add_argument("--session", action="append", default=[],
                    help="only this session id; repeat for several")
    ap.add_argument("--force", action="store_true",
                    help="load sessions an earlier load marked as sent. A session whose "
                         "traces are still in Langfuse is skipped anyway: delete those first "
                         "with langfuse_admin.py delete, so reloading cannot duplicate them")
    ap.add_argument("--batch-tag", default=None,
                    help="default: backfill-<person>-<today's UTC date>")
    ap.add_argument("--min-idle-days", type=float, default=1.0,
                    help="skip a session written to more recently than this, so a session "
                         "still in use is not loaded half finished (default 1)")
    ap.add_argument("--event-day", default="2026-05-07")
    ap.add_argument("--people", type=Path, default=HERE / "people.json")
    ap.add_argument("--skip-git-check", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.load and args.plan is None:
        ap.error("--load needs --plan: run the preview first, review its plan, then load "
                 "with the command the preview prints")
    if args.plan is not None and not args.load:
        ap.error("--plan is only used with --load; the preview writes a new plan")

    problems = setup_problems(skip_git=args.skip_git_check)
    if problems:
        print("Not ready. Fix these, then run the same command again:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    from retro_load import already_loaded, valid_marker

    person = find_person(args.people, args.person)
    if person.get("orcid") is None:
        # Everyone is loaded under an ORCID, as BERIL's live hook does. A pod account name
        # is never used as the Langfuse user id (Mark, 2026-09-24).
        raise SystemExit(f"{args.person} has no orcid in {args.people.name}. Record a confirmed "
                         "ORCID there first; nobody is loaded under a pod account name.")
    try:
        build_manifest.langfuse_user_id(person)  # a malformed ORCID stops here, before any scan
    except ValueError as exc:
        raise SystemExit(f"{exc}. Fix it in {args.people.name}; nothing was read or sent.") from exc
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    tag = args.batch_tag or f"backfill-{args.person}-{today}"
    found = discover(person, set(args.session), args.event_day)
    if not found:
        print(f"no transcripts found for {args.person}")
        return 0
    paths = [path for _, path in found]
    if args.load:
        plan_path = args.plan.expanduser().resolve()
    else:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        plan_path = HERE / "plans" / f"{args.person}-{stamp}.jsonl"
        build_plan(paths, plan_path)
    summary = summarize_plan(plan_path, paths)

    print(f"person   : {args.person}")
    print(f"user_id  : {found[0][0]['user_id']}")
    print(f"batch tag: {tag}")
    by_source = collections.defaultdict(list)
    for entry, path in found:
        by_source[(entry["source"], entry["consent_bin"])].append((entry, path))
    for (source, consent), items in sorted(by_source.items(), key=str):
        turns = sum(e["turns_expected"] for e, _ in items)
        marked = sum(1 for _, p in items if valid_marker(already_loaded(p.resolve())))
        print(f"  {source} (consent: {consent or 'not recorded'}): {len(items)} sessions, "
              f"{turns} turns" + (f", {marked} already marked as sent" if marked else ""))
    print(f"redaction plan: {plan_path}")
    print(f"  {summary['total']} value(s) to mask" + (": " if summary["total"] else "")
          + ", ".join(f"{k} {v}" for k, v in summary["by_category"].most_common()))
    if summary["total"]:
        print("  by pattern: " + ", ".join(f"{k} {v}"
                                           for k, v in summary["by_pattern"].most_common()))
    if summary["blocking"]:
        print(f"  {summary['blocking']} gitleaks finding(s) could not be pinned to a field. "
              "The load refuses these sessions until a reviewer clears or fixes them.")
    failed = [e["session_id"] for e, _ in found if e["dry_run_failed"]]
    if failed:
        print(f"  {len(failed)} session(s) failed to parse: {', '.join(failed)}. A load "
              "refuses until they parse or are left out with --session")

    if not args.load:
        again = [a for a in sys.argv[1:]]
        if args.batch_tag is None:
            # The default tag has today's date in it; pin it so a load after midnight UTC
            # carries the tag this preview showed.
            again += ["--batch-tag", tag]
        # Markers are keyed by the resolved path, as retro_load.py writes them. The frozen
        # corpus is reached through a symlink, so the unresolved path never finds its marker.
        if "--force" not in again and any(valid_marker(already_loaded(p.resolve()))
                                          for p in paths):
            again.append("--force")
        python = sys.executable
        command = shlex.join([python, str(HERE / "backfill.py"), *again, "--load",
                              "--plan", str(plan_path)])
        print("\nNothing sent. Review what the plan will mask, one session at a time:")
        for path in paths:
            print(f"  {shlex.quote(python)} {shlex.quote(str(HERE / 'reveal.py'))} "
                  f"--plan {shlex.quote(str(plan_path))} "
                  f"--transcript {shlex.quote(str(path))}")
        print(f"Then load exactly what was previewed:\n  {command}")
        return 0

    if failed:
        print("refusing to load: some sessions failed to parse (listed above)", file=sys.stderr)
        return 2
    if summary["uncovered"]:
        print(f"refusing to load: the plan does not cover {', '.join(summary['uncovered'])}. "
              "Run the preview with the same options and load with the plan it writes.",
              file=sys.stderr)
        return 2

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump([entry for entry, _ in found], handle, indent=2)
        manifest_path = handle.name
    cmd = [sys.executable, str(HERE / "run_manifest.py"), "--manifest", manifest_path,
           "--plan", str(plan_path), "--batch-tag", tag,
           "--min-idle-days", str(args.min_idle_days)]
    if args.force:
        cmd.append("--force")
    print(f"\nloading {len(found)} sessions")
    try:
        return run_load(cmd)
    finally:
        Path(manifest_path).unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
