#!/usr/bin/env python3
"""Backfill one person's Claude Code sessions into Langfuse with one command.

Run on the BERDL pod, from this repository:

    .venv/bin/python backfill.py mamillerpa            # preview: sends nothing
    .venv/bin/python backfill.py mamillerpa --load     # the same, then loads

The preview checks the setup, finds the person's transcripts from people.json, builds
the redaction plan, and prints what a load would send. Each setup problem is reported
with the command that fixes it. `--load` repeats all of that and then loads through
run_manifest.py and retro_load.py, the same path as a manual load.

A long load should survive a closed browser tab, so run it in the background:

    nohup .venv/bin/python backfill.py mamillerpa --load > backfill-mamillerpa.log 2>&1 &

See https://github.com/beril-doe/langfuse-retro-load/issues/38.
"""
import argparse
import collections
import datetime
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_manifest  # noqa: E402


def git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(HERE), *args], capture_output=True, text=True,
                          check=False)


def run_load(cmd: list[str]) -> int:
    """Run the load in the foreground so its progress shows as it happens."""
    return subprocess.run(cmd, check=False).returncode


def setup_problems(skip_git: bool = False) -> list[str]:
    """Everything that would make a load fail or send the wrong thing, with its fix."""
    problems = []
    if not skip_git:
        branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        git("fetch", "-q", "origin", "main")
        head = git("rev-parse", "HEAD").stdout.strip()
        main = git("rev-parse", "origin/main").stdout.strip()
        if branch != "main":
            problems.append(f"this checkout is on '{branch}', not main. Fix: "
                            f"git -C {HERE} switch main && git -C {HERE} pull --ff-only")
        elif head != main:
            problems.append(f"main is not current. Fix: git -C {HERE} pull --ff-only")
    try:
        import langfuse  # noqa: F401
    except ImportError:
        problems.append(f"this Python has no langfuse package. Fix: run with "
                        f"{HERE / '.venv/bin/python'}, or create it with "
                        f"'uv sync' in {HERE}")
    if shutil.which("gitleaks") is None:
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
        for path in build_manifest.find_jsonl_files(source["find_root"]):
            if sessions and path.stem not in sessions:
                continue
            summary = build_manifest.dry_run_summary(path, event_day)
            found.append((build_manifest.manifest_entry(person, source, path.stem, summary,
                                                        event_day), path))
    missing = sessions - {entry["session_id"] for entry, _ in found}
    if missing:
        raise SystemExit(f"not found under {person['person']}'s sources: "
                         f"{', '.join(sorted(missing))}")
    return found


def build_plan(paths: list[Path], out: Path) -> dict:
    """Write the redaction plan and return a summary of it."""
    import plan
    try:
        entries = [plan.build(path) for path in paths]
    except plan.PlanError as e:
        raise SystemExit(f"could not build the redaction plan: {e}") from e
    out.parent.mkdir(parents=True, exist_ok=True)
    plan.write(out, entries)
    masks = [m for _, ms in entries for m in ms if not m.cleared]
    return {"by_pattern": collections.Counter(m.pattern for m in masks),
            "by_detector": collections.Counter(m.detector for m in masks),
            "blocking": sum(1 for m in masks if m.pointer is None),
            "total": len(masks)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("person", help="the person's name in people.json, e.g. mamillerpa")
    ap.add_argument("--load", action="store_true", help="load after the preview")
    ap.add_argument("--session", action="append", default=[],
                    help="only this session id; repeat for several")
    ap.add_argument("--force", action="store_true",
                    help="reload sessions that an earlier load marked as sent")
    ap.add_argument("--batch-tag", default=None,
                    help="default: backfill-<person>-<today's UTC date>")
    ap.add_argument("--min-idle-days", type=float, default=1.0,
                    help="skip a session written to more recently than this, so a session "
                         "still in use is not loaded half finished (default 1)")
    ap.add_argument("--event-day", default="2026-05-07")
    ap.add_argument("--people", type=Path, default=HERE / "people.json")
    ap.add_argument("--skip-git-check", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    problems = setup_problems(skip_git=args.skip_git_check)
    if problems:
        print("Not ready. Fix these, then run the same command again:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    from retro_load import already_loaded, valid_marker

    person = find_person(args.people, args.person)
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    tag = args.batch_tag or f"backfill-{args.person}-{today}"
    found = discover(person, set(args.session), args.event_day)
    if not found:
        print(f"no transcripts found for {args.person}")
        return 0
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    plan_path = HERE / "plans" / f"{args.person}-{stamp}.jsonl"
    summary = build_plan([path for _, path in found], plan_path)

    print(f"person   : {args.person}")
    print(f"user_id  : {found[0][0]['user_id']}")
    print(f"batch tag: {tag}")
    by_source = collections.defaultdict(list)
    for entry, path in found:
        by_source[(entry["source"], entry["consent_bin"])].append((entry, path))
    for (source, consent), items in sorted(by_source.items(), key=str):
        turns = sum(e["turns_expected"] for e, _ in items)
        marked = sum(1 for _, p in items if valid_marker(already_loaded(p)))
        print(f"  {source} (consent: {consent or 'not recorded'}): {len(items)} sessions, "
              f"{turns} turns" + (f", {marked} already marked as sent" if marked else ""))
    print(f"redaction plan: {plan_path}")
    print(f"  {summary['total']} value(s) to mask" + (": " if summary["total"] else "")
          + ", ".join(f"{k} {v}" for k, v in summary["by_pattern"].most_common()))
    if summary["blocking"]:
        print(f"  {summary['blocking']} gitleaks finding(s) could not be pinned to a field. "
              "The load refuses these sessions until a reviewer clears or fixes them.")
    failed = [e["session_id"] for e, _ in found if e["dry_run_failed"]]
    if failed:
        print(f"  {len(failed)} session(s) failed to parse: {', '.join(failed)}")

    if not args.load:
        print(f"\nNothing sent. To load: .venv/bin/python backfill.py {args.person} --load"
              + (" --force" if any(valid_marker(already_loaded(p)) for _, p in found) else ""))
        return 0

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
