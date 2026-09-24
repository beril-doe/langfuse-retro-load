#!/usr/bin/env python3
"""Load one person's BERIL research artifacts into Langfuse, as BERIL's live hook does.

Run on the BERDL pod, from this repository:

    .venv/bin/python artifacts.py dkishore --people ~/beril-backfill-roster.json          # preview
    .venv/bin/python artifacts.py dkishore --people ~/beril-backfill-roster.json --load   # upload

An artifact is what BERIL's live hook uploads at session end: REPORT.md, RESEARCH_PLAN.md
and WORKLOG.md of the project the session worked on (ARTIFACTS in
.claude/hooks/langfuse_artifacts.py on BERIL main). The live hook reads those files from
disk; for a past session the files have moved on, so this rebuilds each one as it stood
at the end of each session by replaying the Write, Edit and MultiEdit calls recorded in the
person's transcripts, in time order. A file is left out, and the preview says so, when its
state cannot be known exactly: an edit whose old text is missing, or a shell command that
writes to it by name (see shell_writes). A script that changes a file without naming it on
its command line is not visible in the transcript, so its effect is not replayed.

Each rebuilt file is masked with the same rules as the conversation traces, and then
checked with gitleaks; a file gitleaks still flags is not uploaded. The upload matches the
live hook: one span per session and project, named "BERIL artifacts — <project>", tagged
beril, artifacts and the project, with the session id, the person's ORCID as user id, and
each file attached as text/markdown. It adds one tag, retro-load, so a batch can be found
and deleted, and it is dated at the end of the session it belongs to.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import backfill  # noqa: E402
import build_manifest  # noqa: E402

ARTIFACTS = ("REPORT.md", "RESEARCH_PLAN.md", "WORKLOG.md")
_PATH_RE = re.compile(r"projects/([^/\s\"'`]+)/(" + "|".join(re.escape(n) for n in ARTIFACTS) + r")")
_REDIRECT_RE = re.compile(r"(?<![0-9&])>>?\s*[\"']?([^\s\"';|&]+)")


def _artifact(text: str):
    """(project, name) when text names an artifact file, else None."""
    m = _PATH_RE.search(text)
    return (m.group(1), m.group(2)) if m and text.rstrip("\"'/").endswith(m.group(2)) else None


def shell_writes(command: str) -> set[tuple]:
    """Artifacts a shell command could have changed. Reading one is not a change.

    A write is a redirect into the file, tee to it, sed -i or perl -i on it, cp or mv onto
    it, rm of it, or a git checkout, restore, reset or stash that names it. A script that
    writes the file without naming it on the command line is not seen; that limit is
    stated in the preview's docstring rather than guessed at.
    """
    found = set()
    for segment in re.split(r"&&|\|\||;|\||\n", command):
        for target in _REDIRECT_RE.findall(segment):
            if (hit := _artifact(target)):
                found.add(hit)
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue
        verb, args = tokens[0], tokens[1:]
        named = {hit for t in args if (hit := _artifact(t))}
        if verb == "tee" or verb == "rm":
            found |= named
        elif verb in ("sed", "perl") and any(a.startswith("-") and "i" in a for a in args):
            found |= named
        elif verb in ("cp", "mv") and len(args) >= 2:
            dest = args[-1]
            if (hit := _artifact(dest)):
                found.add(hit)
            else:
                m = re.search(r"projects/([^/\s]+)/?$", dest)
                for src in args[:-1]:
                    if m and os.path.basename(src) in ARTIFACTS:
                        found.add((m.group(1), os.path.basename(src)))
        elif verb == "git" and args and args[0] in ("checkout", "restore", "reset", "stash"):
            found |= named
    return found
MARKER_DIR = Path.home() / ".retro_load_markers"


@dataclass
class Snapshot:
    session_id: str
    project: str
    ended: str
    files: dict = field(default_factory=dict)      # name -> text
    unknown: list = field(default_factory=list)    # names whose state could not be known


def _records(path: Path):
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            yield json.loads(line)
        except ValueError:
            continue


def events(paths: list[Path]) -> list[tuple]:
    """(timestamp, session_id, kind, detail) for every artifact change, in time order.

    kind is "op" (detail: tool name, project, file, input) or "shell" (detail: project,
    file). A tool call whose result reported an error is dropped: the file did not change.
    """
    out = []
    for path in paths:
        sid = path.stem
        errored, rows = set(), []
        for rec in _records(path):
            content = (rec.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_result" and block.get("is_error"):
                    errored.add(block.get("tool_use_id"))
                if block.get("type") != "tool_use":
                    continue
                inp = block.get("input") or {}
                name = block.get("name")
                if name in ("Write", "Edit", "MultiEdit"):
                    m = _PATH_RE.search(inp.get("file_path") or "")
                    if m and (inp.get("file_path") or "").endswith(m.group(2)):
                        rows.append((rec.get("timestamp") or "", sid, "op",
                                     (name, m.group(1), m.group(2), inp), block.get("id")))
                elif name == "Bash":
                    for project, fname in sorted(shell_writes(inp.get("command") or "")):
                        rows.append((rec.get("timestamp") or "", sid, "shell",
                                     (project, fname), block.get("id")))
        out += [(ts, sid, kind, detail) for ts, sid, kind, detail, tid in rows if tid not in errored]
    return sorted(out, key=lambda r: r[0])


def apply(state: str | None, name: str, inp: dict) -> str | None:
    """The file after one Write, Edit or MultiEdit, or None when that cannot be known."""
    if name == "Write":
        content = inp.get("content")
        return content if isinstance(content, str) else None
    if state is None:
        return None
    edits = inp.get("edits") if name == "MultiEdit" else [inp]
    for edit in edits or []:
        old, new = edit.get("old_string"), edit.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str) or not old or old not in state:
            return None
        state = state.replace(old, new) if edit.get("replace_all") else state.replace(old, new, 1)
    return state


def session_ends(paths: list[Path]) -> dict:
    """The last record timestamp in each session."""
    ends = {}
    for path in paths:
        stamps = [rec.get("timestamp") for rec in _records(path) if rec.get("timestamp")]
        if stamps:
            ends[path.stem] = max(stamps)
    return ends


def snapshots(paths: list[Path]) -> list[Snapshot]:
    """For each session that changed a project's artifacts, the project's files at its end.

    The live hook uploads every artifact the project has at session end, touched in that
    session or not, so a snapshot carries the current state of all three names.
    """
    state: dict[tuple, str | None] = {}
    touched = collections.defaultdict(set)          # session -> projects
    order = []
    snap_state: dict[tuple, dict] = {}
    for _ts, sid, kind, detail in events(paths):
        if kind == "op":
            name, project, fname, inp = detail
            state[(project, fname)] = apply(state.get((project, fname)), name, inp)
        else:
            project, fname = detail
            state[(project, fname)] = None
        if project not in touched[sid]:
            touched[sid].add(project)
            order.append((sid, project))
        # Take the snapshot as the session's last event for the project goes by.
        snap_state[(sid, project)] = {f: state.get((project, f), "__absent__") for f in ARTIFACTS}
    ends = session_ends(paths)
    result = []
    for sid, project in order:
        snap = Snapshot(session_id=sid, project=project, ended=ends.get(sid, ""))
        for fname, value in snap_state[(sid, project)].items():
            if value == "__absent__":
                continue
            if value is None:
                snap.unknown.append(fname)
            else:
                snap.files[fname] = value
        result.append(snap)
    return result


class Refused(Exception):
    """A file that must not be uploaded, with the reason."""


def mask(text: str, name: str) -> tuple[str, int]:
    """The text with secrets and personal details replaced, and the count replaced.

    gitleaks then reads the masked text; if it still finds anything, the file is refused.
    """
    import inventory
    import plan
    import redaction
    clean, findings = redaction.redact(text, categories=plan.ACTIONABLE)
    replaced = sum(1 for f in findings if f.category in plan.ACTIONABLE)
    with tempfile.NamedTemporaryFile("w", suffix="-" + name, delete=False, encoding="utf-8") as h:
        h.write(clean)
        tmp = Path(h.name)
    try:
        left = inventory.gitleaks_findings(tmp)
    finally:
        tmp.unlink(missing_ok=True)
    if left is None:
        raise Refused("gitleaks is not installed")
    if left:
        raise Refused(f"gitleaks still finds {len(left)} value(s) after masking")
    return clean, replaced


def marker(host: str, session_id: str, project: str) -> Path:
    key = hashlib.sha256(f"{host}|{session_id}|{project}".encode()).hexdigest()[:24]
    return MARKER_DIR / f"artifacts-{key}.json"


def upload(langfuse, snap: Snapshot, masked: dict, user_id: str) -> None:
    """One span, as the live hook writes it, dated at the end of the session."""
    from langfuse import propagate_attributes
    from langfuse.media import LangfuseMedia
    import langfuse_hook_official as hook
    media = {name: LangfuseMedia(content_bytes=text.encode("utf-8"), content_type="text/markdown")
             for name, text in masked.items()}
    ended = hook.parse_ts({"timestamp": snap.ended}) if snap.ended else None
    with propagate_attributes(session_id=snap.session_id, user_id=user_id,
                              tags=["beril", "artifacts", snap.project, "retro-load"]):
        span = hook._start_backdated(langfuse, name=f"BERIL artifacts — {snap.project}",
                                     as_type="span", start_time=ended,
                                     input={"project": snap.project, "files": sorted(masked)},
                                     metadata=media)
        span.end(end_time=hook._to_ns(ended) if ended else None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("person")
    ap.add_argument("--people", type=Path, default=HERE / "people.json")
    ap.add_argument("--load", action="store_true", help="upload after the preview")
    ap.add_argument("--force", action="store_true", help="upload snapshots already marked as sent")
    ap.add_argument("--skip-git-check", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    problems = backfill.setup_problems(skip_git=args.skip_git_check)
    if problems:
        print("Not ready. Fix these, then run the same command again:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    person = backfill.find_person(args.people, args.person)
    if person.get("orcid") is None:
        raise SystemExit(f"{args.person} has no orcid in {args.people.name}; nobody is loaded "
                         "under a pod account name.")
    try:
        user_id = build_manifest.langfuse_user_id(person)
    except ValueError as exc:
        raise SystemExit(f"{exc}. Fix it in {args.people.name}.") from exc

    paths = [p for source in person["sources"]
             for p in build_manifest.find_jsonl_files(source["find_root"])]
    snaps = snapshots(paths)
    print(f"person   : {args.person}\nuser_id  : {user_id}\nsessions : {len(paths)} scanned, "
          f"{len({s.session_id for s in snaps})} changed a BERIL project's artifacts")
    ready = []
    for snap in snaps:
        masked, notes = {}, []
        for name, text in sorted(snap.files.items()):
            try:
                masked[name], n = mask(text, name)
                notes.append(f"{name} ({len(text)} chars, {n} masked)")
            except Refused as exc:
                notes.append(f"{name} REFUSED: {exc}")
        notes += [f"{name} UNKNOWN: changed in a way the transcript cannot replay"
                  for name in snap.unknown]
        print(f"  {snap.session_id[:8]} {snap.project}: " + "; ".join(notes))
        if masked:
            ready.append((snap, masked))
    print(f"{len(ready)} snapshot(s) ready, {sum(len(m) for _, m in ready)} file(s)")
    if not args.load:
        print("\nNothing sent. To upload: repeat this command with --load")
        return 0

    import retro_load
    public, secret = os.environ.get("LANGFUSE_PUBLIC_KEY"), os.environ.get("LANGFUSE_SECRET_KEY")
    if not (public and secret):
        raise SystemExit("LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY are not set (see .env)")
    host = retro_load.resolve_destination()
    langfuse = retro_load.make_client(public, secret, host)
    MARKER_DIR.mkdir(exist_ok=True)
    sent = skipped = 0
    for snap, masked in ready:
        mark = marker(host, snap.session_id, snap.project)
        if mark.exists() and not args.force:
            skipped += 1
            print(f"  {snap.session_id[:8]} {snap.project}: already sent, skipped")
            continue
        upload(langfuse, snap, masked, user_id)
        mark.write_text(json.dumps({"session_id": snap.session_id, "project": snap.project,
                                    "host": host, "files": sorted(masked),
                                    "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}))
        sent += 1
        print(f"  {snap.session_id[:8]} {snap.project}: sent {len(masked)} file(s)")
    langfuse.flush()
    langfuse.shutdown()
    print(f"sent {sent}, skipped {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
