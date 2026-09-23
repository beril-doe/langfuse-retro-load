#!/usr/bin/env python3
"""
Retroactive-load a completed Claude Code .jsonl transcript into Langfuse.

Reuses the turn-reconstruction and backdated-span logic from Langfuse's own
official Claude Code hook (langfuse_hook_official.py, vendored unmodified
alongside this file from
https://langfuse.com/integrations/developer-tools/claude-code) rather than
reimplementing it. The only things this script does differently from the
live hook:

  - reads the ENTIRE transcript file in one pass (no incremental offset /
    state-file tracking — the hook's SessionState mechanism exists to avoid
    re-processing on every Stop event; a one-shot retro-load has no "next
    time" to be incremental for)
  - no TRACE_TO_LANGFUSE gate, no stdin hook payload — session_id and
    transcript_path are given directly
  - tags every emitted trace with "retro-load" (+ whatever --tag values are
    passed) so these are filterable apart from live-captured traces
  - keeps its own idempotency marker, in ~/.retro_load_markers/ (keyed by a
    hash of the source path, NOT a sibling file next to the source -- the
    frozen workshop corpus is read-only from our account) so re-running
    against the same transcript does not duplicate traces in Langfuse, since
    Langfuse itself has no create-time dedupe

Dev/test usage (local transcripts only -- see README.md's governance section
before ever pointing this at a pod-resident transcript: retro-loading pod
.jsonl requires running THIS SCRIPT ON THE POD, never copying the raw file
off it):

    export LANGFUSE_PUBLIC_KEY=pk-lf-...
    export LANGFUSE_SECRET_KEY=sk-lf-...
    export LANGFUSE_HOST=https://us.cloud.langfuse.com
    python3 retro_load.py --dry-run /path/to/session.jsonl
    python3 retro_load.py --tag beril-hackathon-2026-05-07 /path/to/session.jsonl
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")  # must run before langfuse is imported anywhere

sys.path.insert(0, str(Path(__file__).parent))

import inventory  # noqa: E402  (after the sys.path insert, like the hook import below)
import presence  # noqa: E402
import redaction  # noqa: E402
try:
    from langfuse_hook_official import (  # noqa: E402
        build_turns,
        emit_turn,
        parse_ts,
    )
except SystemExit:
    # The vendored hook does sys.exit(0) on import if langfuse/opentelemetry aren't
    # installed (its own "fail-open" design, since it runs as a best-effort Claude Code
    # hook where silence is preferred over breaking a session). That's the wrong default
    # here: a silent 0 exit is indistinguishable from a real, successful --dry-run, and
    # would defeat build_manifest.py's return-code check on this script. Turn it loud.
    print("langfuse_hook_official.py failed to import (likely missing the langfuse/"
          "opentelemetry packages) -- treating that as a hard failure, not a silent no-op.",
          file=sys.stderr)
    sys.exit(1)


def load_all_jsonl(transcript_path: Path):
    msgs = []
    with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                msgs.append(json.loads(line))
            except Exception as e:
                print(f"  ! skipping unparseable line: {e}", file=sys.stderr)
    return msgs


MARKER_DIR = Path.home() / ".retro_load_markers"


def marker_path(transcript_path: Path) -> Path:
    # A sibling file next to the source transcript fails with PermissionError whenever
    # the source lives in a read-only/shared location we don't own (e.g. the frozen
    # workshop corpus, symlinked into another user's global_share storage). Keep markers
    # in our own home instead, keyed by a hash of the resolved source path so re-running
    # against the same file is still idempotent regardless of where it lives.
    MARKER_DIR.mkdir(exist_ok=True)
    key = hashlib.sha256(str(transcript_path).encode("utf-8")).hexdigest()
    return MARKER_DIR / f"{key}.json"


def already_loaded(transcript_path: Path) -> dict | None:
    p = marker_path(transcript_path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def valid_marker(prior) -> bool:
    """The shape write_marker() produces: an object with an integer turn count, a tag list and
    a `redacted` that is a dict (screened load) or null (--no-redact). Anything else is corrupt
    and every caller treats it as no marker."""
    return (isinstance(prior, dict) and isinstance(prior.get("turns_emitted"), int)
            and isinstance(prior.get("tags"), list)
            and (prior.get("redacted") is None or isinstance(prior.get("redacted"), dict)))


def marker_matches(prior: dict | None, host: str, public_key: str | None,
                   session_id: str, *, screened: bool = True) -> bool:
    """True only for a marker written by a load of this session into this host and project.

    A marker is keyed by the source path, so on its own it says a file was loaded somewhere,
    not that it is in the project this run targets. Markers from before the destination was
    recorded carry neither field and never match, so the project is asked instead.
    """
    # A marker that is not an object, or lacks what the early return prints, is treated as
    # absent, which sends the session to the presence check rather than raising.
    if not valid_marker(prior):
        return False
    # A --no-redact load records redacted=None. It is not a completion a screened run can
    # rely on: what went out was never screened.
    if screened and prior.get("redacted") is None:
        return False
    return bool(prior) and prior.get("host") == host and bool(public_key) \
        and prior.get("public_key") == public_key and prior.get("session_id") == session_id


def write_marker(transcript_path: Path, session_id: str, turn_count: int, tags: list[str],
                 redaction_summary: dict | None = None, *, host: str | None = None,
                 public_key: str | None = None) -> None:
    marker_path(transcript_path).write_text(
        json.dumps(
            {
                "session_id": session_id,
                # The destination, so a later run can tell "loaded here" from "loaded
                # somewhere". The public key names a project and is not a secret.
                "host": host,
                "public_key": public_key,
                "turns_emitted": turn_count,
                "tags": tags,
                # What was rewritten before this went out, by category. A marker that says
                # a file was loaded and not whether it was screened leaves the next reader
                # unable to tell a clean session from an unscreened one, and the answer
                # stops being recoverable once Langfuse has the copy: observations are
                # immutable and the only delete takes the whole trace with it.
                "redacted": redaction_summary,
                "loaded_at_utc": None,  # not stamped from the script's own clock: it says nothing
                                         # about when the underlying conversation happened, which
                                         # is the whole point of a marker for a *retroactive* load
            },
            indent=2,
        )
    )


#: Exit status for "deliberately not sent", so run_manifest.py can count it apart from a load.
EXIT_SKIPPED = 3


def last_activity(msgs) -> "datetime | None":
    """The latest timestamp on any record: when this session was last touched."""
    stamps = []
    for m in msgs:
        raw = m.get("timestamp") if isinstance(m, dict) else None
        if raw is None:
            continue
        parsed = parse_ts(m)
        if parsed is None or parsed.tzinfo is None:
            # A time with no zone can't be compared with now without guessing one.
            # One unreadable timestamp could be the newest, so the maximum of the rest is not
            # the last activity. Unknown makes the idle check skip rather than guess.
            return None
        stamps.append(parsed)
    return max(stamps) if stamps else None


def skip_reason(*, last_seen, now, min_idle_days: float, existing: int,
                allow_existing: bool) -> str | None:
    """Why this session should not be sent now, or None if it should.

    Kept free of I/O so the decision is testable on its own. `existing` is the number of
    observations the target project already holds for this session id.
    """
    if existing and not allow_existing:
        return (f"the project already holds {existing} observations for this session and "
                f"this loader has no record of completing it there: live tracing sent it, or "
                f"an earlier load failed partway. Sending would duplicate what is there; "
                f"check it first, and pass --allow-existing only to send anyway")
    if min_idle_days > 0:
        if last_seen is None:
            return ("no record carries a timestamp, so there is no way to tell whether the "
                    "session is still in use. Pass --min-idle-days 0 to send anyway")
        idle_days = (now - last_seen).total_seconds() / 86400
        if idle_days < min_idle_days:
            return (f"last activity {last_seen.isoformat()} is {idle_days:.1f} days ago, under "
                    f"--min-idle-days {min_idle_days:g}. A session still in use could be resumed "
                    f"with live tracing on and sent twice")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("transcript", type=Path, help="path to a Claude Code .jsonl transcript")
    ap.add_argument("--session-id", help="override session id (default: derived from filename stem)")
    ap.add_argument("--tag", action="append", default=[], help="extra tag to attach (repeatable)")
    ap.add_argument("--user-id", help="pseudonymous user_id for Langfuse (the pod account name, e.g. "
                                       "'mamillerpa' or 'dkishore') -- deliberately NOT a real name, since "
                                       "Langfuse's Sessions/Users views are a re-identification surface")
    ap.add_argument("--dry-run", action="store_true", help="parse and print turn summary, do not call Langfuse")
    ap.add_argument("--force", action="store_true", help="ignore an existing marker in ~/.retro_load_markers/")
    ap.add_argument("--no-redact", dest="redact", action="store_false", default=True,
                    help="send values verbatim. The default rewrites secrets and personal "
                         "details in place, one value at a time, keeping every record")
    ap.add_argument("--allow-existing", action="store_true",
                    help="send even when the target project already holds observations for "
                         "this session id. Without it the session is skipped, since Langfuse "
                         "has no create-time dedupe")
    ap.add_argument("--min-idle-days", type=float, default=7.0,
                    help="skip a session whose last record is newer than this many days, so "
                         "one still in use is not backfilled and then re-sent by live tracing "
                         "when resumed (default 7; 0 turns the check off)")
    ap.add_argument("--inventory", type=Path, default=None,
                    help="write a JSONL row per finding here: what kind, which record, "
                         "which JSON pointer. Carries no matched text and no values")
    args = ap.parse_args()

    transcript_path = args.transcript.expanduser().resolve()
    if not transcript_path.exists():
        print(f"transcript not found: {transcript_path}", file=sys.stderr)
        return 1

    session_id = args.session_id or transcript_path.stem
    tags = ["claude-code", "retro-load"] + args.tag

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    host = os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_BASE_URL") or "https://cloud.langfuse.com"

    prior = already_loaded(transcript_path)
    if marker_matches(prior, host, public_key, session_id, screened=args.redact) and not args.force:
        # This line's "already retro-loaded (N turns, tags=[...])" prefix is parsed by
        # build_manifest.py, and a dry run of a marked file is a success there, not a skip.
        print(f"already retro-loaded ({prior['turns_emitted']} turns, tags={prior['tags']}) "
              f"into {host}; pass --force to reload. marker: {marker_path(transcript_path)}")
        return 0 if args.dry_run else EXIT_SKIPPED

    msgs = load_all_jsonl(transcript_path)

    # Ask the project, not the local marker, whether this session is already there. The
    # marker cannot say which project a session went to. "Could not tell" stops the send.
    # --dry-run never calls Langfuse, so it does not ask either. --allow-existing covers a
    # project that answered "yes, it is here", never one that could not answer.
    existing = 0
    if args.dry_run:
        print("  presence not checked: --dry-run does not call Langfuse")
    elif not (public_key and secret_key):
        print("LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY not set in environment", file=sys.stderr)
        return 1
    else:
        try:
            existing = presence.session_observation_count(host, public_key, secret_key, session_id)
        except presence.PresenceError as e:
            print(f"could not check {host} for session {session_id}, not sending: {e}",
                  file=sys.stderr)
            return 1

    reason = skip_reason(last_seen=last_activity(msgs), now=datetime.now(timezone.utc),
                         min_idle_days=args.min_idle_days, existing=existing,
                         allow_existing=args.allow_existing)
    if reason and not args.dry_run:
        print(f"{transcript_path.name}: skipped, {reason}")
        return EXIT_SKIPPED
    if reason:
        # A dry run reports the decision and still prints its summary: build_manifest.py
        # reads the turn count from it and treats a nonzero exit as a failed entry.
        print(f"  would skip: {reason}")

    # Screen before assembling turns, so everything the assembler reads is already
    # rewritten and the vendored hook needs no changes. The unit left out is one value at
    # one pointer: no record, turn or session is dropped for carrying one.
    rows: list[inventory.Row] = []
    if args.redact:
        redactor = redaction.Redactor()
        msgs, rows = inventory.redact_records(msgs, redactor, subject=session_id)
    summary = {}
    for row in rows:
        summary[row.category] = summary.get(row.category, 0) + 1
    if args.inventory:
        inventory.write_inventory(rows, args.inventory)

    turns = build_turns(msgs)
    print(f"{transcript_path.name}: {len(msgs)} jsonl lines -> {len(turns)} turns")
    if args.redact:
        found = ", ".join(f"{k}={v}" for k, v in sorted(summary.items())) or "nothing"
        print(f"  screened: {found}"
              + (f"; inventory written to {args.inventory}" if args.inventory else ""))
    else:
        print("  NOT screened: --no-redact was passed, values go out verbatim")

    if args.dry_run:
        for i, t in enumerate(turns, 1):
            ts = parse_ts(t.user_msg)
            print(f"  turn {i}: {ts.isoformat() if ts else '(no timestamp)'} "
                  f"assistant_msgs={len(t.assistant_msgs)}")
        print("(dry run — nothing sent to Langfuse)")
        return 0

    from langfuse import Langfuse, propagate_attributes  # noqa: E402  (import after env check)

    langfuse = Langfuse(public_key=public_key, secret_key=secret_key, host=host)

    # emit_turn() itself sets tags=["claude-code"] via propagate_attributes; wrap in our own
    # propagate_attributes with the full tag set (and user_id, if given) so ours take effect
    # for this call stack.
    propagate_kwargs = {"tags": tags}
    if args.user_id:
        propagate_kwargs["user_id"] = args.user_id

    # emit_turn() stores str(transcript_path) verbatim into Langfuse metadata. The real
    # resolved path can carry real filesystem structure -- including, for the frozen
    # workshop corpus, another account's username where it's symlinked from -- which
    # undermines the pseudonymization this tool is otherwise careful about. Pass a
    # synthetic path built from session_id (already the trace's own identifier) instead
    # of the real one.
    safe_transcript_path = Path(f"{session_id}.jsonl")

    emitted = 0
    for i, t in enumerate(turns, 1):
        try:
            with propagate_attributes(**propagate_kwargs):
                emit_turn(langfuse, session_id, i, t, safe_transcript_path)
            emitted += 1
        except Exception as e:
            print(f"  ! turn {i} failed: {type(e).__name__}: {e}", file=sys.stderr)

    langfuse.flush()
    langfuse.shutdown()

    if emitted < len(turns):
        print(f"FAILED: only {emitted}/{len(turns)} turns emitted to {host} as session_id={session_id}; "
              f"not writing a marker so this counts as not-yet-loaded. A re-run re-emits all "
              f"turns from scratch (no per-turn state is kept, and Langfuse has no create-time "
              f"dedupe), it does not retry only the missing ones.", file=sys.stderr)
        return 1

    write_marker(transcript_path, session_id, emitted, tags,
                 redaction_summary=(summary if args.redact else None),
                 host=host, public_key=public_key)
    print(f"emitted {emitted}/{len(turns)} turns to {host} as session_id={session_id}, tags={tags}")
    print(f"marker written: {marker_path(transcript_path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
