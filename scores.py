#!/usr/bin/env python3
"""Attach the sensitivity assessment to Langfuse as scores, during or after a load.

A score is the only part of a Langfuse trace that can be written after ingestion. Observations are
immutable, there is no trace update endpoint, and a comment cannot be deleted, so an assessment
that might later be cleared has exactly one place to live. Checked against langfuse 4.15.2:
`scores.create` takes a free-form name, a value, an optional client-supplied id, and one of
`trace_id`, `observation_id`, `session_id`, `dataset_run_id`; `scores_v3.get_many_v3` filters on
name and a value range, so "every trace with at least one secret" is one API call.

Four names, which between them answer the three questions worth browsing by:

    sensitivity.secret   numeric      count of secret findings on that trace
    sensitivity.person   numeric      count of person findings
    sensitivity.kind     categorical  the pattern behind the most severe finding
    sensitivity.review   categorical  open | cleared

Different names, so these sit alongside accuracy or any eval score on the same trace rather than
competing with it. `docs/evals.md` in turbomam/langfuse-notes already puts `passed` and
`failure_reason` on one generation.

Two limits worth knowing before planning around this.

**Media cannot be attached afterwards.** A file becomes a Langfuse Media object by being referenced
from an observation's metadata at ingestion, and there is no observation update. So an asset has to
go in during the load; what this module can do afterwards is score the trace that carries it.

**A finding on a record no turn claims is not scored**, because it never reached Langfuse. Those
are reported separately rather than folded into a trace's total, which would describe a trace as
dirtier than the thing Langfuse actually holds.

Usage:
    python3 scores.py --transcript session.jsonl --dry-run
    python3 scores.py --transcript session.jsonl --clearances cleared.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import inventory
import redaction

SCORE_SECRET = "sensitivity.secret"
SCORE_PERSON = "sensitivity.person"
SCORE_KIND = "sensitivity.kind"
SCORE_REVIEW = "sensitivity.review"

NUMERIC, CATEGORICAL = "NUMERIC", "CATEGORICAL"

#: The loader names every trace this way, so the turn number is recoverable from the trace list
#: without keeping a side table of ids that a second run would have to rebuild anyway.
TRACE_NAME_RE = re.compile(r"Claude Code - Turn (\d+)$")

#: Patterns that are reported and never rewritten, so a trace carrying only these is not a finding
#: anyone needs to browse to.
ADVISORY_PATTERNS = frozenset(
    name for name, category in redaction.CATEGORY.items() if category == redaction.ADVISORY)


@dataclass(frozen=True)
class ScorePlan:
    """One score, ready to send or to print."""
    turn: int
    trace_id: str | None
    name: str
    value: float | str
    data_type: str
    metadata: dict = field(default_factory=dict)

    def as_row(self) -> str:
        where = self.trace_id or "(no trace yet)"
        return f"turn {self.turn:>4}  {where}  {self.name}={self.value}"


def is_cleared(row: inventory.Row, clearances: list[dict]) -> bool:
    """A clearance names a subject and narrows by fingerprint, pattern or pointer. A null narrows
    nothing, so `{"subject": s, "pattern": "private_key_block"}` clears that pattern in that
    session and nothing else. Kept out of the inventory itself: the inventory records what the
    detector saw and the clearance file records what a person decided."""
    for clearance in clearances:
        if clearance.get("subject") not in (None, row.subject):
            continue
        if clearance.get("fingerprint") not in (None, row.fingerprint):
            continue
        if clearance.get("pattern") not in (None, row.pattern):
            continue
        if clearance.get("path") not in (None, row.path):
            continue
        return True
    return False


def plan_scores(findings: list[inventory.TurnFindings], trace_ids: dict[int, str],
                *, any_cleared: dict[int, bool] | None = None) -> list[ScorePlan]:
    """A score per thing worth looking at, not a score per trace.

    The first version wrote four scores on every trace, and on one real session that was 1,040
    scores for 260 traces of which almost all read `secret=0, person=0, kind=account_path`. A list
    where nearly every row says nothing is the same as no list, and at 111 sessions it is six
    figures of score objects. So a trace whose only findings are advisory gets no score at all:
    home-directory paths are in 64.5% of records and are never rewritten, so scoring them is
    scoring the background.
    """
    any_cleared = any_cleared or {}
    plans: list[ScorePlan] = []
    for turn in findings:
        if not turn.secret and not turn.person:
            continue
        trace_id = trace_ids.get(turn.turn)
        common = {"pointers": list(turn.pointers[:20])}
        if turn.secret:
            plans.append(ScorePlan(turn.turn, trace_id, SCORE_SECRET, turn.secret, NUMERIC, common))
        if turn.person:
            plans.append(ScorePlan(turn.turn, trace_id, SCORE_PERSON, turn.person, NUMERIC, common))
        if turn.worst and turn.worst not in ADVISORY_PATTERNS:
            plans.append(ScorePlan(turn.turn, trace_id, SCORE_KIND, turn.worst, CATEGORICAL, common))
        plans.append(ScorePlan(turn.turn, trace_id, SCORE_REVIEW,
                               "cleared" if any_cleared.get(turn.turn) else "open", CATEGORICAL, {}))
    return plans


def trace_ids_for_session(client, session_id: str) -> dict[int, str]:
    """Turn number to trace id, read back from Langfuse rather than remembered.

    The loader does not record which trace id a turn became, and a run that scores after the fact
    has no side table at all. `trace.list` filters on session_id, and the loader's own trace names
    carry the turn number, so this works the same whether it runs one second or one week after the
    load.
    """
    out: dict[int, str] = {}
    page = 1
    while True:
        response = client.api.trace.list(session_id=session_id, limit=100, page=page)
        traces = getattr(response, "data", []) or []
        for trace in traces:
            match = TRACE_NAME_RE.search(getattr(trace, "name", "") or "")
            if match:
                out[int(match.group(1))] = trace.id
        if len(traces) < 100:
            return out
        page += 1


def send(client, plans: list[ScorePlan]) -> tuple[int, list[str]]:
    sent, failures = 0, []
    for plan in plans:
        if not plan.trace_id:
            failures.append(f"turn {plan.turn}: no trace id, not sent")
            continue
        try:
            client.api.scores.create(
                name=plan.name, value=plan.value, trace_id=plan.trace_id,
                data_type=plan.data_type, metadata=plan.metadata or None,
            )
            sent += 1
        except Exception as exc:  # noqa: BLE001  the caller needs the tally, not a stack trace
            failures.append(f"turn {plan.turn} {plan.name}: {type(exc).__name__}: {exc}")
    return sent, failures


def findings_for(transcript: Path, clearances: list[dict], *, session_id: str | None = None):
    """Scan one transcript and group it the way Langfuse will hold it."""
    import retro_load
    from langfuse_hook_official import build_turns

    records = retro_load.load_all_jsonl(transcript)
    redactor = redaction.Redactor()
    # The subject is the session id Langfuse holds, so a clearance addressed to it matches
    # even when --session-id overrides the filename.
    _, rows = inventory.redact_records(records, redactor, subject=session_id or transcript.stem,
                                       categories=inventory.REPORT_ONLY)
    kept = [row for row in rows if not is_cleared(row, clearances)]
    cleared_rows = [row for row in rows if is_cleared(row, clearances)]
    turns = build_turns(records)
    turn_of = inventory.turn_of_record(records, turns)
    per_turn, unclaimed = inventory.by_turn(kept, turn_of)
    cleared_turns = {turn_of.get(row.record) for row in cleared_rows}
    any_cleared = {t: True for t in cleared_turns if t is not None}
    return per_turn, unclaimed, len(turns), any_cleared


def client_for(prefix: str):
    """A Langfuse client for one project, resolved the way this repository already does it.

    `langfuse_admin.load_env` reads `./.env` if there is one and `~/.env` otherwise, and
    `auth_for_project` matches a key set by its `_PROJECT_ID` and refuses to fall back to whichever
    key happens to be present. That prefix convention is why nothing needs copying: the credentials
    in `~/.env` are already in the form this tooling expects, and a copy under a second name would
    be the naming drift the credential inventory tracks, plus a second place to rotate.

    Values go from the file into this process and into the SDK. They are never printed, never
    written to another file, and never put into the parent shell's environment.
    """
    import langfuse_admin
    from langfuse import Langfuse

    # All three from the named prefix, or none. Falling back to unprefixed keys, or to a host
    # from somewhere else, could pair one project's public key with another's secret or
    # write scores to the wrong instance, which is what auth_for_project refuses to do.
    env, source = langfuse_admin.load_env()
    public = env.get(f"{prefix}_LANGFUSE_PUBLIC_KEY")
    secret = env.get(f"{prefix}_LANGFUSE_SECRET_KEY")
    host = env.get(f"{prefix}_LANGFUSE_BASE_URL") or env.get(f"{prefix}_LANGFUSE_HOST")
    if not public or not secret or not host:
        print(f"no complete {prefix}_LANGFUSE_PUBLIC_KEY / _SECRET_KEY / _BASE_URL set in "
              f"{source or '(no .env found)'}. "
              f"Prefixes present: "
              f"{', '.join(sorted({k.split('_LANGFUSE_')[0] for k in env if '_LANGFUSE_' in k}))}",
              file=sys.stderr)
        return None
    return Langfuse(public_key=public, secret_key=secret, host=host.rstrip("/"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript", type=Path, required=False)
    ap.add_argument("--session-id", default=None, help="default: the transcript's filename stem")
    ap.add_argument("--clearances", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the scores that would be created, talk to nothing")
    ap.add_argument("--limit", type=int, default=25, help="rows to print in a dry run")
    ap.add_argument("--prefix", default="BERIL",
                    help="which <PREFIX>_LANGFUSE_* credentials in .env to use. The repository "
                         "already resolves keys this way in langfuse_admin.py; nothing is copied "
                         "into a second file and no value is printed")
    ap.add_argument("--check-auth", action="store_true",
                    help="resolve credentials, name the project they open, and stop")
    args = ap.parse_args()
    if not args.check_auth and args.transcript is None:
        ap.error("--transcript is required unless --check-auth is given")

    clearances = []
    if args.clearances:
        clearances = [json.loads(line) for line in args.clearances.read_text().splitlines() if line.strip()]

    if args.check_auth:
        client = client_for(args.prefix)
        if client is None:
            return 1
        project = client.api.projects.get()
        for item in getattr(project, "data", []) or []:
            print(f"  {args.prefix} keys open project {item.name!r} (id {item.id})")
        return 0

    session_id = args.session_id or args.transcript.stem
    per_turn, unclaimed, total_turns, any_cleared = findings_for(args.transcript, clearances,
                                                                 session_id=session_id)
    print(f"{args.transcript.name}: {total_turns} turns, {len(per_turn)} with findings, "
          f"{len(unclaimed)} findings on records no turn claims (not scored)")

    if args.dry_run:
        plans = plan_scores(per_turn, {}, any_cleared=any_cleared)
        for plan in plans[:args.limit]:
            print("  " + plan.as_row())
        if len(plans) > args.limit:
            print(f"  ... {len(plans) - args.limit} more")
        print(f"(dry run: {len(plans)} scores over {len(per_turn)} traces, nothing sent)")
        return 0

    client = client_for(args.prefix)
    if client is None:
        return 1
    trace_ids = trace_ids_for_session(client, session_id)
    print(f"  matched {len(trace_ids)} traces in Langfuse for session {session_id}")
    plans = plan_scores(per_turn, trace_ids, any_cleared=any_cleared)
    sent, failures = send(client, plans)
    client.flush()
    print(f"  {sent} scores created, {len(failures)} not sent")
    for line in failures[:10]:
        print(f"  ! {line}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
