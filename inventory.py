#!/usr/bin/env python3
"""Write down what is in a transcript or an asset, one row per finding, before any of it
is uploaded.

The scanner proposed in https://github.com/beril-doe/langfuse-retro-load/pull/6 answers
one question per file: does this transcript contain anything, yes or no, as an exit
status. That is the wrong shape. A session is one Langfuse
trace made of many observations, a finding is in one value inside one of them, and an
answer that only names the file leaves a loader with two options, send the whole thing or
send none of it. Langfuse observations are immutable once ingested and the only delete
removes an entire trace, so "send none of it" is the one that actually gets used, and a
session's research is dropped because a tool result forty turns in printed an environment
variable. See https://github.com/beril-doe/langfuse-retro-load/issues/11 and
https://github.com/beril-doe/langfuse-retro-load/issues/7.

So each row here is addressed precisely enough to act on without touching anything else:

    subject      the session id, or an asset's path relative to the snapshot root
    record       0-based line in the .jsonl, which is also the gitleaks line number - 1
    record_uuid  the transcript record's own uuid, when it has one
    path         RFC 6901 JSON pointer to the exact value inside that record

A loader holding these rows can rewrite one value, drop one observation, or drop one
record, and still emit the turn and the session around it.

**No row carries matched text, a value, an absolute path, or the fingerprint key.** A
fingerprint is HMAC-SHA256 under a key that is random per run and never stored, truncated
to eight characters, so equal fingerprints mean the same value appeared twice and nothing
else. That is what makes a review artifact readable by a colleague: "this one token is in
41 records" is the fact a reviewer needs, and quoting the token to say it is the problem
being avoided. It also means the inventory needs no special file permissions, unlike that
pull request's `--detail` output, whose whole purpose is to hold the material being
looked for.

Two detectors, union, per https://github.com/beril-doe/langfuse-retro-load/issues/10:

    redaction.py   keyword and shape anchored, plus key-name evidence a text scanner
                   cannot have. Catches a six-character token under a credential key.
    gitleaks       about 150 provider rules, entropy gated near 3.5. Catches shapes
                   nobody here wrote a rule for, misses the low-entropy ones: the three
                   real tokens in the September corpus scored 4.351, 3.531 and 3.328.

They fail in opposite directions, so neither substitutes for the other. gitleaks rows are
addressed by record only, because it reports a line and a file, not a JSON pointer, and
they are fingerprinted under the same key, which makes them comparable with the
whole-value findings and not with the span-widened ones (see `gitleaks_rows`).

Usage:
    python3 inventory.py --out inv.jsonl --report report.md session.jsonl
    python3 inventory.py --out inv.jsonl --asset-root projects/ projects/**/*.md
    python3 inventory.py --out inv.jsonl --no-gitleaks session.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

import redaction

#: Report everything, rewrite nothing. An inventory pass never produces redacted text, so
#: passing any category here would only cost the work of building strings nobody reads.
REPORT_ONLY: frozenset[str] = frozenset()

#: Read an asset this large at most. Langfuse media uploads are bounded well below this,
#: and a scan that hangs on a multi-gigabyte parquet file is a scan that gets skipped.
MAX_ASSET_BYTES = 32 * 1024 * 1024

#: gitleaks rule ids are its own vocabulary. Everything it reports is credential material
#: by construction, so the category is fixed rather than mapped rule by rule.
GITLEAKS_PREFIX = "gitleaks:"


@dataclass(frozen=True)
class Row:
    """One finding, located well enough to exclude on its own."""
    subject: str
    kind: str                    # "transcript" or "asset"
    record: int | None
    record_uuid: str | None
    path: str                    # JSON pointer, or "" for a whole-file finding
    detector: str                # "redaction" or "gitleaks"
    pattern: str
    category: str
    fingerprint: str
    length: int
    masked: bool
    whole_value: bool

    def as_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def _subject_for(path: Path) -> str:
    """A transcript's session id, which is its filename stem.

    Deliberately not the path. `retro_load.py` already refuses to put a real filesystem
    path into Langfuse metadata, because the frozen corpus is symlinked out of another
    account's storage and the path carries their username. An inventory is read by more
    people than that metadata is, so it gets the same treatment.
    """
    return path.stem


def record_numbers(path: Path) -> dict[int, int]:
    """0-based file line to record number, for every line that parses.

    A record number is the position among parsed records, which is how retro_load.py's
    load_all_jsonl(), redact_records() and reveal.py count. Blank and unparseable lines have
    no record number: the loader never sends them.
    """
    out, index = {}, 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
            except ValueError:  # noqa: S112 -- the loader skips these lines too
                continue
            out[line_no] = index
            index += 1
    return out


def scan_transcript(path: Path, redactor: redaction.Redactor) -> list[Row]:
    """Every finding in one .jsonl transcript, addressed by record and JSON pointer.

    Parses each line rather than scanning the raw text, which is what gives the pointer
    and what bounds the damage a value with no terminator can do. A line that will not
    parse is still scanned, as one string, because an unparseable line is exactly where
    something unexpected ended up. Such a row has no record number, since the loader never
    sends that line; `record` counts parsed records only, the same as the loader.
    """
    subject = _subject_for(path)
    rows: list[Row] = []
    index = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                _, found = redaction.redact_tree(line, categories=REPORT_ONLY,
                                                 key=redactor.key)
                rows.extend(_rows_from(found, subject, "transcript", None, None))
                continue
            uuid = record.get("uuid") if isinstance(record, dict) else None
            # The loader's own policy, so the report says what a load would screen.
            _, found = redaction.redact_tree(record, categories=REPORT_ONLY,
                                             key=redactor.key, skip_keys=STRUCTURAL_KEYS,
                                             payload_keys=PAYLOAD_KEYS,
            payload_by_type=PAYLOAD_BY_TYPE)
            rows.extend(_rows_from(found, subject, "transcript", index,
                                   uuid if isinstance(uuid, str) else None))
            index += 1
    return rows


#: Pattern name for an asset over MAX_ASSET_BYTES, which was never read.
UNSCANNED_TOO_LARGE = "unscanned_too_large"

#: Pattern name for a .json or .ipynb asset that would not parse.
UNSCANNED_UNPARSEABLE = "unscanned_unparseable"


class GitleaksFailed(RuntimeError):
    """gitleaks ran and failed, so its half of the union is missing, not empty."""


def scan_asset(path: Path, redactor: redaction.Redactor, *, root: Path | None = None) -> list[Row]:
    """Every finding in one file being uploaded as an asset.

    Assets are the other half of what gets published: the research-artifact backfill
    attaches project files to a session as Langfuse Media
    (https://github.com/beril-doe/BERIL-research-observatory/issues/424), and a snapshot
    of a project directory is exactly where a notebook with a live token in a cell output
    ends up (https://github.com/beril-doe/BERIL-research-observatory/issues/382). Rows
    carry the path relative to the snapshot root so one file can be left out of a snapshot
    without dropping the snapshot.

    A `.ipynb` or a `.json` is parsed and walked like a transcript record, so a token in a
    cell output is addressed by pointer. Anything else is read as one string.
    """
    relative = str(path.relative_to(root)) if root else path.name
    size = path.stat().st_size
    if size > MAX_ASSET_BYTES:
        # Not scanned is not clean. One blocking row, in the secret category so every caller
        # that leaves out secret-bearing files leaves this one out too, named for the reason.
        return [Row(subject=relative, kind="asset", record=None, record_uuid=None, path="",
                    detector="redaction", pattern=UNSCANNED_TOO_LARGE,
                    category=redaction.SECRET, fingerprint="", length=size, masked=False,
                    whole_value=True)]
    text = path.read_text(encoding="utf-8", errors="replace")
    blocked: list[Row] = []
    if path.suffix in {".json", ".ipynb"}:
        try:
            parsed = json.loads(text)
        except ValueError:
            # Scanned as text, but without the key-based rule a short value under `TOKEN`
            # goes unseen, so the file is also blocked rather than reported clean.
            parsed = text
            blocked.append(Row(subject=relative, kind="asset", record=None, record_uuid=None,
                               path="", detector="redaction", pattern=UNSCANNED_UNPARSEABLE,
                               category=redaction.SECRET, fingerprint="", length=size,
                               masked=False, whole_value=True))
    else:
        parsed = text
    _, found = redaction.redact_tree(parsed, categories=REPORT_ONLY, key=redactor.key)
    rows = blocked + _rows_from(found, relative, "asset", None, None)
    if isinstance(parsed, str):
        rows += _keyed_lines(parsed, relative, redactor.key)
    return rows


#: `KEY=value`, `export KEY=value` or `key: value` on a line of its own, as in a .env or YAML
#: file. Only used to give the key-name rule its key, which a flat string scan never has.
_KEYED_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(\S.*?)\s*$")


def _keyed_lines(text: str, relative: str, key: bytes) -> list[Row]:
    """Findings from the key-name rule on each `KEY=value` line of a text asset.

    `KBASE_AUTH_TOKEN=s3cret` is too short for the flat keyed pattern and too low in entropy
    for gitleaks; under its own key name it is the credential. Addressed as `/line/N`.
    """
    rows = []
    for number, line in enumerate(text.splitlines()):
        match = _KEYED_LINE.match(line)
        if not match or not redaction.is_credential_key(match.group(1)):
            continue
        value = match.group(2).strip("\"'")
        _, found = redaction.redact_value(value, key_name=match.group(1),
                                          categories=REPORT_ONLY, key=key)
        rows += [Row(subject=relative, kind="asset", record=None, record_uuid=None,
                     path=f"/line/{number}", detector="redaction", pattern=f.pattern,
                     category=f.category, fingerprint=f.fingerprint, length=f.length,
                     masked=f.masked, whole_value=f.start == 0 and f.end == len(value))
                 for f in found if f.pattern == redaction.CREDENTIAL_KEY]
    return rows


def _rows_from(found: list[redaction.Located], subject: str, kind: str,
               record: int | None, record_uuid: str | None) -> list[Row]:
    return [
        Row(subject=subject, kind=kind, record=record, record_uuid=record_uuid,
            path=located.path, detector="redaction", pattern=located.finding.pattern,
            category=located.finding.category, fingerprint=located.finding.fingerprint,
            length=located.finding.length, masked=located.finding.masked,
            whole_value=located.whole_value)
        for located in found
    ]


def gitleaks_findings(path: Path) -> list[dict] | None:
    """gitleaks' raw findings for one file, or None when gitleaks is not installed.

    Each finding holds the matched text under "Secret". Callers keep it in memory only for as
    long as it takes to locate or fingerprint it, and never write it anywhere. A gitleaks run
    that fails, or reports findings it doesn't list, raises GitleaksFailed.
    """
    try:
        result = subprocess.run(
            # --exit-code 2 separates "found something" from "failed": gitleaks exits 1
            # for both by default, and a failure read as no output looks clean.
            ["gitleaks", "detect", "--no-git", "--no-banner", "--exit-code", "2",
             "--report-format", "json", "--report-path", "-", "--source", str(path)],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return None
    if result.returncode not in (0, 2):
        raise GitleaksFailed(f"gitleaks exited {result.returncode} on {path.name}; "
                             f"its findings for this file are missing, not empty")
    if not result.stdout.strip():
        if result.returncode == 2:
            raise GitleaksFailed(f"gitleaks reported findings on {path.name} but wrote no "
                                 f"report; its findings for this file are missing")
        return []
    try:
        findings = json.loads(result.stdout)
    except ValueError as exc:
        raise GitleaksFailed(f"gitleaks wrote an unreadable report for {path.name}; its "
                             f"findings for this file are missing") from exc
    if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
        raise GitleaksFailed(f"gitleaks wrote a report for {path.name} that is not a list "
                             f"of findings")
    if result.returncode == 2 and not findings:
        raise GitleaksFailed(f"gitleaks reported findings on {path.name} but listed none")
    return findings


def gitleaks_rows(paths: list[Path], *, kind: str, key: bytes,
                  root: Path | None = None) -> list[Row]:
    """gitleaks' findings for the same files, as rows in the same inventory.

    Returns an empty list when gitleaks is not installed rather than failing: the union is
    better than either detector alone, and a machine without it should still produce an
    inventory, with the report saying which detectors ran. Addressed by record only, since
    gitleaks reports a line rather than a pointer, and a .jsonl line is a record.
    """
    rows: list[Row] = []
    for path in paths:
        findings = gitleaks_findings(path)
        if findings is None:
            return []
        if not findings:
            continue
        subject = _subject_for(path) if kind == "transcript" else (
            str(path.relative_to(root)) if root else path.name)
        # gitleaks reports file lines; a transcript row's record is its parsed-record number.
        numbers = record_numbers(path) if kind == "transcript" else {}
        for finding in findings:
            match = str(finding.get("Secret") or finding.get("Match") or "")
            line = finding.get("StartLine")
            rows.append(Row(
                subject=subject, kind=kind,
                # gitleaks counts lines from 1 and a .jsonl record is a line, so this is
                # the same `record` the pointer-addressed rows use.
                record=(numbers.get(line - 1) if kind == "transcript" else line - 1)
                if isinstance(line, int) and line > 0 else None,
                record_uuid=None, path="", detector="gitleaks",
                pattern=GITLEAKS_PREFIX + str(finding.get("RuleID", "unknown")),
                category=redaction.SECRET,
                # Fingerprinted under the same run key as everything else. That makes
                # the two detectors comparable only where they saw the same characters:
                # a whole-value finding fingerprints the value, so it matches gitleaks,
                # while `keyed_value` fingerprints the span it widened to, which includes
                # the `NAME=` in front, so the same token reads as two rows. Measured on
                # the fixture transcript: two tokens, four rows, two fingerprints each.
                # Normalising the prefix away would be the boundary-guessing this module
                # exists to stop doing, so the report counts distinct values per detector
                # rather than pretending to one number. It costs holding the value in
                # memory for one call, which `detect()` already does for every match, and
                # the value is never written: not to the inventory, not to the report, and
                # not to stderr, which is why the parse failure above is silent rather
                # than raising a JSONDecodeError with a slice of the document in it.
                fingerprint=redaction.fingerprint(match, key), length=len(match),
                masked=False, whole_value=False))
    return rows


def write_inventory(rows: list[Row], out: Path) -> None:
    with out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(row.as_json() + "\n")


def read_inventory(path: Path) -> list[Row]:
    return [Row(**json.loads(line)) for line in path.read_text().splitlines() if line.strip()]


def excluded_paths(rows: list[Row], *, categories: frozenset[str]) -> dict[tuple[str, int | None], set[str]]:
    """The JSON pointers a loader should act on, grouped by subject and record.

    The unit is the pointer, not the record and not the subject, which is the whole point
    of the inventory. A caller that wants to drop a whole record can ask this for the
    record's key and act on a non-empty set; a caller that wants to rewrite one value has
    the pointer to rewrite.
    """
    out: dict[tuple[str, int | None], set[str]] = defaultdict(set)
    for row in rows:
        if row.category in categories:
            out[(row.subject, row.record)].add(row.path)
    return dict(out)


def report(rows: list[Row], *, detectors: list[str]) -> str:
    """A rollup a person reads, in the order a person asks the questions.

    Counts of distinct fingerprints, not just of findings: one credential repeated in 41
    records is one thing to rotate, and 41 unrelated findings is a different afternoon.
    """
    lines = ["# Sensitivity inventory", ""]
    lines.append(f"Detectors run: {', '.join(detectors) if detectors else 'none'}.")
    lines.append(f"{len(rows)} finding(s) across {len({r.subject for r in rows})} subject(s).")
    lines.append("")

    by_category: Counter[str] = Counter(row.category for row in rows)
    lines.append("## By category")
    lines.append("")
    lines.append("| category | findings | distinct values |")
    lines.append("|---|---|---|")
    for category, count in sorted(by_category.items()):
        distinct = len({row.fingerprint for row in rows
                        if row.category == category and row.fingerprint})
        lines.append(f"| {category} | {count} | {distinct} |")
    lines.append("")

    lines.append("## By pattern")
    lines.append("")
    lines.append("| pattern | detector | findings | distinct values |")
    lines.append("|---|---|---|---|")
    by_pattern: Counter[tuple[str, str]] = Counter((row.pattern, row.detector) for row in rows)
    for (pattern, detector), count in sorted(by_pattern.items()):
        distinct = len({row.fingerprint for row in rows
                        if row.pattern == pattern and row.fingerprint})
        lines.append(f"| {pattern} | {detector} | {count} | {distinct} |")
    lines.append("")

    lines.append("## By subject")
    lines.append("")
    lines.append("| subject | kind | records touched | findings | secret | person | advisory |")
    lines.append("|---|---|---|---|---|---|---|")
    for subject in sorted({row.subject for row in rows}):
        mine = [row for row in rows if row.subject == subject]
        touched = len({row.record for row in mine})
        counts = Counter(row.category for row in mine)
        lines.append(
            f"| {subject} | {mine[0].kind} | {touched} | {len(mine)} | "
            f"{counts[redaction.SECRET]} | {counts[redaction.PERSON]} | "
            f"{counts[redaction.ADVISORY]} |")
    lines.append("")

    secrets = [row for row in rows if row.category == redaction.SECRET]
    if secrets:
        lines.append("## Every secret finding, by location")
        lines.append("")
        lines.append("| subject | record | pointer | pattern | value |")
        lines.append("|---|---|---|---|---|")
        for row in sorted(secrets, key=lambda r: (r.subject, r.record or -1, r.path)):
            record = "-" if row.record is None else str(row.record)
            # An empty pointer means the detector addressed a line, not a value. Saying
            # "whole file" there would overstate what it found by the size of the file.
            pointer = row.path or "(record only)"
            value = row.fingerprint or "(not compared)"
            lines.append(f"| {row.subject} | {record} | `{pointer}` | {row.pattern} | {value} |")
        lines.append("")
    return "\n".join(lines)


#: String fields the loader reads back to reassemble turns and to join a record to its
#: parent. Redacting one of these would leave the record looking fine and quietly break
#: the assembly, so they are passed through. They are identifiers, not content: nothing
#: a person typed or a tool printed reaches Langfuse through them.
STRUCTURAL_KEYS: frozenset[str] = frozenset({
    "uuid", "parentUuid", "leafUuid", "sessionId", "session_id", "messageId",
    "requestId", "promptId", "id", "tool_use_id", "sourceToolUseID",
    "sourceToolAssistantUUID", "type", "role", "timestamp", "version",
})

#: Subtrees that carry what a tool was given or returned, not how the transcript is put
#: together. Inside them a field named `id` or `type` is content, so the structural skip
#: stops at their boundary.
PAYLOAD_KEYS: frozenset[str] = frozenset({"input", "toolUseResult"})

#: The same by block type: what a tool returned sits in a `tool_result` block's `content`,
#: which the vendored hook serialises into the tool observation.
PAYLOAD_BY_TYPE: dict[str, frozenset[str]] = {"tool_result": frozenset({"content"})}


def redact_records(records: list, redactor: redaction.Redactor, *, subject: str,
                   categories: frozenset[str] = redaction.DEFAULT_REDACT):
    """Rewrite the sensitive values in a parsed transcript, keeping every record.

    This is the exclusion the loader actually needs. The unit that gets left out is one
    value at one JSON pointer; the record stays, the turn it belongs to stays, and the
    session stays, so a tool result that printed an environment variable costs that value
    rather than the research around it.

    Run before turn assembly rather than after, so everything the assembler reads is
    already rewritten and the vendored hook stays untouched. Returns the new records and
    the inventory rows for what was changed.
    """
    out, rows = [], []
    for index, record in enumerate(records):
        clean, found = redaction.redact_tree(
            record, categories=categories, key=redactor.key, skip_keys=STRUCTURAL_KEYS,
            payload_keys=PAYLOAD_KEYS,
            payload_by_type=PAYLOAD_BY_TYPE)
        out.append(clean)
        uuid = record.get("uuid") if isinstance(record, dict) else None
        rows.extend(_rows_from(found, subject, "transcript", index,
                               uuid if isinstance(uuid, str) else None))
    return out, rows


def turn_of_record(records: list, turns: list) -> dict[int, int]:
    """Which turn each record ended up in, by identity.

    `build_turns` keeps the record dicts themselves rather than copies, so `id()` maps a turn's
    members back to their position in the list it was given. Records that no turn claims are
    absent from the result, and there are a lot of them: attachments, superseded assistant rows
    (the assembler keeps the latest per message id), and the Claude Code metadata rows the
    assembler ignores. Those never reach Langfuse, which is exactly why a rate computed over the
    whole file overstates what is actually uploaded.
    """
    position = {id(record): index for index, record in enumerate(records)}
    out: dict[int, int] = {}
    for number, turn in enumerate(turns, 1):
        for member in [turn.user_msg, *turn.assistant_msgs, *turn.tool_results_by_id.values()]:
            index = position.get(id(member))
            if index is not None:
                out[index] = number
    return out


@dataclass(frozen=True)
class TurnFindings:
    """What one turn carries, which is what one Langfuse trace will carry."""
    turn: int
    secret: int
    person: int
    advisory: int
    worst: str | None       # the pattern behind the most severe finding, for a categorical score
    pointers: tuple[str, ...]


def by_turn(rows: list[Row], turn_of: dict[int, int]) -> tuple[list[TurnFindings], list[Row]]:
    """Group findings by turn, and hand back the ones no turn claims rather than dropping them.

    The second return value is the honest part. A finding on a record the assembler discards is
    not uploaded, and silently folding those into a per-turn total would report a trace as dirtier
    than the thing Langfuse actually holds.
    """
    grouped: dict[int, list[Row]] = defaultdict(list)
    unclaimed: list[Row] = []
    for row in rows:
        turn = turn_of.get(row.record) if row.record is not None else None
        if turn is None:
            unclaimed.append(row)
        else:
            grouped[turn].append(row)

    order = {redaction.SECRET: 0, redaction.PERSON: 1, redaction.ADVISORY: 2}
    out = []
    for turn in sorted(grouped):
        mine = grouped[turn]
        counts = Counter(row.category for row in mine)
        worst = min(mine, key=lambda r: (order.get(r.category, 9), -r.length))
        out.append(TurnFindings(
            turn=turn, secret=counts[redaction.SECRET], person=counts[redaction.PERSON],
            advisory=counts[redaction.ADVISORY], worst=worst.pattern,
            pointers=tuple(sorted({row.path for row in mine if row.path})),
        ))
    return out, unclaimed


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True, help="inventory JSONL to write")
    ap.add_argument("--report", type=Path, default=None, help="markdown rollup to write")
    ap.add_argument("--asset-root", type=Path, default=None,
                    help="treat the inputs as assets under this root, not transcripts")
    ap.add_argument("--no-gitleaks", action="store_true",
                    help="skip the gitleaks half of the union")
    args = ap.parse_args()
    if args.report and args.report.expanduser().resolve() == args.out.expanduser().resolve():
        ap.error("--out and --report name the same file; the report would replace the inventory")
    inputs = {p.expanduser().resolve() for p in args.paths}
    for name, out in (("--out", args.out), ("--report", args.report)):
        # Both are opened with "w", so naming an input here would destroy the transcript.
        if out is not None and out.expanduser().resolve() in inputs:
            ap.error(f"{name} names one of the inputs; refusing to overwrite it")

    kind = "asset" if args.asset_root else "transcript"
    redactor = redaction.Redactor()
    rows: list[Row] = []
    unreadable: list[Path] = []
    for path in args.paths:
        try:
            if kind == "asset":
                rows.extend(scan_asset(path, redactor, root=args.asset_root))
            else:
                rows.extend(scan_transcript(path, redactor))
        except OSError as exc:
            print(f"{path.name}: unreadable ({exc.strerror})", file=sys.stderr)
            unreadable.append(path)

    detectors = ["redaction"]
    if not args.no_gitleaks:
        # An asset over the size bound was never read, and gitleaks must not read it either.
        scannable = [p for p in args.paths if p not in unreadable
                     and not (kind == "asset" and p.stat().st_size > MAX_ASSET_BYTES)]
        gitleaks = gitleaks_rows(scannable, kind=kind, key=redactor.key, root=args.asset_root)
        if gitleaks:
            rows.extend(gitleaks)
            detectors.append("gitleaks")
        else:
            # An empty result and a missing binary look the same from here, and a report
            # claiming both detectors ran when one did not is the kind of clean answer
            # that stops a check being read.
            detectors.append("gitleaks (no findings, or not installed)")

    write_inventory(rows, args.out)
    text = report(rows, detectors=detectors)
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    print(text)
    return 2 if unreadable else 0


if __name__ == "__main__":
    sys.exit(main())
