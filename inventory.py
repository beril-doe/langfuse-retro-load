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


def scan_transcript(path: Path, redactor: redaction.Redactor) -> list[Row]:
    """Every finding in one .jsonl transcript, addressed by record and JSON pointer.

    Parses each line rather than scanning the raw text, which is what gives the pointer
    and what bounds the damage a value with no terminator can do. A line that will not
    parse is still scanned, as one string, because an unparseable line is exactly where
    something unexpected ended up.
    """
    subject = _subject_for(path)
    rows: list[Row] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                _, found = redaction.redact_tree(line, categories=REPORT_ONLY,
                                                 key=redactor.key)
                rows.extend(_rows_from(found, subject, "transcript", index, None))
                continue
            uuid = record.get("uuid") if isinstance(record, dict) else None
            _, found = redaction.redact_tree(record, categories=REPORT_ONLY,
                                             key=redactor.key)
            rows.extend(_rows_from(found, subject, "transcript", index,
                                   uuid if isinstance(uuid, str) else None))
    return rows


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
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix in {".json", ".ipynb"}:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = text
    else:
        parsed = text
    _, found = redaction.redact_tree(parsed, categories=REPORT_ONLY, key=redactor.key)
    return _rows_from(found, relative, "asset", None, None)


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
        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--no-git", "--no-banner",
                 "--report-format", "json", "--report-path", "-", "--source", str(path)],
                capture_output=True, text=True, check=False,
            )
        except FileNotFoundError:
            return []
        if not result.stdout.strip():
            continue
        try:
            findings = json.loads(result.stdout)
        except ValueError:
            continue
        subject = _subject_for(path) if kind == "transcript" else (
            str(path.relative_to(root)) if root else path.name)
        for finding in findings:
            match = str(finding.get("Secret") or finding.get("Match") or "")
            line = finding.get("StartLine")
            rows.append(Row(
                subject=subject, kind=kind,
                # gitleaks counts lines from 1 and a .jsonl record is a line, so this is
                # the same `record` the pointer-addressed rows use.
                record=(line - 1) if isinstance(line, int) and line > 0 else None,
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
            record, categories=categories, key=redactor.key, skip_keys=STRUCTURAL_KEYS)
        out.append(clean)
        uuid = record.get("uuid") if isinstance(record, dict) else None
        rows.extend(_rows_from(found, subject, "transcript", index,
                               uuid if isinstance(uuid, str) else None))
    return out, rows


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
        gitleaks = gitleaks_rows([p for p in args.paths if p not in unreadable],
                                 kind=kind, key=redactor.key, root=args.asset_root)
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
