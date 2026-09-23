#!/usr/bin/env python3
"""Build a redaction plan at scan time; apply exactly that plan at load time.

The inventory says what a scan found. The redaction plan says what a load will rewrite: the
inventory's secret and personal-detail findings, minus what a person cleared, each pinned to
a record, a JSON pointer and the character offsets of the value inside that field. It carries
no values, and it is tied to the transcript by SHA-256, so the offsets are only ever applied
to the exact bytes they were measured on.

Three files, three jobs:

- **inventory** (`inventory.py --out`): everything the scan found, including report-only items.
- **clearances** (written by a reviewer): findings a person decided are not secrets.
- **redaction plan** (this module): what the load applies. `reveal.py --plan` shows it.

Both detectors feed the plan. The local patterns give offsets directly. gitleaks reports a
line and the matched text, so the plan finds which field of that record holds the text and
records the pointer and offsets; the text itself is held in memory only for that search. A
gitleaks finding that can't be pinned to a field is kept as an unplaceable row, and the
loader refuses a plan that has one.

Usage, on the pod:
    python3 plan.py build --out plan.jsonl [--clearances clearances.jsonl] SESSION.jsonl ...
    python3 reveal.py --transcript SESSION.jsonl --plan plan.jsonl
    python3 retro_load.py --plan plan.jsonl SESSION.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import inventory  # noqa: E402
import redaction  # noqa: E402

#: The categories a plan acts on. Advisory findings (home paths, ORCIDs) are reported by the
#: inventory and never rewritten.
ACTIONABLE = frozenset({redaction.SECRET, redaction.PERSON})


class PlanError(RuntimeError):
    """The plan can't be applied as written: wrong transcript, bad row, or missing."""


@dataclass(frozen=True)
class Header:
    """One per transcript scanned, findings or not, so "nothing to mask" differs from
    "never scanned"."""
    subject: str
    transcript_sha256: str
    records: int
    detectors: tuple[str, ...]
    kind: str = "transcript"


@dataclass(frozen=True)
class Mask:
    """One span to rewrite. `pointer`, `start` and `end` are None for a gitleaks finding that
    couldn't be pinned to a field; the loader refuses a plan holding one."""
    subject: str
    record: int | None
    pointer: str | None
    start: int | None
    end: int | None
    pattern: str
    category: str
    detector: str
    fingerprint: str
    kind: str = "mask"
    #: A reviewer cleared it. Kept in the plan so the loader knows not to mask it and doesn't
    #: treat it as something the plan missed.
    cleared: bool = False


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _records(path: Path) -> list:
    """Parsed records, numbered the way load_all_jsonl() and the inventory number them."""
    out = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:  # noqa: S112 -- the loader skips these lines too
                continue
    return out


def _leaves(node, path: str = "", *, in_payload: bool = False, key: str | None = None):
    """Every string leaf the loader screens, with its RFC 6901 pointer.

    The same boundaries as inventory.redact_records(): a structural field (`id`, `uuid`,
    `type` and the rest) is skipped unless it sits inside a payload subtree, since rewriting
    one would break the turn assembly. A gitleaks match found only in such a field can't be
    placed, which blocks the load rather than corrupting it.
    """
    if isinstance(node, dict):
        block_payload = inventory.PAYLOAD_BY_TYPE.get(node.get("type"), frozenset()) \
            if isinstance(node.get("type"), str) else frozenset()
        for name, value in node.items():
            name = str(name)
            yield from _leaves(value, f"{path}/{redaction._escape_token(name)}",
                               in_payload=(in_payload or name in inventory.PAYLOAD_KEYS
                                           or name in block_payload), key=name)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _leaves(value, f"{path}/{index}", in_payload=in_payload, key=key)
    elif isinstance(node, str) and (in_payload or key not in inventory.STRUCTURAL_KEYS):
        yield path, node


def _all_leaves(node, path: str = ""):
    """Every string leaf, structural fields included."""
    if isinstance(node, dict):
        for name, value in node.items():
            yield from _all_leaves(value, f"{path}/{redaction._escape_token(str(name))}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _all_leaves(value, f"{path}/{index}")
    elif isinstance(node, str):
        yield path, node


def _all_keys(node):
    """Every object key, at every depth."""
    if isinstance(node, dict):
        for name, value in node.items():
            yield str(name)
            yield from _all_keys(value)
    elif isinstance(node, list):
        for value in node:
            yield from _all_keys(value)


def is_cleared(mask: Mask, clearances: list[dict]) -> bool:
    """A clearance names any of subject, record, pointer, pattern and fingerprint; a missing
    or null field matches anything, so `{"subject": s, "pattern": "orcid"}` clears that pattern
    in that session and nothing else."""
    fields = {"subject": mask.subject, "record": mask.record, "pointer": mask.pointer,
              "pattern": mask.pattern, "fingerprint": mask.fingerprint}
    return any(all(c.get(k) in (None, v) for k, v in fields.items()) for c in clearances)


def build(path: Path, *, clearances: list[dict] | None = None,
          use_gitleaks: bool = True) -> tuple[Header, list[Mask]]:
    """Scan one transcript and return its header and the masks the load should apply.

    Fingerprints are keyed by the transcript's own hash, so the same value in the same
    transcript fingerprints the same way on every scan and a clearance written against one
    scan still matches the next. Anyone who can compute one already holds the transcript.
    """
    digest = sha256_of(path)
    key = bytes.fromhex(digest)
    subject = inventory._subject_for(path)
    records = _records(path)
    masks: list[Mask] = []

    for index, record in enumerate(records):
        _, found = redaction.redact_tree(
            record, categories=inventory.REPORT_ONLY, key=key,
            skip_keys=inventory.STRUCTURAL_KEYS, payload_keys=inventory.PAYLOAD_KEYS,
            payload_by_type=inventory.PAYLOAD_BY_TYPE)
        for located in found:
            f = located.finding
            if f.category in ACTIONABLE:
                masks.append(Mask(subject=subject, record=index, pointer=located.path,
                                  start=f.start, end=f.end, pattern=f.pattern,
                                  category=f.category, detector="redaction",
                                  fingerprint=f.fingerprint))

    detectors = ["redaction"]
    if use_gitleaks:
        findings = inventory.gitleaks_findings(path)
        if findings is None:
            raise PlanError("gitleaks is not installed, so this plan would miss what only it "
                            "finds; install it, or pass --no-gitleaks to plan without it")
        detectors.append("gitleaks")
        numbers = inventory.record_numbers(path)
        for finding in findings:
            masks.extend(_place_gitleaks(finding, records, numbers, subject, key))

    clearances = clearances or []
    masks = [replace(m, cleared=True) if is_cleared(m, clearances) else m for m in masks]
    return Header(subject=subject, transcript_sha256=digest, records=len(records),
                  detectors=tuple(detectors)), masks


def _place_gitleaks(finding: dict, records: list, numbers: dict[int, int], subject: str,
                    key: bytes) -> list[Mask]:
    """Pin one gitleaks match to every field of its record that contains it."""
    secret = str(finding.get("Secret") or finding.get("Match") or "")
    pattern = inventory.GITLEAKS_PREFIX + str(finding.get("RuleID", "unknown"))
    line = finding.get("StartLine")
    record = numbers.get(line - 1) if isinstance(line, int) and line > 0 else None
    fp = redaction.fingerprint(secret, key)
    unplaceable = Mask(subject=subject, record=record, pointer=None, start=None, end=None,
                       pattern=pattern, category=redaction.SECRET, detector="gitleaks",
                       fingerprint=fp)
    if record is None or not secret:
        return [unplaceable]
    # A copy in a field the load won't rewrite (a structural identifier) would go out
    # whatever the plan does elsewhere, so it blocks the load. gitleaks' columns are for the
    # raw line, not the parsed field, so every copy counts rather than one guessed occurrence.
    eligible = dict(_leaves(records[record]))
    if any(secret in leaf for pointer, leaf in _all_leaves(records[record])
           if pointer not in eligible) or any(secret in k for k in _all_keys(records[record])):
        # A copy in an object key can't be masked either: the plan rewrites values only.
        return [unplaceable]
    placed = []
    for pointer, leaf in eligible.items():
        start = leaf.find(secret)
        while start != -1:
            placed.append(Mask(subject=subject, record=record, pointer=pointer, start=start,
                               end=start + len(secret), pattern=pattern,
                               category=redaction.SECRET, detector="gitleaks", fingerprint=fp))
            start = leaf.find(secret, start + len(secret))
    return placed or [unplaceable]


def write(out: Path, entries: list[tuple[Header, list[Mask]]]) -> None:
    with out.open("w", encoding="utf-8") as handle:
        for header, masks in entries:
            handle.write(json.dumps(asdict(header), sort_keys=True) + "\n")
            for mask in masks:
                handle.write(json.dumps(asdict(mask), sort_keys=True) + "\n")


def read(path: Path) -> tuple[dict[str, Header], dict[str, list[Mask]]]:
    headers: dict[str, Header] = {}
    masks: dict[str, list[Mask]] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if row.get("kind") == "transcript":
                row["detectors"] = tuple(row["detectors"])
                header = Header(**row)
                headers[header.subject] = header
            elif row.get("kind") == "mask":
                mask = Mask(**row)
                masks.setdefault(mask.subject, []).append(mask)
            else:
                raise ValueError(f"unknown kind {row.get('kind')!r}")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise PlanError(f"{path.name} line {number} is not a plan row: {exc}") from exc
    return headers, masks


def for_transcript(plan_path: Path, transcript: Path) -> list[Mask]:
    """The masks for one transcript, after checking the plan was built from these exact bytes."""
    return load(plan_path, transcript)[1]


def load(plan_path: Path, transcript: Path) -> tuple[Header, list[Mask]]:
    """for_transcript(), with the header, so a caller can check which detectors built it."""
    headers, masks = read(plan_path)
    subject = inventory._subject_for(transcript)
    header = headers.get(subject)
    if header is None:
        raise PlanError(f"{plan_path.name} has no entry for {subject}; build a plan for it first")
    if header.transcript_sha256 != sha256_of(transcript):
        raise PlanError(f"{subject} changed after its plan was built; rebuild the plan")
    rows = masks.get(subject, [])
    unplaceable = [m for m in rows if m.pointer is None and not m.cleared]
    if unplaceable:
        raise PlanError(f"{len(unplaceable)} finding(s) in {subject} could not be pinned to a "
                        f"field (record(s) {sorted({m.record for m in unplaceable}, key=str)}); "
                        f"review with reveal.py and clear or fix them before loading")
    return header, rows


def _set(document, pointer: str, value) -> None:
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in pointer.split("/")[1:]]
    node = document
    for token in tokens[:-1]:
        node = node[int(token)] if isinstance(node, list) else node[token]
    last = tokens[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


def apply(records: list, masks: list[Mask]) -> list:
    """Rewrite each planned span in place of the value, merging overlapping spans per field.

    Returns new records; the input is not changed. Raises PlanError when a mask doesn't fit
    the record it names, which the hash check makes a bug rather than an expected case.
    """
    out = json.loads(json.dumps(records))
    by_field: dict[tuple[int, str], list[Mask]] = {}
    for mask in masks:
        if mask.cleared:
            continue
        by_field.setdefault((mask.record, mask.pointer), []).append(mask)
    for (record, pointer), group in by_field.items():
        try:
            leaf = _resolve(out[record], pointer)
        except (IndexError, KeyError, ValueError, TypeError) as exc:
            raise PlanError(f"record {record} has no field {pointer}") from exc
        if not isinstance(leaf, str):
            raise PlanError(f"record {record} {pointer} is not text")
        spans = sorted(group, key=lambda m: (m.start, -m.end))
        merged: list[list] = []
        for mask in spans:
            if mask.start < 0 or mask.end > len(leaf) or mask.start >= mask.end:
                raise PlanError(f"record {record} {pointer}: span {mask.start}-{mask.end} "
                                f"does not fit a {len(leaf)}-character field")
            if merged and mask.start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], mask.end)
            else:
                merged.append([mask.start, mask.end, mask])
        for start, end, mask in reversed(merged):
            leaf = leaf[:start] + redaction._placeholder(_placeholder_name(mask),
                                                         mask.fingerprint) + leaf[end:]
        _set(out[record], pointer, leaf)
    return out


def _placeholder_name(mask: Mask) -> str:
    # One name for every gitleaks rule keeps the placeholder recognisable to PLACEHOLDER_RE.
    return "gitleaks" if mask.detector == "gitleaks" else mask.pattern


def _resolve(document, pointer: str):
    node = document
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="scan transcripts and write a redaction plan")
    b.add_argument("paths", nargs="+", type=Path)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--clearances", type=Path, default=None,
                   help="JSONL of findings a reviewer cleared; each row names any of subject, "
                        "record, pointer, pattern, fingerprint")
    b.add_argument("--no-gitleaks", action="store_true",
                   help="plan from the local patterns only. The header records it, and the "
                        "loader refuses such a plan unless --allow-plan-without-gitleaks")
    args = ap.parse_args()

    inputs = {p.expanduser().resolve() for p in args.paths}
    if args.clearances and args.clearances.expanduser().resolve() in inputs:
        # Its records would read as clearances, and a missing field matches anything.
        ap.error("--clearances names one of the transcripts")
    clearances = []
    if args.clearances:
        clearances = [json.loads(line) for line in args.clearances.read_text().splitlines()
                      if line.strip()]
    if args.out.expanduser().resolve() in inputs:
        ap.error("--out names one of the transcripts; refusing to overwrite it")
    subjects = [inventory._subject_for(p) for p in args.paths]
    repeated = sorted({s for s in subjects if subjects.count(s) > 1})
    if repeated:
        ap.error(f"more than one input has session id {', '.join(repeated)}; a plan names each "
                 f"transcript by session id, so build them into separate plans")
    entries = []
    for path in args.paths:
        try:
            header, masks = build(path, clearances=clearances, use_gitleaks=not args.no_gitleaks)
        except PlanError as e:
            print(f"{path.name}: {e}", file=sys.stderr)
            return 1
        entries.append((header, masks))
        unplaceable = sum(1 for m in masks if m.pointer is None and not m.cleared)
        cleared = sum(1 for m in masks if m.cleared)
        print(f"{path.name}: {len(masks) - cleared} mask(s), {cleared} cleared, detectors "
              f"{', '.join(header.detectors)}"
              + (f", {unplaceable} could not be pinned to a field" if unplaceable else ""))
    write(args.out, entries)
    print(f"plan written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
