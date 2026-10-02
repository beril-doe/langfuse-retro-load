#!/usr/bin/env python3
"""Look at what a redaction in Langfuse replaced, from the source transcript.

This is the other end of the screening pass. A trace in Langfuse shows
`[REDACTED:keyed_value:8c10b2ce]` and you want to know whether that was a live credential,
a documentation placeholder, or a false positive. The value is not in Langfuse by design,
so the answer can only come from the source.

**This is the one tool here that can print credential material, so it has rules.**

It runs on the pod and nowhere else. The only unredacted copies of these transcripts are
the pod's live `~/.claude` and the frozen corpus beside it, and raw `.jsonl` does not leave
the pod.

It writes no files. There is no `--out` and no `--detail`. A tool whose purpose is to
surface the material everything else exists to remove should leave nothing behind, and
`--show-values` refuses to run when stdout is not a terminal, so a redirect into a file
fails instead of quietly creating one.

**Its output is yours to read, not to paste anywhere.** Anything pasted into an agent
session reaches the model provider, which is the exposure
https://github.com/beril-doe/BERIL-research-observatory/issues/428 exists about and the one
thing deleting a trace afterwards cannot undo. Report your verdict, not the value.

The default prints no value at all. It prints the shape (how long, and for a long value the
first and last two characters), a guess at whether it looks like a placeholder, and the
surrounding text with any *other* finding in that context redacted, so reading about one
credential never shows you a neighbouring one. `--show-values` prints the raw text and is
the only way to see it. With `--plan`, it also shows the other planned values in the same
field, so the context reads as the transcript does.

Usage, from ~/langfuse-retro-load on the pod:
    .venv/bin/python reveal.py --transcript SESSION.jsonl --turn 71
    .venv/bin/python reveal.py --transcript SESSION.jsonl --record 133 --pattern keyed_value
    .venv/bin/python reveal.py --transcript SESSION.jsonl --turn 71 --show-values
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))

import inventory
import redaction

#: How much text either side of a finding to show.
CONTEXT = 60

#: Below this length, showing the first and last characters shows most of the value.
SHORT = 12

#: Shapes that suggest documentation rather than a credential. A guess, labelled as one:
#: it decides nothing, it is printed so a reader can triage faster.
PLACEHOLDER_HINTS = re.compile(
    r"(?i)<[^>]*>|\byour[_ -]|example|changeme|change_me|xxx+|\bdummy\b|\bfake\b|placeholder"
    r"|not[ _]set|\bnone\b|\bnull\b|todo|\bredacted\b|\*{3,}")

#: A value that is a variable reference holds no secret, whatever the key in front of it is
#: called. `export ANTHROPIC_AUTH_TOKEN=$CBORG_API_KEY` is the shape, found 2026-09-18 in the
#: first real use of this tool: three of six findings in one record were two references and a
#: documentation placeholder, and only the placeholder was labelled. Kept separate from the
#: hints above because this one is certain rather than a guess.
REFERENCE_RE = re.compile(r"[:=]\s*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\s*$|^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")


def shape(value: str) -> str:
    """What a value looks like, without being the value."""
    n = len(value)
    if REFERENCE_RE.search(value):
        hint = " is a variable reference, not a value"
    elif PLACEHOLDER_HINTS.search(value):
        hint = " looks like a placeholder"
    else:
        hint = ""
    if n <= SHORT:
        return f"<{n} chars{hint}>"
    return f'<{n} chars, "{value[:2]}"…"{value[-2:]}"{hint}>'


def resolve(document, pointer: str):
    """RFC 6901, enough for a transcript record."""
    node = document
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


#: One key for the whole run, so a field's scan can be reused across its findings.
_KEY = redaction.new_key()


@functools.lru_cache(maxsize=16)
def _field_findings(leaf: str) -> tuple:
    return tuple(redaction.detect(leaf, key=_KEY))


def _hide(leaf: str, lo: int, hi: int, found) -> str:
    """leaf[lo:hi] with every finding that touches it replaced, the part inside the range
    only, so a finding cut by the range edge is still hidden."""
    out, cursor = [], lo
    for f in found:
        if f.end <= lo or f.start >= hi:
            continue
        a, b = max(f.start, lo), min(f.end, hi)
        if a < cursor:
            continue
        out.append(leaf[cursor:a])
        out.append(f.placeholder)
        cursor = b
    out.append(leaf[cursor:hi])
    return "".join(out)


def context_for(leaf: str, start: int, end: int, *, show_values: bool,
                raw_context: bool = False) -> str:
    """The text around a finding, with every neighbouring finding redacted.

    Reading about one credential must not put a different one on the screen, so the two
    sides are redacted independently and the finding itself is spliced back in as its shape
    or, with `--show-values`, as itself. `raw_context` leaves the two sides as they are, for
    `--plan --show-values`, where the reviewer asked to read the field as the transcript has it.
    """
    if raw_context:
        before, after = leaf[:start], leaf[end:]
    else:
        # Neighbours come from one scan of the whole field, not of each side or of the
        # window: a neighbour crossing the window's edge, or one whose key sits inside this
        # finding's span, is still recognised and hidden in full, and a field with many
        # findings is scanned once rather than once per finding
        # (https://github.com/beril-doe/langfuse-retro-load/issues/26).
        found = _field_findings(leaf)
        before, after = _hide(leaf, 0, start, found), _hide(leaf, end, len(leaf), found)
    before, after = before[max(0, len(before) - CONTEXT):], after[:CONTEXT]
    middle = leaf[start:end] if show_values else shape(leaf[start:end])
    return (before + middle + after).replace("\n", " ⏎ ")


#: What a neighbouring planned span shows as in context.
OTHER_MASK = "[another planned mask]"


def hide_others(leaf: str, target, others) -> tuple[str, int, int]:
    """The field with every other planned span replaced, and the target's new offsets.

    A span overlapping the target is part of the same value: the target grows to cover it,
    so a wider gitleaks span around a narrower local one is hidden in full.
    """
    lo, hi = target.start, target.end
    grown = True
    while grown:
        grown = False
        for other in others:
            if other.start < hi and lo < other.end and (other.start < lo or other.end > hi):
                lo, hi, grown = min(lo, other.start), max(hi, other.end), True
    target = SimpleNamespace(start=lo, end=hi)
    spans = []
    for other in sorted(others, key=lambda m: (m.start, m.end)):
        if other.end <= target.start or other.start >= target.end:
            if spans and other.start < spans[-1][1]:
                spans[-1][1] = max(spans[-1][1], other.end)
            else:
                spans.append([other.start, other.end])
    text, pos, shift = "", 0, 0
    for start, end in spans:
        text += leaf[pos:start] + OTHER_MASK
        if end <= target.start:
            shift += len(OTHER_MASK) - (end - start)
        pos = end
    text += leaf[pos:]
    return text, target.start + shift, target.end + shift


def overlap_chain(target, others) -> list:
    """Every span joined to `target` through a chain of overlaps, as `plan.apply` merges them.

    Direct overlap alone missed C when A overlaps B and B overlaps C but not A, so the view
    printed C apart from the one span the load would replace (Copilot review of the merged
    head of https://github.com/beril-doe/langfuse-retro-load/pull/43).
    """
    lo, hi, chain = target.start, target.end, []
    grown = True
    while grown:
        grown = False
        for other in others:
            if other not in chain and other.start < hi and lo < other.end:
                chain.append(other)
                lo, hi, grown = min(lo, other.start), max(hi, other.end), True
    return chain


def shown_with(target, siblings) -> list:
    """The planned spans `--show-values` folds into `target`: its overlap chain, ignoring
    cleared spans. The load does not apply a cleared span, so it must not join two masked
    spans into one; it stays visible as raw context (Copilot review of
    https://github.com/beril-doe/langfuse-retro-load/pull/45)."""
    if getattr(target, "cleared", False):
        # A cleared target is not applied either, so it joins nothing (third Copilot
        # review of the same pull request).
        return []
    return overlap_chain(target, [m for m in siblings if not m.cleared])


def _plan_for(plan_path: Path, headers, masks, transcript: Path, data: bytes):
    """This transcript's header and masks, or None after saying why the view would be wrong."""
    subject = inventory._subject_for(transcript)
    header = headers.get(subject)
    if header is None:
        print(f"{plan_path.name} has no entry for {subject}", file=sys.stderr)
        return None
    if header.transcript_sha256 != hashlib.sha256(data).hexdigest():
        print(f"{subject} changed after its plan was built; this view would not match what a "
              f"load does. Rebuild the plan.", file=sys.stderr)
        return None
    if header.masks != len(masks.get(subject, [])):
        print(f"{plan_path.name} is incomplete for {subject}: its header lists {header.masks} "
              f"mask(s) and {len(masks.get(subject, []))} follow. The load refuses it; rebuild "
              f"the plan.", file=sys.stderr)
        return None
    return subject, header, masks.get(subject, [])


def show_plan(args, records, data: bytes) -> int:
    """Print each mask the plan holds for this transcript, as the load will apply it."""
    import plan
    headers, masks = plan.read(args.plan)
    checked = _plan_for(args.plan, headers, masks, args.transcript, data)
    if checked is None:
        return 1
    subject, header, subject_masks = checked
    print(f"{subject}: plan from {', '.join(header.detectors)}, {header.records} records")
    shown = unplaceable = 0
    for mask in subject_masks:
        if args.record and mask.record not in args.record:
            continue
        if args.pointer and mask.pointer not in args.pointer:
            continue
        if args.pattern and mask.pattern not in args.pattern:
            continue
        where = f"record {mask.record}"
        if mask.pointer is None:
            if mask.cleared:
                print(f"{where}  (no field)  {mask.pattern}: CLEARED; not pinned to a field, "
                      f"which the load accepts because a reviewer cleared it")
                continue
            print(f"{where}  (no field)  {mask.pattern}: found by {mask.detector} but not pinned "
                  f"to a field; the load will refuse this plan until it is cleared or fixed")
            unplaceable += 1
            continue
        leaf = resolve(records[mask.record], mask.pointer)
        # Without --show-values, every other planned span in this field is hidden before the
        # context is cut, so the default view never prints any value, including gitleaks-only
        # ones and cleared ones. With --show-values the context reads as the transcript does:
        # only a span overlapping this one is folded into it, so a reviewer sees the value
        # next to the one under review instead of a placeholder (asked for 2026-09-24).
        siblings = [m for m in subject_masks
                    if m is not mask and m.record == mask.record and m.pointer == mask.pointer]
        if args.show_values:
            siblings = shown_with(mask, siblings)
        shown_leaf, start, end = hide_others(leaf, mask, siblings)
        label = "  CLEARED, will not be masked" if mask.cleared else ""
        print(f"{where}  {mask.pointer}  {mask.pattern} ({mask.detector}){label}")
        print(f"    {context_for(shown_leaf, start, end, show_values=args.show_values, raw_context=args.show_values)}")
        shown += 1
    print(f"\n{shown} planned mask(s)" + (f", {unplaceable} not pinned" if unplaceable else "")
          + ("" if args.show_values else ". No value was printed; pass --show-values in a "
                                         "terminal to see the text itself."))
    return 0


#: How many places to list for one distinct value before summarising the rest.
PLACES = 5


def show_distinct(args, transcripts: list[Path]) -> int:
    """Each distinct planned value once, across every transcript given, most urgent first.

    A preview with hundreds of masks is mostly the same few values repeating: one `.env` read
    several times, the same command output in every session. Paging through each occurrence
    buries the handful that need a decision
    (https://github.com/beril-doe/langfuse-retro-load/issues/77). Values are grouped by pattern
    and text, secrets before personal details, then by how often they occur. Each group shows
    one occurrence in context and lists where the others are. The plan and the load are
    unchanged; this only changes what is printed.
    """
    import plan
    import retro_load
    headers, masks = plan.read(args.plan)
    groups: dict[tuple[str, str, str], dict] = {}
    unplaceable = cleared = 0
    for transcript in transcripts:
        data = transcript.read_bytes()
        checked = _plan_for(args.plan, headers, masks, transcript, data)
        if checked is None:
            return 1
        subject, _, subject_masks = checked
        records = None
        for mask in subject_masks:
            if mask.cleared:
                cleared += 1
                continue
            if mask.pointer is None:
                unplaceable += 1
                continue
            if records is None:
                records = retro_load.parse_jsonl(data)
            leaf = resolve(records[mask.record], mask.pointer)
            key = (mask.category, mask.pattern, leaf[mask.start:mask.end])
            group = groups.get(key)
            if group is None:
                siblings = [m for m in subject_masks if m is not mask and not m.cleared
                            and m.record == mask.record and m.pointer == mask.pointer]
                if args.show_values:
                    siblings = shown_with(mask, siblings)
                shown_leaf, start, end = hide_others(leaf, mask, siblings)
                group = groups[key] = {
                    "detectors": set(), "places": [], "sessions": set(),
                    "context": context_for(shown_leaf, start, end, show_values=args.show_values,
                                           raw_context=args.show_values)}
            group["detectors"].add(mask.detector)
            group["sessions"].add(subject)
            group["places"].append(f"{subject[:8]} record {mask.record}")
    order = sorted(groups.items(), key=lambda kv: (kv[0][0] != redaction.SECRET,
                                                   -len(kv[1]["places"]), kv[0][1]))
    total = sum(len(g["places"]) for g in groups.values())
    print(f"{total} planned mask(s) in {len(transcripts)} session(s), "
          f"{len(groups)} distinct value(s)\n")
    for n, ((category, pattern, _), group) in enumerate(order, 1):
        places = group["places"]
        more = f", and {len(places) - PLACES} more" if len(places) > PLACES else ""
        print(f"[{n}] {category} {pattern} ({', '.join(sorted(group['detectors']))}): "
              f"{len(places)} time(s) in {len(group['sessions'])} session(s)")
        print(f"    {group['context']}")
        print(f"    at {'; '.join(places[:PLACES])}{more}")
    if cleared:
        print(f"\n{cleared} cleared mask(s) not shown; the load leaves them unmasked")
    if unplaceable:
        print(f"\n{unplaceable} mask(s) not pinned to a field; the load will refuse this plan "
              f"until they are cleared or fixed")
    if not args.show_values:
        print("\nNo value was printed; pass --show-values in a terminal to see the text itself.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript", type=Path, action="append", required=True,
                    help="the session's .jsonl; repeat for several with --distinct")
    ap.add_argument("--turn", type=int, action="append", default=[],
                    help="turn number, as the Langfuse trace name gives it (repeatable)")
    ap.add_argument("--record", type=int, action="append", default=[],
                    help="0-based record number, as the inventory gives it: the position among "
                         "parsed records, so blank and unparseable lines are not counted "
                         "(repeatable)")
    ap.add_argument("--pointer", action="append", default=[],
                    help="JSON pointer, as the inventory gives it")
    ap.add_argument("--pattern", action="append", default=[],
                    help="only this pattern, e.g. keyed_value (repeatable)")
    ap.add_argument("--all-categories", action="store_true",
                    help="include advisory findings, which are home paths and ORCIDs")
    ap.add_argument("--plan", type=Path, default=None,
                    help="show what this redaction plan will mask, in context, instead of "
                         "scanning. The same spans the load will rewrite")
    ap.add_argument("--distinct", action="store_true",
                    help="with --plan: show each distinct planned value once, with a count, "
                         "across every --transcript given")
    ap.add_argument("--show-values", action="store_true",
                    help="print the raw matched text. Refuses when output is not a terminal")
    args = ap.parse_args()

    if args.show_values and not sys.stdout.isatty():
        print("--show-values refuses to run when output is not a terminal: this tool writes "
              "no files and a redirect is a file.", file=sys.stderr)
        return 2

    if args.distinct:
        if not args.plan:
            print("--distinct shows a plan; give --plan", file=sys.stderr)
            return 2
        if args.turn or args.record or args.pointer or args.pattern:
            print("--distinct shows the whole plan; it takes no --turn, --record, --pointer "
                  "or --pattern", file=sys.stderr)
            return 2
        return show_distinct(args, args.transcript)
    if len(args.transcript) > 1:
        print("several --transcript values need --distinct", file=sys.stderr)
        return 2
    args.transcript = args.transcript[0]

    import retro_load
    if args.plan:
        if args.turn:
            print("--turn isn't supported with --plan; use --record, --pointer or --pattern",
                  file=sys.stderr)
            return 2
        # One read, used for both the hash check and the records shown, as the loader does.
        data = args.transcript.read_bytes()
        return show_plan(args, retro_load.parse_jsonl(data), data)

    records = retro_load.load_all_jsonl(args.transcript)

    turn_of: dict[int, int] = {}
    if args.turn:
        from langfuse_hook_official import build_turns
        turn_of = inventory.turn_of_record(records, build_turns(records))

    wanted_categories = ({redaction.SECRET, redaction.PERSON, redaction.ADVISORY}
                         if args.all_categories else {redaction.SECRET, redaction.PERSON})
    redactor = redaction.Redactor()
    shown = 0
    for index, record in enumerate(records):
        if args.record and index not in args.record:
            continue
        if args.turn and turn_of.get(index) not in args.turn:
            continue
        _, found = redaction.redact_tree(record, categories=inventory.REPORT_ONLY,
                                         key=redactor.key,
                                         skip_keys=inventory.STRUCTURAL_KEYS,
                                         payload_keys=inventory.PAYLOAD_KEYS,
                                         payload_by_type=inventory.PAYLOAD_BY_TYPE)
        for located in found:
            f = located.finding
            if f.category not in wanted_categories:
                continue
            if args.pattern and f.pattern not in args.pattern:
                continue
            if args.pointer and located.path not in args.pointer:
                continue
            leaf = resolve(record, located.path)
            if not isinstance(leaf, str):
                continue
            turn = turn_of.get(index)
            where = f"record {index}" + (f", turn {turn}" if turn else "")
            print(f"{where}  {located.path}  {f.pattern} ({f.category})")
            print(f"    {context_for(leaf, f.start, f.end, show_values=args.show_values)}")
            shown += 1
    if not shown:
        print("no findings matched those selectors")
    elif not args.show_values:
        print(f"\n{shown} finding(s). No value was printed; pass --show-values in a terminal "
              f"to see the text itself.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
