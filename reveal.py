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
the only way to see it.

Usage, from ~/langfuse-retro-load on the pod:
    .venv/bin/python reveal.py --transcript SESSION.jsonl --turn 71
    .venv/bin/python reveal.py --transcript SESSION.jsonl --record 133 --pattern keyed_value
    .venv/bin/python reveal.py --transcript SESSION.jsonl --turn 71 --show-values
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

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


def shape(value: str) -> str:
    """What a value looks like, without being the value."""
    n = len(value)
    hint = " looks like a placeholder" if PLACEHOLDER_HINTS.search(value) else ""
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


def context_for(leaf: str, start: int, end: int, *, show_values: bool) -> str:
    """The text around a finding, with every neighbouring finding redacted.

    Reading about one credential must not put a different one on the screen, so the two
    sides are redacted independently and the finding itself is spliced back in as its shape
    or, with `--show-values`, as itself.
    """
    before, _ = redaction.redact(leaf[max(0, start - CONTEXT):start])
    after, _ = redaction.redact(leaf[end:end + CONTEXT])
    middle = leaf[start:end] if show_values else shape(leaf[start:end])
    return (before + middle + after).replace("\n", " ⏎ ")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript", type=Path, required=True)
    ap.add_argument("--turn", type=int, action="append", default=[],
                    help="turn number, as the Langfuse trace name gives it (repeatable)")
    ap.add_argument("--record", type=int, action="append", default=[],
                    help="0-based line in the .jsonl, as the inventory gives it (repeatable)")
    ap.add_argument("--pointer", action="append", default=[],
                    help="JSON pointer, as the inventory or a score's metadata gives it")
    ap.add_argument("--pattern", action="append", default=[],
                    help="only this pattern, e.g. keyed_value (repeatable)")
    ap.add_argument("--all-categories", action="store_true",
                    help="include advisory findings, which are home paths and ORCIDs")
    ap.add_argument("--show-values", action="store_true",
                    help="print the raw matched text. Refuses when output is not a terminal")
    args = ap.parse_args()

    if args.show_values and not sys.stdout.isatty():
        print("--show-values refuses to run when output is not a terminal: this tool writes "
              "no files and a redirect is a file.", file=sys.stderr)
        return 2

    import retro_load
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
                                         skip_keys=inventory.STRUCTURAL_KEYS)
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
