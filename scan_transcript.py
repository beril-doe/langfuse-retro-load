#!/usr/bin/env python3
"""
Scan transcripts for material that should not be uploaded, before uploading them.

Why this exists: the artifact path in this project redacts and refuses. The
transcript path does not. `retro_load.py` takes turn content verbatim, truncates
it at 20,000 characters, and sends it. Nothing inspects what is in it.

That gap is not hypothetical. A BERDL tenant-membership API dump landed in one
already-loaded session, carrying display names, email addresses and access levels
for 24 people who are not party to this work. Langfuse observations are immutable
once ingested, and the only delete removes an entire trace including the original
research, so there is no fixing this after the fact. The check has to happen
before the write.

Two pattern families, and the distinction matters:

  secrets  -- the same seven shapes evalome/collecting.py refuses on, in
              coscientist-bench. Duplicated here deliberately rather than imported:
              this script has to run on the pod next to retro_load.py, and dragging
              a benchmark package there for seven regexes is the wrong trade. If you
              change one table, change the other.

  people   -- email addresses, the name-beside-address shape that an API dump of a
              membership list produces, and phone numbers. evalome has none of
              these. Its redaction is about credentials, not persons, so a file
              listing colleagues passes it untouched.

ORCIDs are counted but never block a load. They are public identifiers by design.

Output is counts by default and nothing else, so this is safe to run against
anyone's transcript, including the frozen workshop corpus. `--detail` writes
matched context to a file for a human to read; that file is gitignored and must
never be committed, because its whole purpose is to hold the material we are
trying not to publish.

Exit status is the point: 0 clean, 1 findings, 2 could not read. Make a load
depend on it.

Usage:
    python3 scan_transcript.py ~/.claude/projects/*/*.jsonl
    python3 scan_transcript.py --detail /tmp/scan.txt one-session.jsonl
    python3 scan_transcript.py --ignore orcid,email_institutional *.jsonl
"""
import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

#: Keep in sync with VALUE_RES in evalome/collecting.py (coscientist-bench).
#: (?<![A-Za-z0-9]) rather than \b: a token embedded in a filename sits behind an
#: underscore, which \b does not treat as a boundary at all.
SECRET_RES = {
    "bearer_header": re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    "openai_style": re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}"),
    "github_pat": re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}"),
    "aws_access_key_id": re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    "google_oauth": re.compile(r"(?<![A-Za-z0-9])ya29\.[A-Za-z0-9_-]{20,}"),
    "google_api_key": re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    "private_key_block": re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    "jwt": re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    "slack_token": re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    "keyed_value": re.compile(
        r"(?i)(?:token|secret|password|passwd|api[ _-]?key|credential)"
        r"[\"'*`\t ]*[:=][\t ]*[\"']?[A-Za-z0-9!@#$%^&*_+/=-]{8,}"
    ),
    "mongo_uri": re.compile(r"mongodb(?:\+srv)?://[^\s\"']{6,}"),
}

#: Personal-provider domains, kept separate from institutional addresses. An
#: lbl.gov address is usually already public in a paper or a repo; a Gmail address
#: attached to someone's name generally is not, and it is the one people mind.
PERSONAL_DOMAINS = r"(?:gmail|googlemail|yahoo|ymail|hotmail|outlook|live|icloud|me|aol|proton|protonmail|pm)\.(?:com|me)"

PERSON_RES = {
    "email_personal": re.compile(rf"[A-Za-z0-9._%+-]+@{PERSONAL_DOMAINS}\b", re.IGNORECASE),
    "email_institutional": re.compile(
        r"[A-Za-z0-9._%+-]+@(?!" + PERSONAL_DOMAINS + r"\b)[A-Za-z0-9.-]+\.(?:gov|edu|org|net|com|io|ac\.[a-z]{2})\b",
        re.IGNORECASE,
    ),
    # A membership or directory dump: a person's name sitting next to their address.
    # Written loosely on purpose. It is meant to catch the shape of an API response
    # that enumerates people, whatever the serialization, not one client's exact repr.
    "name_beside_email": re.compile(
        r"(?i)(?:display_?name|full_?name|real_?name|\bname)[\"'\s]*[:=][\"'\s]*[^\"'\n,}]{2,60}"
        r"[\"'\s,}]{1,8}[\"'\s]*(?:e?mail|email_address)[\"'\s]*[:=]",
    ),
    "phone_us": re.compile(r"(?<!\d)\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"),
}

#: Counted, reported, never a reason to block. Public identifiers.
NOTE_RES = {
    "orcid": re.compile(r"(?<!\d)\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b"),
}

ALL = {**SECRET_RES, **PERSON_RES, **NOTE_RES}
#: Findings in these categories do not set a failing exit status on their own.
ADVISORY = set(NOTE_RES)

#: A value that is already masked is not a secret. `gh auth status` prints
#: "Token: gho_************", and a transcript full of tool output contains a lot of
#: that. Counting it buries the one real finding under seventy harmless ones, which
#: is how a check stops being read. Only applied to secret patterns: a masked email is
#: still worth a look, since the mask may not cover the whole address.
MASKED_RE = re.compile(r"\*{4,}|x{8,}|•{4,}|\[REDACTED\]|<REDACTED>", re.IGNORECASE)


def scan_text(text: str, ignore: set[str]) -> tuple[Counter, dict[str, set[str]], dict[str, list[str]]]:
    """Count matches, collect distinct matched values, and keep a little context."""
    counts: Counter = Counter()
    values: dict[str, set[str]] = defaultdict(set)
    context: dict[str, list[str]] = defaultdict(list)
    for name, pattern in ALL.items():
        if name in ignore:
            continue
        for match in pattern.finditer(text):
            if name in SECRET_RES and MASKED_RE.search(match.group(0)):
                continue
            counts[name] += 1
            # Distinct values only for the person patterns. Never for secrets: holding
            # a secret in memory to print a count of unique ones is not worth it, and
            # a caller with --detail would then have it written to disk.
            if name in PERSON_RES or name in NOTE_RES:
                values[name].add(match.group(0))
            if len(context[name]) < 5:
                start = max(0, match.start() - 90)
                context[name].append(text[start:match.end() + 50].replace("\n", " "))
    return counts, values, context


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="+", type=Path, help="transcript or text files to scan")
    ap.add_argument("--detail", type=Path, default=None,
                     help="write matched context here for human review. Contains the very "
                          "material being checked for: never commit it, never paste it.")
    ap.add_argument("--ignore", default="",
                     help="comma-separated pattern names to skip entirely")
    ap.add_argument("--quiet", action="store_true",
                     help="suppress the per-file lines, leaving only the closing summary")
    args = ap.parse_args()

    ignore = {name.strip() for name in args.ignore.split(",") if name.strip()}
    unknown = ignore - set(ALL)
    if unknown:
        print(f"unknown pattern name(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        print(f"known: {', '.join(sorted(ALL))}", file=sys.stderr)
        return 2

    total: Counter = Counter()
    blocking_files: list[Path] = []
    unreadable: list[Path] = []
    detail_rows = []

    for path in args.paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"{path.name}: UNREADABLE ({exc.strerror})")
            unreadable.append(path)
            continue
        counts, values, context = scan_text(text, ignore)
        total.update(counts)
        blocking = {n: c for n, c in counts.items() if n not in ADVISORY}
        if blocking:
            blocking_files.append(path)
        if not args.quiet:
            if counts:
                parts = []
                for name in sorted(counts):
                    distinct = f"/{len(values[name])} distinct" if values.get(name) else ""
                    parts.append(f"{name}={counts[name]}{distinct}")
                flag = "FINDINGS" if blocking else "advisory"
                print(f"{path.name}: {flag}  " + "  ".join(parts))
            else:
                print(f"{path.name}: clean")
        if args.detail and counts:
            detail_rows.append((path, counts, values, context))

    if args.detail:
        with args.detail.open("w", encoding="utf-8") as handle:
            handle.write("Scan detail. Contains the material being checked for. Do not commit.\n\n")
            for path, counts, values, context in detail_rows:
                handle.write(f"=== {path} ===\n")
                for name in sorted(counts):
                    handle.write(f"  {name}: {counts[name]}\n")
                    for value in sorted(values.get(name, ()))[:50]:
                        handle.write(f"      value: {value}\n")
                    for line in context[name]:
                        handle.write(f"      context: {line[:240]}\n")
                handle.write("\n")
        args.detail.chmod(0o600)

    print()
    print(f"summary: {len(args.paths)} file(s), {len(blocking_files)} with findings, "
          f"{len(unreadable)} unreadable")
    for name in sorted(total):
        kind = "advisory" if name in ADVISORY else "blocking"
        print(f"  {name:<22}{total[name]:>7}  ({kind})")
    if unreadable:
        return 2
    return 1 if blocking_files else 0


if __name__ == "__main__":
    sys.exit(main())
