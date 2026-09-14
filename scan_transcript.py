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

  secrets  -- six shapes copied from evalome/collecting.py in coscientist-bench,
              plus five added here (private key blocks, JWTs, Slack tokens, a generic
              key=value rule, and credential-carrying Mongo URIs). Duplicated rather
              than imported because this has to run on the pod next to retro_load.py.
              If you change one table, change the other.

              Prior art note, 2026-09-11, corrected the same day. gitleaks 8.30.1 is
              installed here and runs on every commit. I first wrote that it finds the
              same credentials this file does, having compared totals. It does not.
              Its generic-api-key rule is entropy-gated with a floor near 3.5, and the
              three real tokens in the corpus score 4.351, 3.531 and 3.328. gitleaks
              misses the third, a genuine 32-character JUPYTERHUB_API_TOKEN, in every
              form tried: bare assignment, quoted JSON pair, inside an environment dump,
              as api_key=, as secret=, across six file extensions.

              The two approaches fail in opposite directions. Keyword anchoring catches
              anything after TOKEN= whatever its entropy and misses shapes nobody wrote
              a rule for; gitleaks catches roughly 150 provider shapes and misses
              low-entropy secrets. Run both and take the union. See issue #10.

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
import os
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
    # The escaped-quote alternatives are load-bearing. A transcript is JSONL, so a tool
    # result containing JSON arrives as \"token\":\"...\", and a nested payload as
    # \\"token\\":\\"...\\". Without them the scanner reads the raw file and misses a
    # credential that retro_load.py then decodes and uploads. The leak we actually found
    # came through as a plain env dump, so this gap had not bitten yet.
    "keyed_value": re.compile(
        r"(?i)(?:token|secret|password|passwd|api[ _-]?key|credential)"
        r"(?:\\{1,2}[\"'])?[\"'*`\t ]*[:=][\t ]*(?:\\{1,2}[\"'])?"
        r"[\"']?[A-Za-z0-9!@#$%^&*_+/=-]{8,}"
    ),
    # Only a URI that actually carries credentials. A bare mongodb://host:port is a
    # hostname, and source code building one from an f-string is neither. Real
    # transcripts are full of both, and counting them trains the reader to skip the line.
    "mongo_uri": re.compile(r"mongodb(?:\+srv)?://[^\s\"'/{}$<>]+:[^\s\"'/{}$<>@]+@"),
}

#: Personal-provider domains, kept separate from institutional addresses. An
#: lbl.gov address is usually already public in a paper or a repo; a Gmail address
#: attached to someone's name generally is not, and it is the one people mind.
PERSONAL_DOMAINS = r"(?:gmail|googlemail|yahoo|ymail|hotmail|outlook|live|icloud|me|aol|proton|protonmail|pm)\.(?:com|me)"

#: The lookbehind is not cosmetic, it is what keeps this linear. Without it the engine
#: restarts the local part at every character of a long run of word characters, and a
#: transcript is full of those: base64 blobs, hex digests, minified JSON. Measured on one
#: run of repeated characters, no lookbehind: 1.0s at 20k, 15.9s at 80k, 97s at 200k.
#: With it, and a bounded local part, 0.001s at all three. A real address is always
#: preceded by a space, quote or punctuation, so nothing real is lost.
LOCAL_PART = r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}"

PERSON_RES = {
    "email_personal": re.compile(rf"{LOCAL_PART}@{PERSONAL_DOMAINS}\b", re.IGNORECASE),
    "email_institutional": re.compile(
        LOCAL_PART + r"@(?!" + PERSONAL_DOMAINS + r"\b)[A-Za-z0-9.-]{1,255}\.(?:gov|edu|org|net|com|io|ac\.[a-z]{2})\b",
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


#: Read this much at a time. A transcript can be hundreds of megabytes, and holding
#: one in a single str costs that much again in the regex engine.
BLOCK_CHARS = 1_000_000
#: Carried from the end of one block to the start of the next, so a match straddling
#: the boundary is still seen. Longer than any pattern here can match.
OVERLAP_CHARS = 400


def read_blocks(path: Path):
    """Yield overlapping blocks of a file, bounding memory regardless of file size."""
    carry = ""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        while True:
            chunk = handle.read(BLOCK_CHARS)
            if not chunk:
                break
            yield carry + chunk
            carry = chunk[-OVERLAP_CHARS:]


def scan_text(text: str, ignore: set[str], counts=None, values=None, context=None, seen=None):
    """Count matches, collect distinct matched values, and keep a little context.

    Accepts the running tallies so a caller can feed it one block at a time. ``seen``
    holds (pattern, matched text, absolute-ish position) for spans inside the overlap
    region, so a match straddling a block boundary is counted once rather than twice.
    """
    counts = Counter() if counts is None else counts
    values = defaultdict(set) if values is None else values
    context = defaultdict(list) if context is None else context
    seen = set() if seen is None else seen
    for name, pattern in ALL.items():
        if name in ignore:
            continue
        for match in pattern.finditer(text):
            if name in SECRET_RES and MASKED_RE.search(match.group(0)):
                continue
            if match.start() < OVERLAP_CHARS:
                # This span may have been counted at the tail of the previous block.
                key = (name, match.group(0))
                if key in seen:
                    continue
                seen.add(key)
            counts[name] += 1
            # Distinct values only for the person patterns. Never for secrets: holding
            # a secret in memory to print a count of unique ones is not worth it, and
            # a caller with --detail would then have it written to disk.
            if name in PERSON_RES or name in NOTE_RES:
                values[name].add(match.group(0))
            if len(context[name]) < 5:
                start = max(0, match.start() - 90)
                context[name].append(text[start:match.end() + 50].replace("\n", " "))
    # Only spans near the end can reappear at the start of the next block.
    tail = len(text) - OVERLAP_CHARS
    for name, pattern in ALL.items():
        if name in ignore:
            continue
        for match in pattern.finditer(text, max(0, tail)):
            seen.add((name, match.group(0)))
    return counts, values, context, seen


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
            counts, values, context = Counter(), defaultdict(set), defaultdict(list)
            seen: set = set()
            for block in read_blocks(path):
                counts, values, context, seen = scan_text(
                    block, ignore, counts, values, context, seen
                )
        except OSError as exc:
            # stderr, and never suppressed by --quiet. stdout is the machine-readable
            # summary, and a file that could not be read is precisely the case where
            # silence would be read as "nothing in it".
            print(f"{path.name}: UNREADABLE ({exc.strerror})", file=sys.stderr)
            unreadable.append(path)
            continue
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
        # 0o600 at creation, not after. os.open applies the mode atomically, and the
        # umask can only clear bits, never add them.
        try:
            fd = os.open(args.detail, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            # The mode argument only applies when os.open creates the file. Reusing an
            # existing path keeps whatever permissions it already had, so a detail file
            # written twice could stay group or world readable while holding exactly the
            # material this script exists to find. fchmod the descriptor we hold.
            os.fchmod(fd, 0o600)
        except OSError as exc:
            print(f"cannot write {args.detail}: {exc.strerror}", file=sys.stderr)
            return 2
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
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
