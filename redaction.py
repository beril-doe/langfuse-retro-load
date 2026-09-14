"""Detection and redaction of sensitive spans, as a pure function.

No file handling, no Langfuse, no argparse, no logging, no clock. Text in, text out.
That is the whole point: the same logic has to run at three places that share nothing
else. See https://github.com/beril-doe/langfuse-retro-load/issues/13.

    Pre-LLM      a hook, on tool output, before the model ever sees it
    Pre-bulk     this repo's loader, on each turn, before emission
    Real-time    a wrapping OpenTelemetry span exporter, on span attributes

Only the first prevents the model provider from receiving anything. The other two
control our own Langfuse copy, and deleting a trace does nothing about what the
provider already has.

Three properties this module guarantees, each with a test that would fail without it:

**It never raises.** `redact()` on any `str` returns a `str` and a list. A real-time
exporter that raises either kills a span or, worse, is wrapped in a try/except that
exports the span unredacted, which defeats the only thing it was there for.

**It is idempotent.** `redact(redact(t)[0])[0] == redact(t)[0]`. A turn can pass
through more than one filter point, and a second pass must not redact the first pass's
placeholders into placeholders of placeholders.

**The records it returns are safe to write down.** A record carries a pattern name, a
span, a length and a keyed fingerprint. It never carries the matched text. The whole
reason to produce a record is so a person can review what a load will change before it
is sent, and a review artifact that quotes the secrets is the problem it was avoiding.

The fingerprint is HMAC-SHA256 under a per-run key, truncated. Equal fingerprints mean
the same value appeared twice, which is what makes a review useful ("this one token is
in 41 turns" reads very differently from 41 unrelated findings). Because the key is
random per run and never stored, the fingerprint cannot be brute-forced back to a
low-entropy secret the way a bare hash can. Pass `key=` to make a run reproducible; do
not use a fixed key on anything that leaves the machine.

What this module does not do: decide policy. It reports and rewrites. Whether a turn
with an unrewritable finding is dropped, sent, or held for review belongs to the caller,
because the right answer is different at each of the three points.
"""
from __future__ import annotations

import bisect
import hmac
import os
import re
from dataclasses import dataclass, field
from typing import TypeVar, overload

_T = TypeVar("_T")

SECRET = "secret"
PERSON = "person"
ADVISORY = "advisory"

#: Patterns, and what kind of thing each one finds. Kept in sync with VALUE_RES in
#: evalome/collecting.py (coscientist-bench) and with scan_transcript.py, which should
#: import from here rather than keep its own copy.
#:
#: `(?<![A-Za-z0-9])` rather than `\b`: a token embedded in a filename sits behind an
#: underscore, and `\b` does not treat that as a boundary at all.
PATTERNS: dict[str, re.Pattern[str]] = {
    # Case-insensitive: the HTTP Authorization scheme token is, per RFC 9110, and a
    # client sending "bearer" lowercase was passing through unredacted.
    "bearer_header": re.compile(r"(?i:bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    "openai_style": re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}"),
    "github_pat": re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}"),
    "aws_access_key_id": re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    "google_oauth": re.compile(r"(?<![A-Za-z0-9])ya29\.[A-Za-z0-9_-]{20,}"),
    "google_api_key": re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    # Detection only. The marker is all a pattern can reliably find; where the key ends is
    # decided by _span_for below, not here. An earlier version tried to match the body and
    # the END marker with a bounded repeat, and the bound then became the defect: a key
    # longer than the bound matched its prefix, and redact() replaced the prefix and left
    # the rest of the key in the output while reporting that the block had been redacted.
    "private_key_block": re.compile(r"(?:-----)?BEGIN [A-Z ]*PRIVATE KEY(?:-----)?"),
    # Three segments, not two. Stopping at the dot after the payload left the signature
    # in the rewritten text, and the signature is the credential material: the header and
    # payload are base64 of public JSON, and it is the signature that makes the token
    # usable. The last segment is `*` rather than `+` because alg=none tokens end in a dot.
    "jwt": re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"),
    "slack_token": re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    # The escaped-quote alternatives are load-bearing. A transcript is JSONL, so a tool
    # result containing JSON arrives as \"token\":\"...\", and a nested payload as
    # \\"token\\":\\"...\\". Without them a scanner reading the raw file misses a
    # credential that retro_load.py then decodes and uploads.
    #
    # This is also the pattern that caught the one credential gitleaks could not see.
    # gitleaks' generic-api-key rule is entropy-gated at about 3.5; the three real
    # credentials in the September corpus scored 4.351, 3.531 and 3.328, and the last
    # of those is a 32-character JUPYTERHUB_API_TOKEN that gitleaks reported in no
    # form or file extension. Keyword anchoring has the opposite failure: it finds
    # anything after TOKEN= and nothing nobody wrote a rule for. See
    # https://github.com/beril-doe/langfuse-retro-load/issues/10.
    "keyed_value": re.compile(
        r"(?i)(?:token|secret|password|passwd|api[ _-]?key|credential)"
        r"(?:\\{1,2}[\"'])?[\"'*`\t ]*[:=][\t ]*(?:\\{1,2}[\"'])?"
        r"[\"']?[A-Za-z0-9!@#$%^&*_+/=-]{8,}"
    ),
    # Only a URI that actually carries credentials. A bare mongodb://host:port is a
    # hostname, and source code building one from an f-string is neither.
    "mongo_uri": re.compile(r"mongodb(?:\+srv)?://[^\s\"'/{}$<>]+:[^\s\"'/{}$<>@]+@"),
    "email_personal": None,        # filled in below, they need PERSONAL_DOMAINS
    "email_institutional": None,
    "name_beside_email": re.compile(
        r"(?i)(?:display_?name|full_?name|real_?name|\bname)[\"'\s]*[:=][\"'\s]*[^\"'\n,}]{2,60}"
        r"[\"'\s,}]{1,8}[\"'\s]*(?:e?mail|email_address)[\"'\s]*[:=]",
    ),
    "phone_us": re.compile(r"(?<!\d)\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"),
    "orcid": re.compile(r"(?<!\d)\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b"),
}

#: Personal-provider domains, kept separate from institutional addresses. An lbl.gov
#: address is usually already public in a paper or a repo; a Gmail address attached to
#: someone's name generally is not, and it is the one people mind.
PERSONAL_DOMAINS = (r"(?:gmail|googlemail|yahoo|ymail|hotmail|outlook|live|icloud|me"
                    r"|aol|proton|protonmail|pm)\.(?:com|me)")

#: The lookbehind is not cosmetic, it is what keeps this linear. Without it the engine
#: restarts the local part at every character of a long run of word characters, and a
#: transcript is full of those: base64 blobs, hex digests, minified JSON. Measured on one
#: run of repeated characters with no lookbehind: 1.0s at 20k, 15.9s at 80k, 97s at 200k.
#: With it, and a bounded local part, 0.001s at all three.
LOCAL_PART = r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}"

PATTERNS["email_personal"] = re.compile(rf"{LOCAL_PART}@{PERSONAL_DOMAINS}\b", re.IGNORECASE)
PATTERNS["email_institutional"] = re.compile(
    LOCAL_PART + r"@(?!" + PERSONAL_DOMAINS + r"\b)[A-Za-z0-9.-]{1,255}"
    r"\.(?:gov|edu|org|net|com|io|ac\.[a-z]{2})\b",
    re.IGNORECASE,
)

CATEGORY: dict[str, str] = {
    "bearer_header": SECRET, "openai_style": SECRET, "github_pat": SECRET,
    "aws_access_key_id": SECRET, "google_oauth": SECRET, "google_api_key": SECRET,
    "private_key_block": SECRET, "jwt": SECRET, "slack_token": SECRET,
    "keyed_value": SECRET, "mongo_uri": SECRET,
    "email_personal": PERSON, "email_institutional": PERSON,
    "name_beside_email": PERSON, "phone_us": PERSON,
    # Public by design. Reported so a reader knows the turn names someone, never
    # rewritten: an ORCID is what a person publishes in order to be identified.
    "orcid": ADVISORY,
}

#: Rewrite these categories, report the rest. A caller can pass its own set; at the
#: pre-LLM point someone may well want ADVISORY in it too.
DEFAULT_REDACT = frozenset({SECRET, PERSON})

#: A value that is already masked is not a secret. `gh auth status` prints
#: "Token: gho_************", and a transcript full of tool output contains a lot of
#: that. Counting it buries the one real finding under seventy harmless ones, which is
#: how a check stops being read. Applied only to secret patterns: a masked email is
#: still worth a look, because the mask may not cover the whole address.
MASKED_RE = re.compile(r"\*{4,}|x{8,}|•{4,}|\[REDACTED[^\]]*\]", re.IGNORECASE)

#: Leading key name and separator, so "token: " is not mistaken for secret material
#: left over after the mask. The separator is required, not optional. Written with `*`
#: it ate the first 32 characters of any value with no separator in it, so `sk-abcdef...`
#: came back three characters long and every unmasked key read as masked. Four of the
#: pattern tests caught that immediately, which is the only reason it is not in the
#: commit above this one.
_KEY_PREFIX_RE = re.compile(r"""(?i)^[a-z0-9_-]{0,32}["'\s:=]+""")

#: Shortest run of characters that could be a real secret. Every pattern here requires
#: at least eight, so anything shorter surviving a mask is a prefix, not a credential.
_MIN_SECRET_CHARS = 8


def is_masked(value: str) -> bool:
    """Whether a value looks like it has already been masked. Advisory only.

    **This does not decide whether anything is redacted, and it must not.** It used to. Two
    rounds of review found two different ways for it to be wrong, and each one meant a real
    secret was dropped from the findings and left in the text: first any run of eight `x`
    characters anywhere in the value, then a value made entirely of the mask character, where
    `sk-xxxxxxxxxxxxxxxx` reduces to `sk-` and reads as too short to be a credential.

    Patching the predicate a third time would be treating a design problem as a wording
    problem. A predicate that can be wrong is not allowed to stand between a secret and its
    redaction, so this now only sets `Finding.masked`. Secrets are redacted either way, and a
    report that wants to keep `gho_************` out of a reviewer's way filters on the flag.
    Being wrong now costs a redacted asterisk run, not a leaked credential.
    """
    remainder = _KEY_PREFIX_RE.sub("", MASKED_RE.sub("", value))
    return len(remainder) < _MIN_SECRET_CHARS

#: Where a secret value ends, in every serialization these transcripts carry: bare shell
#: output, JSON, JSON embedded in JSON with escaped quotes, YAML, and prose.
#:
#: This exists because three separate defects were all one defect. A pattern was being asked
#: to say where a secret ends, and it is not able to: `keyed_value` stopped at the first
#: character outside its class, so `token=abcdefghijklmnop.qrstuvwxyz` lost its tail to the
#: dot; the private-key pattern stopped at a length bound. Both reported a finding and left
#: credential material in the output, which is worse than reporting nothing.
#:
#: So the match now only anchors detection, and the span that gets replaced runs to the next
#: character that cannot be inside a value. An imprecise pattern over-redacts instead of
#: under-redacting. Over-redaction costs a reader some context and is visible in the record;
#: under-redaction ships the secret and says it did not.
_VALUE_TERMINATORS = frozenset(' \t\r\n"\'\\,}]<>|')

#: A private key is the exception: its body contains newlines, so the terminator set above
#: would cut it at the first one. It ends at its end marker, or failing that at the end of
#: whatever value encloses it.
_PEM_END = re.compile(r"(?:-----)?END [A-Z ]*PRIVATE KEY(?:-----)?")
_PEM_TERMINATORS = frozenset('"\'\\')


#: Precompiled terminator scans. Built once per call rather than per candidate.
_VALUE_TERMINATOR_RE = re.compile("[" + re.escape("".join(sorted(_VALUE_TERMINATORS))) + "]")
_PEM_TERMINATOR_RE = re.compile("[" + re.escape("".join(sorted(_PEM_TERMINATORS))) + "]")


class _Boundaries:
    """Where every value could end, worked out once for a whole input.

    The first version of the widening walked right from each candidate one character at a
    time. That is linear per candidate and there is a candidate per match, so it is quadratic
    in the number of matches, and the pathological inputs are ordinary: `token=a;token=b;...`
    has no terminator between fields, and prose containing many unterminated key markers has
    none either. Measured on this branch before the fix, with time roughly quadrupling each
    time the input doubled:

        200 semicolon-separated fields, 4,199 chars    0.014s
        1600 fields,                   33,599 chars    0.846s
        400 unterminated key markers,  11,889 chars    0.105s

    This is the same class of defect as the one fixed on 2026-09-10, where a missing lookbehind
    took a pattern to 97 seconds on 200KB, and the design change today put it back somewhere
    else. The performance test in place at the time could not see it: it uses one long run of a
    single character, which produces exactly one candidate.

    Each terminator position is now found once and the widening is a binary search.
    """

    __slots__ = ("value_ends", "pem_ends", "pem_markers", "length")

    def __init__(self, text: str):
        self.length = len(text)
        self.value_ends = [m.start() for m in _VALUE_TERMINATOR_RE.finditer(text)]
        self.pem_ends = [m.start() for m in _PEM_TERMINATOR_RE.finditer(text)]
        self.pem_markers = [m.end() for m in _PEM_END.finditer(text)]

    def _first_at_or_after(self, positions: list[int], index: int) -> int:
        i = bisect.bisect_left(positions, index)
        return positions[i] if i < len(positions) else self.length

    def span_for(self, pattern: str, start: int, end: int) -> tuple[int, int]:
        """Widen a match to the whole value it sits in. Never narrows it."""
        if pattern == "private_key_block":
            i = bisect.bisect_left(self.pem_markers, end)
            if i < len(self.pem_markers):
                return start, self.pem_markers[i]
            return start, self._first_at_or_after(self.pem_ends, end)
        return start, self._first_at_or_after(self.value_ends, end)


#: What this module writes in place of a match, and how it recognises its own work on a
#: second pass. The two must stay in step, which is what test_idempotent checks.
PLACEHOLDER_RE = re.compile(r"\[REDACTED:[a-z_]+:[0-9a-f]{8}\]")


def _placeholder(pattern: str, fingerprint: str) -> str:
    return f"[REDACTED:{pattern}:{fingerprint}]"


@dataclass(frozen=True)
class Finding:
    """One match, located in the text that was passed in.

    Carries no matched text. `start` and `end` index the *input*, not the redacted
    output, which is what makes a record comparable across a re-run of the same input.
    """
    pattern: str
    category: str
    start: int
    end: int
    length: int
    fingerprint: str
    #: The matched text already looked masked. Advisory: it is redacted regardless.
    masked: bool = False

    @property
    def placeholder(self) -> str:
        return _placeholder(self.pattern, self.fingerprint)


def new_key() -> bytes:
    """A fresh fingerprint key. Random, never stored, never written to a record."""
    return os.urandom(32)


def fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode("utf-8", "replace"), "sha256").hexdigest()[:8]


def _protected(text: str) -> list[tuple[int, int]]:
    """Spans of this module's own placeholders, which later passes must leave alone."""
    return [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]


def _inside(span: tuple[int, int], regions: list[tuple[int, int]]) -> bool:
    return any(a <= span[0] and span[1] <= b for a, b in regions)


def _overlaps(span: tuple[int, int], regions: list[tuple[int, int]]) -> bool:
    return any(span[0] < b and a < span[1] for a, b in regions)


#: Which finding wins when two overlap. A secret must never lose to a person pattern:
#: `name_beside_email` and `keyed_value` both match a directory dump that also holds a
#: token, and rewriting only the name would leave the token in place while the record
#: said the turn had been redacted.
_RANK = {SECRET: 0, PERSON: 1, ADVISORY: 2}


def detect(text: str, *, key: bytes | None = None) -> list[Finding]:
    """Every non-overlapping finding, in order of position. Pure, and never raises."""
    if not isinstance(text, str) or not text:
        return []
    key = new_key() if key is None else key
    protected = _protected(text)
    boundaries = _Boundaries(text)

    candidates = []
    for name, pattern in PATTERNS.items():
        category = CATEGORY[name]
        for match in pattern.finditer(text):
            span = (match.start(), match.end())
            if span[0] == span[1] or _inside(span, protected):
                continue
            if category is SECRET:
                span = boundaries.span_for(name, span[0], span[1])
                if _inside(span, protected):
                    continue
            value = text[span[0]:span[1]]
            candidates.append((_RANK[category], -(span[1] - span[0]), span[0], name, value))

    # Resolve overlaps: highest-ranked category first, then the longest match, then the
    # earliest, then the name, so the result does not depend on dict iteration order.
    candidates.sort()
    taken: list[tuple[int, int]] = []
    findings = []
    for _rank, neg_len, start, name, value in candidates:
        span = (start, start - neg_len)
        if _overlaps(span, taken):
            continue
        taken.append(span)
        findings.append(Finding(pattern=name, category=CATEGORY[name], start=span[0],
                                end=span[1], length=span[1] - span[0],
                                fingerprint=fingerprint(value, key),
                                masked=CATEGORY[name] is SECRET and is_masked(value)))
    findings.sort(key=lambda f: f.start)
    return findings


@dataclass(frozen=True, repr=False)
class Redactor:
    """One key, held for a run, so fingerprints are comparable across calls.

    The adapters process one turn at a time, and `redact()` on its own mints a fresh key per
    call, which makes the same credential in two turns look like two unrelated findings. That
    defeats the reason the fingerprint exists. Build one of these per run and use it for every
    turn, and keep it out of anything written down.

        r = Redactor()
        for turn in turns:
            clean, findings = r.redact(turn)
    """

    key: bytes = field(default_factory=new_key)

    def __repr__(self) -> str:
        # The generated repr prints the key. Anything that logs a Redactor, or puts one in a
        # traceback, would then publish the value that makes every fingerprint in the run
        # reversible. The whole reason the key is random and unstored is to stop that.
        return "Redactor(key=<hidden>)"

    def detect(self, text: str) -> list[Finding]:
        return detect(text, key=self.key)

    def redact(self, text, *, categories: frozenset[str] = DEFAULT_REDACT):
        return redact(text, categories=categories, key=self.key)


@overload
def redact(text: str, *, categories: frozenset[str] = ...,
           key: bytes | None = ...) -> tuple[str, list[Finding]]: ...
@overload
def redact(text: _T, *, categories: frozenset[str] = ...,
           key: bytes | None = ...) -> tuple[_T, list[Finding]]: ...
def redact(text, *, categories: frozenset[str] = DEFAULT_REDACT,
           key: bytes | None = None):
    """Rewrite matched spans and return the new text with a record of every finding.

    The returned list includes findings that were *not* rewritten, because a reviewer
    needs to see those too. Compare `f.category in categories` to tell them apart.

    Never raises on a `str`. A non-`str` is returned unchanged with no findings rather
    than coerced: at the real-time point the input is a span attribute, which can be a
    bool or an int, and guessing at a conversion there is how a filter starts changing
    data it was not asked to touch.
    """
    if not isinstance(text, str) or not text:
        return text, []
    key = new_key() if key is None else key
    findings = detect(text, key=key)
    out, cursor = [], 0
    for f in findings:
        if f.category not in categories:
            continue
        out.append(text[cursor:f.start])
        out.append(f.placeholder)
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), findings
