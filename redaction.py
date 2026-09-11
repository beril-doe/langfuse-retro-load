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

import hmac
import os
import re
from dataclasses import dataclass

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
    "bearer_header": re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    "openai_style": re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}"),
    "github_pat": re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}"),
    "aws_access_key_id": re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    "google_oauth": re.compile(r"(?<![A-Za-z0-9])ya29\.[A-Za-z0-9_-]{20,}"),
    "google_api_key": re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    # The whole block, not the marker. As a detector, matching "BEGIN RSA PRIVATE KEY"
    # was enough to raise a finding. As a redactor it is worse than useless: it rewrites
    # the marker and leaves the base64 body, so the key is still loadable and the record
    # says the turn was redacted. The body class stops at the first "-", which is the
    # start of the END marker, and at the first quote, which is where a JSON string ends,
    # so an unterminated block stops at the end of its value rather than eating the file.
    "private_key_block": re.compile(
        r"(?:-----)?BEGIN [A-Z ]*PRIVATE KEY(?:-----)?"
        r"(?:[A-Za-z0-9+/=\s]|\\[rn]){0,10000}"
        r"(?:(?:-----)?END [A-Z ]*PRIVATE KEY(?:-----)?)?"
    ),
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
    """True when what survives removing the mask is too short to be a credential.

    Not `MASKED_RE.search(value)`, which was the first version and was wrong in the
    dangerous direction. That suppressed a finding whenever the value contained a run of
    eight x characters anywhere, so `token=xxxxxxxxREALSECRET123` was dropped from the
    findings and left in the text. Removing the masked runs and measuring what is left
    keeps `gho_************` suppressed and reports that one.
    """
    remainder = _KEY_PREFIX_RE.sub("", MASKED_RE.sub("", value))
    return len(remainder) < _MIN_SECRET_CHARS

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

    candidates = []
    for name, pattern in PATTERNS.items():
        category = CATEGORY[name]
        for match in pattern.finditer(text):
            span = (match.start(), match.end())
            if span[0] == span[1] or _inside(span, protected):
                continue
            value = match.group(0)
            if category is SECRET and is_masked(value):
                continue
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
                                fingerprint=fingerprint(value, key)))
    findings.sort(key=lambda f: f.start)
    return findings


def redact(text: str, *, categories: frozenset[str] = DEFAULT_REDACT,
           key: bytes | None = None) -> tuple[str, list[Finding]]:
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
