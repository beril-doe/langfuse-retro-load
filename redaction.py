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
    #
    # Only the value is redacted, named by the `value` group, so a reader can still see which
    # variable was hidden: `KBASE_AUTH_TOKEN=...` used to become `KBASE_AUTH_[REDACTED...]`
    # (https://github.com/beril-doe/langfuse-retro-load/issues/23).
    "keyed_value": re.compile(
        r"(?i)(?:token|secret|password|passwd|api[ _-]?key|credential)"
        r"(?:\\{1,2}[\"'])?[\"'*`\t ]*[:=][\t ]*(?:\\{1,2}[\"'])?"
        r"[\"']?(?P<value>[A-Za-z0-9!@#$%^&*_+/=-]{8,})"
    ),
    # Basic and Token schemes, which `bearer_header` does not cover. Taken from the live hook
    # merged in https://github.com/beril-doe/BERIL-research-observatory/pull/420, so the two
    # filter points agree on headers.
    "auth_header": re.compile(
        r"(?i)\b(?:proxy-)?authorization(?:\\{1,2})?[\"']?[ \t]*[:=][ \t]*(?:\\{1,2})?[\"']?"
        r"(?:basic|token)[ \t]+"
        r"(?P<value>[A-Za-z0-9._~+/=-]{8,})"
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
    # A home directory names the account that owns it, and on the pod an account name is
    # a person. `retro_load.py` already substitutes a synthetic transcript path for this
    # reason, since the frozen corpus is symlinked out of someone else's storage and the
    # real path carries their username, but the same paths turn up in `cwd`, in shell
    # output and in tracebacks, where nothing substitutes anything. Reported, never
    # rewritten: a transcript is mostly paths, and rewriting them all would leave a trace
    # nobody can follow in order to remove a name that is on the trace's own user_id.
    # The pointer in the inventory is there for a caller that wants to rewrite one.
    "account_path": re.compile(
        r"(?<![A-Za-z0-9])/(?:home|Users|global_share)/[A-Za-z0-9][A-Za-z0-9._-]{1,31}"),
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

#: Local parts that are a role or a service, never a person. `git@github.com` is the one
#: that actually bit: it is the host half of every SSH remote URL, it has the exact shape of
#: an institutional address, and redacting it turned a working instruction inside a trace
#: into an unfollowable one. Found 2026-09-18 by reading a loaded trace, five occurrences of
#: one value in a single turn. The cost of the mistake is not privacy, it is that the reader
#: of a redacted trace cannot tell a real removal from a mangled command, which is how a
#: redactor stops being trusted.
ROLE_LOCAL_PARTS = (r"(?:git|noreply|no-reply|donotreply|do-not-reply|root|postmaster"
                    r"|hostmaster|webmaster|mailer-daemon|abuse|admin|support|info"
                    r"|notifications|bounce|nobody|daemon)")

PATTERNS["email_personal"] = re.compile(rf"{LOCAL_PART}@{PERSONAL_DOMAINS}\b", re.IGNORECASE)
PATTERNS["email_institutional"] = re.compile(
    LOCAL_PART + r"@(?!" + PERSONAL_DOMAINS + r"\b)[A-Za-z0-9.-]{1,255}"
    r"\.(?:gov|edu|org|net|com|io|ac\.[a-z]{2})\b",
    re.IGNORECASE,
)

#: Domains that cannot belong to a person. RFC 2606 reserves the first four for documentation
#: and testing, so an address there is an example by definition. GitHub's noreply domain is a
#: per-account forwarding address that GitHub publishes in every commit it authors.
RESERVED_DOMAINS = re.compile(
    r"(?i)@(?:[A-Za-z0-9.-]+\.)?(?:example\.(?:com|org|net)|test|invalid|localhost"
    r"|users\.noreply\.github\.com)$")


def _is_role_address(text: str, start: int, end: int) -> bool:
    """Whether a match is a service address rather than a person's.

    Two shapes, checked on the matched text rather than baked into the pattern, because a
    negative lookbehind for a variable-length local part is not expressible and a second
    alternation makes the pattern unreadable. An address whose local part is a role, and the
    `user@host:path` shape of an SSH remote, which is a URL and not an address at all.
    """
    value = text[start:end]
    local = value.split("@", 1)[0]
    if re.fullmatch(ROLE_LOCAL_PARTS, local, re.IGNORECASE):
        return True
    if RESERVED_DOMAINS.search(value):
        return True
    # `git@github.com:owner/repo.git`: a colon then a path, immediately after the host.
    return bool(re.match(r":[A-Za-z0-9._~-]+/", text[end:end + 40]))

#: A value that only names another value: `$CBORG_API_KEY`, `${GITHUB_TOKEN}`,
#: `<your-token-here>`, `{{ secrets.TOKEN }}`. Redacting one hides where a credential came
#: from and hides nothing secret (https://github.com/beril-doe/langfuse-retro-load/issues/23).
REFERENCE_RE = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}"
    r"|\{\{\s*[A-Za-z_][\w.]*\s*\}\}")

#: A placeholder in angle brackets is words only: `<your-token-here>`, `<API KEY>`. Anything
#: with a digit or other symbol could be a real value someone wrapped in brackets, such as
#: `<ghp_...>`, so it is not exempt (second-to-last Copilot round on
#: https://github.com/beril-doe/langfuse-retro-load/pull/25).
_PLACEHOLDER_RE = re.compile(r"<[A-Za-z][A-Za-z _-]{0,78}[A-Za-z]>")


#: A value that is code rather than data: a name, or names joined by dots, followed by a
#: call or an index. `file_token = env_vars.get("KBASE_AUTH_TOKEN", "")` reads a token and
#: holds none, but `keyed_value` saw `token =` and masked `env_vars.get(`. Found reviewing
#: the first backfill plan on the pod, 2026-09-24. A bare dotted chain such as
#: `settings.secret_key` is not exempt: `abcdefghijklmnop.qrstuvwxyz` has the same shape and
#: can be a real value.
#: Only a complete expression counts: the call's parentheses must close, and an index must
#: hold a quoted key, a number or a name and then close. `token=abcdefghijklmnop[rest` or
#: `token=abcdefghijklmnop(rest` stay masked, since a value that merely starts like code could
#: be a credential containing a bracket (first Copilot review of
#: https://github.com/beril-doe/langfuse-retro-load/pull/42).
_CODE_EXPRESSION_RE = re.compile(
    r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
    r"(?:\((?:[^()\"'\n]|\"[^\"\n]*\"|'[^'\n]*')*\)"
    r"|\[(?:\"[^\"\n]*\"|'[^'\n]*'|\d+|[A-Za-z_]\w*)\])")


_LITERAL_RE = re.compile(r"\"([^\"\n]*)\"|'([^'\n]*)'")
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def code_literals(text: str, start: int, end: int) -> list[tuple[int, int]] | None:
    """For a keyword-anchored value text[start:end]: None when it is not a complete one-line
    call or index covering the whole value. Otherwise the spans of the string literals
    inside it that could be credentials, which is an empty list for code that only names
    things, such as `env_vars.get("KBASE_AUTH_TOKEN", "")`.

    A quoted value is data, whatever its shape: `token="abcdefghijklmnop()"` stays masked.
    A call split across lines is still masked as before, which is the safe direction, and
    is left out of scope (second Copilot review of
    https://github.com/beril-doe/langfuse-retro-load/pull/42).

    Masking the literal rather than the call closes a gap that predates the exemption: for
    `password = get_secret("hunter2hunter2")` the pattern used to mask only `get_secret(`
    and send the argument (third Copilot review of the same pull request).
    """
    before = start
    while before > 0 and text[before - 1] in " \t":
        before -= 1
    if (before > 0 and text[before - 1] in "\"'`") or text[start:start + 1] in "\"'`":
        return None
    match = _CODE_EXPRESSION_RE.match(text, start)
    if not match or match.end() < end:
        return None
    # Literals are checked to the end of the line, not only inside the call, so a value
    # joined on after it is still found: `get_secret("PASSWORD") + "hunter2hunter2"`
    # (fourth Copilot review of the same pull request).
    line_end = text.find("\n", match.end())
    line_end = len(text) if line_end == -1 else line_end
    spans = []
    for literal in _LITERAL_RE.finditer(text, match.start(), line_end):
        group = 1 if literal.group(1) is not None else 2
        value = literal.group(group)
        if len(value) >= 8 and not _ENV_NAME_RE.fullmatch(value):
            spans.append(literal.span(group))
    return spans


def is_reference(value: str) -> bool:
    """True when the whole value, quotes and whitespace aside, names another value.

    A variable or template reference, or a words-only placeholder that nothing in PATTERNS
    recognises as a secret.
    """
    bare = value.strip().strip("\"'")
    if REFERENCE_RE.fullmatch(bare):
        return True
    if _PLACEHOLDER_RE.fullmatch(bare):
        return not any(CATEGORY.get(name) == SECRET and pattern is not None
                       and pattern.search(bare[1:-1]) for name, pattern in PATTERNS.items())
    return False


CATEGORY: dict[str, str] = {
    "bearer_header": SECRET, "openai_style": SECRET, "github_pat": SECRET,
    "aws_access_key_id": SECRET, "google_oauth": SECRET, "google_api_key": SECRET,
    "private_key_block": SECRET, "jwt": SECRET, "slack_token": SECRET,
    "keyed_value": SECRET, "auth_header": SECRET, "mongo_uri": SECRET,
    "email_personal": PERSON, "email_institutional": PERSON,
    "name_beside_email": PERSON, "phone_us": PERSON,
    # Public by design. Reported so a reader knows the turn names someone, never
    # rewritten: an ORCID is what a person publishes in order to be identified.
    "orcid": ADVISORY, "account_path": ADVISORY,
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
_VALUE_TERMINATORS = frozenset(' \t\r\n"\'\\,;}]<>|')

#: A private key is the exception: its body contains newlines, so the terminator set above
#: would cut it at the first one. It ends at its end marker, or failing that at the end of
#: whatever value encloses it.
_PEM_END = re.compile(r"(?:-----)?END [A-Z ]*PRIVATE KEY(?:-----)?")
_PEM_TERMINATORS = frozenset('"\'\\')


#: Precompiled terminator scans. Built once per call rather than per candidate.
#: A backslash ends a value only where it escapes a quote: `\\"` inside a JSONL line, or
#: `\\\\"` one level deeper, which is the case the terminator exists for. A bare backslash is
#: ordinary value content. Treating every backslash as the end left the tail of
#: `password=abcdefgh\\\\ijklmnop` in the output while reporting the value redacted, the
#: backslash thread on https://github.com/beril-doe/langfuse-retro-load/pull/20.
_VALUE_TERMINATOR_RE = re.compile(
    "[" + re.escape("".join(sorted(_VALUE_TERMINATORS - {"\\"}))) + "]" + r"|\\+(?=[\"'])")
#: Same backslash rule as values: raw JSONL writes a key's line breaks as `\\n`, and ending on
#: that first escape left the rest of the key in the output.
_PEM_TERMINATOR_RE = re.compile(
    "[" + re.escape("".join(sorted(_PEM_TERMINATORS - {"\\"}))) + "]" + r"|\\+(?=[\"'])")


def _through_closing_quote(text: str, span: tuple[int, int]) -> tuple[int, int]:
    """Widen a quoted value to its closing quote, so a comma or space inside it is content.

    `password="abcdefgh,ijklmnop"` used to end at the comma and leave `,ijklmnop` behind. Only
    ever widens: with no closing quote the value runs to the end of the text. A closing quote
    escaped as `\\"` inside a JSONL line ends before its backslashes, like the value rule.
    """
    start, end = span
    quote = text[start - 1] if start > 0 else ""
    if quote not in ("\"", "'"):
        return span
    # The opening quote's escape level decides which quote closes it: a bare quote closes a
    # bare one, and `\\"` closes `\\"` in JSON nested inside a JSONL line. A quote escaped
    # differently is content, so `password="abc\\"def"` keeps going past `\\"`.
    level = _backslashes_before(text, start - 1)
    close = text.find(quote, start)
    while close != -1 and _backslashes_before(text, close) != level:
        close = text.find(quote, close + 1)
    if close == -1:
        # No matching close: the delimiter is unknown, so the value runs to the end of the
        # text. Over-redacting a field beats leaving the rest of a credential behind.
        return start, len(text)
    return start, max(end, close - level)


def _backslashes_before(text: str, index: int) -> int:
    count = 0
    while index - count - 1 >= 0 and text[index - count - 1] == "\\":
        count += 1
    return count


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
            # The earlier of the key's END marker and the end of the value it sits in, so an
            # unterminated key cannot reach an END marker in a later field across a quote.
            value_end = self._first_at_or_after(self.pem_ends, end)
            i = bisect.bisect_left(self.pem_markers, end)
            if i < len(self.pem_markers) and self.pem_markers[i] <= value_end:
                return start, self.pem_markers[i]
            return start, value_end
        return start, self._first_at_or_after(self.value_ends, end)


#: What this module writes in place of a match, and how it recognises its own work on a
#: second pass. The two must stay in step, which is what test_idempotent checks.
#: Only this module's own pattern names, so a value that merely looks like a placeholder,
#: such as `[REDACTED:made_up:deadbeef]`, is still screened. `credential_key` is written by
#: the key-based whole-value rule further down, and `gitleaks` by plan.py for gitleaks' matches.
PLACEHOLDER_RE = re.compile(
    r"\[REDACTED:(?:" + "|".join(sorted(re.escape(n) for n in [*PATTERNS, "credential_key",
                                                                 "gitleaks"]))
    + r"):[0-9a-f]{8}\]")


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


def _overlaps_sorted(span: tuple[int, int], starts: list[int],
                     regions: list[tuple[int, int]]) -> bool:
    """_overlaps for non-overlapping regions sorted by start: only the two neighbours of the
    insertion point can collide."""
    i = bisect.bisect_left(starts, span[0])
    return any(span[0] < b and a < span[1]
               for a, b in regions[max(0, i - 1):i + 1])


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
        has_value = "value" in pattern.groupindex
        for match in pattern.finditer(text):
            span = match.span("value") if has_value else (match.start(), match.end())
            if span[0] == span[1] or _inside(span, protected):
                continue
            if category is SECRET:
                span = boundaries.span_for(name, span[0], span[1])
                if has_value:
                    span = _through_closing_quote(text, span)
                if _inside(span, protected):
                    continue
            if name in ("email_institutional", "email_personal") and _is_role_address(text, *span):
                continue
            value = text[span[0]:span[1]]
            if has_value and is_reference(value):
                continue
            if name == "keyed_value":
                literals = code_literals(text, span[0], span[1])
                if literals is not None:
                    for lo, hi in literals:
                        if not _inside((lo, hi), protected):
                            candidates.append((_RANK[category], -(hi - lo), lo, name,
                                               text[lo:hi]))
                    continue
            candidates.append((_RANK[category], -(span[1] - span[0]), span[0], name, value))

    # Resolve overlaps: highest-ranked category first, then the longest match, then the
    # earliest, then the name, so the result does not depend on dict iteration order.
    candidates.sort()
    # Accepted spans never overlap, so kept sorted by start, a new span can only collide
    # with its neighbours. Checking every accepted span made many small findings quadratic.
    taken_starts: list[int] = []
    taken: list[tuple[int, int]] = []
    findings = []
    for _rank, neg_len, start, name, value in candidates:
        span = (start, start - neg_len)
        if _overlaps_sorted(span, taken_starts, taken):
            continue
        position = bisect.bisect_left(taken_starts, span[0])
        taken_starts.insert(position, span[0])
        taken.insert(position, span)
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


# ----------------------------------------------------------------------------------------
# Value-level and structure-level entry points.
#
# Everything above treats its input as a document and has to work out where each value
# ends. Three rounds of review found three inputs where that was wrong, each in the same
# direction: a finding was reported while credential material stayed in the output. The
# span-widening in `_Boundaries` fixed the two that had a terminator to find, and two
# review threads are still open against it because some inputs have none: a backslash
# inside a keyed value, and a `BEGIN ... PRIVATE KEY` in unquoted prose with no `END`,
# which widens to the end of the input.
#
# The entry points below remove the question instead of answering it again. A transcript
# is JSONL, so something has already parsed it and knows exactly where every value starts
# and stops. `redact_value` is told "this string is one value" and replaces the whole of
# it. `redact_tree` walks a parsed structure and calls the right one per leaf.
#
# What that buys, stated as measured on 2026-09-18 rather than as the review thread frames
# it: the widening is bounded by one JSON value. It is not eliminated. An unterminated
# private key inside a `stdout` value still takes the rest of that value, and an asset read
# as one string is one value, so nothing is bounded there at all. The thread's own worst
# case, running to the end of the input, needs text with no quote after the marker: scanned
# flat, a raw .jsonl stops at the next `"`, which is usually still inside the same record.
# ----------------------------------------------------------------------------------------

#: A finding that comes from the key a value sits under rather than from the value's own
#: shape. `{"KBASE_AUTH_TOKEN": "s3cret"}` carries a credential that no pattern here
#: matches, because six characters is shorter than any of them accept, and that the
#: entropy-gated scanners miss for the same reason: the three real tokens in the September
#: corpus scored 4.351, 3.531 and 3.328 against gitleaks' floor near 3.5. See
#: https://github.com/beril-doe/langfuse-retro-load/issues/10. The key name is the
#: evidence, and only a caller walking a parsed structure has it.
CREDENTIAL_KEY = "credential_key"

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def is_credential_key(name: str) -> bool:
    """CREDENTIAL_KEY_RE, with camelCase split first: `authToken` is `auth_Token`.

    `tokenCount` still does not match, since the credential word has to end the name.
    """
    return bool(CREDENTIAL_KEY_RE.match(_CAMEL_BOUNDARY.sub("_", name)))

#: Keys whose value is credential material whatever the value looks like. Anchored at both
#: ends, so `x-api-key`, `KBASE_AUTH_TOKEN` and `tokens` match while `token_count`,
#: `password_hint` and `secret_name` do not: a key that merely mentions a credential is
#: usually a count, a flag or a filename, and redacting those buries the real ones.
CREDENTIAL_KEY_RE = re.compile(
    r"(?i)^(?:.*[._-])?(?:token|secret|passwd|password|api[_-]?key|apikey|credential"
    r"|authorization|private[_-]?key|access[_-]?key)s?$"
)


def _whole_value_finding(text: str, pattern: str, key: bytes) -> Finding:
    """One finding covering the entire string, fingerprinted on the whole value.

    Fingerprinting the whole value rather than the matched span is what makes the record
    useful: the same credential appearing under `token` in one record and inside a shell
    command in another gets the same fingerprint only if both fingerprint the same text,
    and the value is the thing a reviewer counts.
    """
    # `is_masked` alone answers "is what survives the mask too short to be a credential",
    # and a short real credential answers that the same way: `{"token": "s3cret"}` came
    # back masked=True with no mask in it. A whole-value finding therefore requires an
    # explicit mask run to be present before it says masked, because the flag's only job
    # is to let a reviewer filter out `gho_************`, and filtering out a six
    # character token instead is the failure this module keeps having to fix.
    return Finding(pattern=pattern, category=SECRET, start=0, end=len(text),
                   length=len(text), fingerprint=fingerprint(text, key),
                   masked=bool(MASKED_RE.search(text)) and is_masked(text))


def redact_value(text, *, key_name: str | None = None,
                 categories: frozenset[str] = DEFAULT_REDACT, key: bytes | None = None):
    """Redact a string the caller has already delimited: one value, not a document.

    Two things happen here that cannot happen in the flat-string path:

    A value carrying a secret is replaced **whole**. Nothing scans for a terminator, so the
    backslash case open against `_Boundaries` has nothing to get wrong, and over-redaction
    is bounded by the value the caller passed in. When that value is a whole file read as
    one string, that bound is the file, which is the honest limit of this approach.

    A value under a credential-shaped `key_name` is replaced **whether or not any pattern
    matches it**. That is the only way a six-character token or an unrecognised provider
    shape is caught, and it is the half of the union that gitleaks cannot do.

    A value with no secret in it falls through to span mode, because an email address or a
    phone number inside a longer value should not take the whole value with it.
    """
    if not isinstance(text, str) or not text:
        return text, []
    key = new_key() if key is None else key

    # Already this module's own work, whole. Replacing it again would nest placeholders,
    # and a value under a credential key is exactly where that would happen on every pass.
    if PLACEHOLDER_RE.fullmatch(text):
        return text, []

    # Whether a finding is reported and whether it is rewritten are two questions. An
    # inventory pass runs with no categories at all, and it still has to see everything,
    # or the report it writes says a value is clean because this run was not rewriting.
    if key_name is not None and is_credential_key(key_name) and not is_reference(text):
        finding = _whole_value_finding(text, CREDENTIAL_KEY, key)
        # The whole value is replaced, but a personal detail inside it is still reported, so
        # the inventory keeps one row per finding.
        others = [f for f in detect(text, key=key) if f.category != SECRET]
        return (finding.placeholder if SECRET in categories else text), [finding, *others]

    findings = detect(text, key=key)
    secrets = [f for f in findings if f.category == SECRET]
    if secrets:
        # Name the placeholder after the longest secret in the value, so a reader of the
        # record still learns what kind of thing was in there.
        widest = max(secrets, key=lambda f: (f.length, -f.start))
        finding = _whole_value_finding(text, widest.pattern, key)
        others = [f for f in findings if f.category != SECRET]
        return (finding.placeholder if SECRET in categories else text), [finding, *others]

    return redact(text, categories=categories, key=key)


@dataclass(frozen=True)
class Located:
    """One finding, plus where in the parsed structure it was found.

    `path` is an RFC 6901 JSON pointer into the structure passed to `redact_tree`, which
    is what lets a loader leave out one tool result while still emitting the turn it
    belongs to, and lets a reviewer find the same value again on a later pass.
    """
    path: str
    key_name: str | None
    whole_value: bool
    finding: Finding


def _escape_token(token: str) -> str:
    """RFC 6901: `~` becomes `~0` and `/` becomes `~1`, in that order."""
    return token.replace("~", "~0").replace("/", "~1")


def redact_tree(node, *, categories: frozenset[str] = DEFAULT_REDACT,
                key: bytes | None = None, key_name: str | None = None, path: str = "",
                skip_keys: frozenset[str] = frozenset(),
                payload_keys: frozenset[str] = frozenset(),
                payload_by_type: dict[str, frozenset[str]] | None = None):
    """Redact every string leaf of a parsed JSON structure, reporting where each one was.

    Returns the rewritten structure and a list of `Located`. Containers are rebuilt rather
    than mutated, so the caller's copy is untouched and a dry run can compare the two.

    A leaf under a credential-shaped key goes through `redact_value`, which replaces it
    whole. Every other leaf goes through the flat-string path, bounded by the leaf: an
    unterminated private key in a `stdout` value takes the rest of that value and leaves
    its siblings and every other record alone.

    List elements inherit the key their list sits under, because `{"tokens": [a, b]}` is
    two tokens, not two anonymous strings.

    `skip_keys` names string fields to pass through untouched. It exists for identifiers
    the caller's own machinery reads back, not as a way to exempt content: rewriting a
    record's `uuid` would leave the record intact and quietly break the turn assembly that
    joins it to its parent, which is a corruption no test of the redaction itself would
    see. Containers under a skipped key are still walked.

    `payload_keys` names subtrees that hold content rather than structure, such as a tool
    call's `input`. Below one of them `skip_keys` no longer applies, so a field that happens
    to be called `id` inside a tool's arguments is screened like any other value.

    `payload_by_type` does the same for a field of a block with a given `type`: a
    `tool_result` block's `content` is what the tool returned, while that block's own `id`
    and `tool_use_id` stay structural.
    """
    payload_by_type = payload_by_type or {}
    if isinstance(node, dict):
        out, found = {}, []
        block_payload = payload_by_type.get(node.get("type"), frozenset()) \
            if isinstance(node.get("type"), str) else frozenset()
        for name, value in node.items():
            # A structural name under a credential key is not structure, it is the secret:
            # `{"token": {"id": "s3cret"}}`.
            under_credential = key_name is not None and is_credential_key(key_name)
            if isinstance(value, str) and str(name) in skip_keys and not under_credential:
                out[name] = value
                continue
            # Under a credential key, a nested mapping is still the credential: keep the
            # parent's name so `{"token": {"value": "s3cret"}}` is caught like `{"token": ...}`.
            inherited = key_name if key_name is not None and is_credential_key(key_name) \
                else str(name)
            child, child_found = redact_tree(
                value, categories=categories, key=key, key_name=inherited,
                path=f"{path}/{_escape_token(str(name))}",
                skip_keys=(frozenset() if str(name) in payload_keys or str(name) in block_payload
                           else skip_keys),
                payload_keys=payload_keys, payload_by_type=payload_by_type,
            )
            out[name] = child
            found.extend(child_found)
        return out, found

    if isinstance(node, list):
        out_list, found = [], []
        for index, value in enumerate(node):
            child, child_found = redact_tree(
                value, categories=categories, key=key, key_name=key_name,
                path=f"{path}/{index}", skip_keys=skip_keys, payload_keys=payload_keys,
                payload_by_type=payload_by_type,
            )
            out_list.append(child)
            found.extend(child_found)
        return out_list, found

    if not isinstance(node, str) or not node:
        return node, []

    if key_name is not None and is_credential_key(key_name):
        clean, findings = redact_value(node, key_name=key_name, categories=categories, key=key)
        # Whether the finding covers the whole leaf, not whether this call rewrote it: a
        # report-only pass rewrites nothing and still has to say the unit was the value.
        return clean, [Located(path=path, key_name=key_name,
                               whole_value=(f.start == 0 and f.end == len(node)), finding=f)
                       for f in findings]
    clean, findings = redact(node, categories=categories, key=key)
    return clean, [Located(path=path, key_name=key_name, whole_value=False, finding=f)
                   for f in findings]
