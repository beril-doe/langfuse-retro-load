"""The pure redaction function.

Three of these tests exist because of how the function will be used rather than what it
computes. At the real-time filter point it runs inside a live application and inside a
wrapping span exporter, so raising is not an available failure mode; a turn can pass
more than one filter point, so a second pass must not redact the first pass's work; and
the records it returns are meant to be read by a person before a load is sent, so they
must not contain what the load was trying not to send.
"""
import random
import string
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import redaction

KEY = b"fixed key for reproducible tests, never used outside them"

# Several lines below carry `# gitleaks:allow`. The repository's pre-commit hook matches
# the literal `-----BEGIN RSA PRIVATE KEY-----` marker and the `eyJ` JWT prefix without
# looking at what follows, so no fixture content can satisfy it: a test for a private-key
# pattern has to contain a private-key marker. The allow comments are on exactly those
# lines and nowhere else, so a real secret pasted into this file is still caught.
#
# The key body and the JWT signature are deliberately not the public spec examples they
# would naturally be. Those are base64 of nothing in particular and harmless, and the
# repository's own pre-commit hook flags them, correctly by its own rules: it cannot tell
# a published test vector from a real key and should not try. A fixture that reads as
# obviously fake to a person costs the tests nothing, since both patterns care about the
# shape of the characters rather than their content.
FAKE_KEY_BODY = "NOTAREALKEY" * 6
FAKE_SIGNATURE = "notarealsignature" * 3

# Synthetic throughout. The AWS id is a documented entropy edge case: gitleaks rejects
# it and the keyword patterns accept it, which is the whole argument of
# https://github.com/beril-doe/langfuse-retro-load/issues/10.
SAMPLES = {
    "bearer_header": "Authorization: Bearer abcdefghijklmnopqrstuvwx",
    "auth_header": "Authorization: Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk",
    "openai_style": "key sk-abcdefghijklmnopqrstuvwxyz012345",
    "github_pat": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "google_oauth": "ya29.abcdefghijklmnopqrstuvwxyz",
    "google_api_key": "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    "private_key_block": ("-----BEGIN RSA PRIVATE KEY-----\n"  # gitleaks:allow
                          + FAKE_KEY_BODY + "\n-----END RSA PRIVATE KEY-----"),  # gitleaks:allow
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + FAKE_SIGNATURE,  # gitleaks:allow
    "slack_token": "xoxb-0000000000-abcdefghijkl",
    "keyed_value": 'JUPYTERHUB_API_TOKEN=abcdef0123456789abcdef0123456789',
    "mongo_uri": "mongodb://someuser:somepassword@localhost:27017",
    "email_personal": "someone.else@gmail.com",
    "email_institutional": "someone@lbl.gov",
    "name_beside_email": '{"display_name": "A Person", "email": "x"}',
    "phone_us": "call 555-867-5309 now",
    "orcid": "0000-0002-1825-0097",
    "account_path": "reading /home/someuser/projects/notes.md",
}


def test_every_pattern_has_a_category_and_a_sample():
    """A pattern with no category would raise a KeyError inside detect(), and one with
    no sample here is untested however green the file looks."""
    assert set(redaction.PATTERNS) == set(redaction.CATEGORY)
    assert set(redaction.PATTERNS) == set(SAMPLES)


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_each_pattern_matches_its_sample(name):
    found = {f.pattern for f in redaction.detect(SAMPLES[name], key=KEY)}
    assert name in found, f"{name} did not match its own sample"


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_each_pattern_is_silent_on_ordinary_prose(name):
    """The negative control. A pattern that matches everything reports nothing."""
    clean = ("The soil sample was collected two metres below the waterline and the "
             "study identifier was recorded in the manifest, version 3, page 12.")
    assert name not in {f.pattern for f in redaction.detect(clean, key=KEY)}


def test_redact_replaces_secrets_and_leaves_advisory_alone():
    text = f"{SAMPLES['github_pat']} for {SAMPLES['orcid']}"
    clean, findings = redaction.redact(text, key=KEY)
    assert SAMPLES["github_pat"] not in clean
    assert SAMPLES["orcid"] in clean, "an ORCID is published on purpose; rewriting it loses meaning"
    reported = {f.pattern: f.category for f in findings}
    assert reported["orcid"] == redaction.ADVISORY, "still reported, just not rewritten"


def test_findings_never_carry_the_matched_text():
    """The reason a record exists is so a person can review a load before it is sent.
    A review artifact that quotes the secrets is the problem it was avoiding."""
    text = " ".join(SAMPLES.values())
    _, findings = redaction.redact(text, key=KEY)
    blob = " ".join(repr(f) for f in findings)
    for name, sample in SAMPLES.items():
        if name == "orcid":
            continue  # not rewritten, and public by design
        assert sample not in blob


def test_idempotent():
    """A turn can pass more than one filter point. A second pass must not turn the
    first pass's placeholders into placeholders of placeholders."""
    text = " ".join(SAMPLES.values())
    once, _ = redaction.redact(text, key=KEY)
    twice, second_findings = redaction.redact(once, key=KEY)
    assert twice == once
    assert not [f for f in second_findings if f.category in redaction.DEFAULT_REDACT]


def test_a_secret_beats_a_genuinely_overlapping_person_match():
    """Written the obvious way, this test could not fail.

    The first version used a directory dump carrying a token. Both patterns matched it,
    the assertions passed, and inverting the precedence in `_RANK` changed nothing,
    because the two spans sat side by side and never competed. Overlap has to be
    constructed, and the harm has to be visible in the output rather than inferred.

    Here they really do overlap. `bearer_header` claims the whole header from character
    0; `phone_us` claims twelve digits inside the token. If the person pattern wins, the
    tail of the credential survives in plain text while the record says the turn was
    redacted.
    """
    text = "Authorization: Bearer 555-867-5309abcdefgh"
    clean, findings = redaction.redact(text, key=KEY)
    assert [f.pattern for f in findings] == ["bearer_header"]
    assert "abcdefgh" not in clean, "the tail of the credential survived"
    assert "555-867-5309" not in clean


def test_non_overlapping_matches_of_different_kinds_are_all_reported():
    """The companion to the case above: precedence resolves overlaps and must not
    discard a finding that simply sits next to another one."""
    # gitleaks:allow -- hand-typed synthetic fixture, not a credential. The pre-commit
    # hook's generic-api-key rule reads the quoted value after "token" exactly as this
    # module's keyed_value pattern does, which is the behaviour under test.
    text = '{"name": "A Person", "email": "person@lbl.gov", "token": "abcdef0123456789"}'  # gitleaks:allow
    clean, findings = redaction.redact(text, key=KEY)
    assert {f.pattern for f in findings} == {
        "name_beside_email", "email_institutional", "keyed_value"}
    assert "abcdef0123456789" not in clean
    assert "person@lbl.gov" not in clean


def test_findings_do_not_overlap():
    text = " ".join(SAMPLES.values())
    findings = redaction.detect(text, key=KEY)
    for a, b in zip(findings, findings[1:], strict=False):
        assert a.end <= b.start


def test_an_already_masked_value_is_flagged_and_still_redacted():
    """`gh auth status` prints Token: gho_************ and a transcript is full of that, so a
    report wants to keep it out of the way. It gets a flag for that, not an exemption.

    Two rounds of review found two ways for the mask predicate to be wrong, and each one left
    a real secret in the text. So it no longer decides anything: secrets are redacted either
    way and `masked` only tells a reader which findings are probably noise."""
    findings = redaction.detect("Token: gho_************", key=KEY)
    secrets = [f for f in findings if f.category == redaction.SECRET]
    assert secrets and all(f.masked for f in secrets)
    clean, _ = redaction.redact("Token: gho_************", key=KEY)
    assert "gho_" not in clean


def test_a_secret_made_entirely_of_the_mask_character_is_still_redacted():
    """The second way the predicate was wrong. `sk-xxxxxxxxxxxxxxxx` passes openai_style, and
    removing the mask run leaves `sk-`, which read as too short to be a credential. Under the
    old design that dropped the finding and left the value in the text."""
    clean, findings = redaction.redact("sk-xxxxxxxxxxxxxxxx", key=KEY)
    assert [f.pattern for f in findings] == ["openai_style"]
    assert "xxxxxxxx" not in clean


def test_a_value_is_redacted_past_characters_the_pattern_stops_at():
    """`keyed_value` stops at the first character outside its class, so it ended at the dot
    and left the rest of the credential in the output while reporting a finding. The pattern
    now only anchors detection; the span runs to the end of the value."""
    clean, findings = redaction.redact("token=abcdefghijklmnop.qrstuvwxyz", key=KEY)
    assert [f.pattern for f in findings] == ["keyed_value"]
    assert "qrstuvwxyz" not in clean


def test_a_private_key_longer_than_any_bound_is_fully_redacted():
    """The bounded repeat that replaced the marker-only pattern became the same defect one
    round later: a key longer than the bound matched its prefix and the rest survived."""
    body = "NOTAREALKEY" * 1000
    text = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"  # gitleaks:allow
    clean, findings = redaction.redact(text, key=KEY)
    assert [f.pattern for f in findings] == ["private_key_block"]
    assert "NOTAREALKEY" not in clean
    assert "END RSA PRIVATE KEY" not in clean


def test_a_run_scoped_redactor_gives_one_credential_one_fingerprint():
    """redact() on its own mints a key per call, so the same credential in two turns looks
    like two unrelated findings. The adapters process one turn at a time, which is exactly
    when that matters."""
    turns = ["first turn " + SAMPLES["github_pat"], "later turn " + SAMPLES["github_pat"]]
    r = redaction.Redactor()
    prints = [r.redact(t)[1][0].fingerprint for t in turns]
    assert prints[0] == prints[1]
    loose = [redaction.redact(t)[1][0].fingerprint for t in turns]
    assert loose[0] != loose[1], "the bare function is per-call by design; this is why Redactor exists"


def test_same_value_gets_the_same_fingerprint_and_different_values_do_not():
    """What makes a review readable: one token in forty turns is a different situation
    from forty unrelated findings, and the record has to show which it is."""
    text = f"{SAMPLES['github_pat']} then {SAMPLES['github_pat']} then {SAMPLES['openai_style']}"
    findings = redaction.detect(text, key=KEY)
    pats = [f.fingerprint for f in findings if f.pattern == "github_pat"]
    others = [f.fingerprint for f in findings if f.pattern == "openai_style"]
    assert len(pats) == 2 and pats[0] == pats[1]
    assert others and others[0] not in pats


def test_a_random_key_makes_fingerprints_unguessable_across_runs():
    """Without this the fingerprint is a bare hash, and a bare hash of a low-entropy
    secret is reversible by anyone who reads the record."""
    a = redaction.detect(SAMPLES["github_pat"])[0].fingerprint
    b = redaction.detect(SAMPLES["github_pat"])[0].fingerprint
    assert a != b


@pytest.mark.parametrize("value", [None, 42, True, b"bytes", ["a"], {"a": 1}, ""])
def test_non_text_passes_through_unchanged(value):
    """At the real-time point the input is a span attribute, which can be a bool or an
    int. Coercing it is how a filter starts changing data it was not asked to touch."""
    out, findings = redaction.redact(value)
    assert out is value or out == value
    assert findings == []


def test_never_raises_on_adversarial_input():
    """There is no available failure mode inside a span exporter. Raising either loses
    the span or, if a caller wraps it in try/except, exports it unredacted, which
    defeats the only reason the exporter is there."""
    rng = random.Random(0)
    alphabet = string.printable + "\x00�•\\\"'{}[]"
    cases = [
        "",
        "\x00" * 1000,
        "[REDACTED:github_pat:deadbeef]" * 50,
        "[REDACTED:not_a_real_pattern:zz]",
        "token=" + "A" * 10000,
        "a@" + "b" * 5000 + ".gov",
        "\\\"token\\\":\\\"" + "x" * 64 + "\\\"",
    ] + ["".join(rng.choice(alphabet) for _ in range(2000)) for _ in range(25)]
    for case in cases:
        out, findings = redaction.redact(case)
        assert isinstance(out, str)
        assert isinstance(findings, list)


def test_stays_fast_enough_for_the_real_time_point():
    """The linearity claim in LOCAL_PART's comment, held in place. Without the
    lookbehind this pattern went quadratic on a long run of word characters: 1.0s at
    20k, 15.9s at 80k, 97s at 200k. A span exporter cannot pay that.

    The bound is loose on purpose, at roughly a hundred times the measured cost on a
    2026 laptop, so it fails on a return to quadratic behaviour and not on a slow
    continuous-integration runner. 60k characters rather than 200k for the same reason
    in the other direction: quadratic on 200k takes about 97 seconds to fail, which is
    long enough that it reads as a hang rather than a failure.
    """
    text = ("x" * 60_000) + " ordinary sentence " + SAMPLES["github_pat"]
    start = time.perf_counter()
    _, findings = redaction.redact(text, key=KEY)
    elapsed = time.perf_counter() - start
    assert "github_pat" in {f.pattern for f in findings}
    assert elapsed < 2.0, f"{elapsed:.2f}s on {len(text):,} characters"


def test_a_private_key_is_removed_body_and_all():
    """As a detector, matching the BEGIN marker was enough to raise a finding. As a
    redactor it is worse than useless: rewriting the marker and leaving the base64 body
    keeps the key loadable while the record says the turn was redacted."""
    body = FAKE_KEY_BODY
    text = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"  # gitleaks:allow
    clean, findings = redaction.redact(text, key=KEY)
    assert [f.pattern for f in findings] == ["private_key_block"]
    assert body not in clean
    assert "END RSA PRIVATE KEY" not in clean  # gitleaks:allow
    assert clean == redaction.Finding(
        "private_key_block", redaction.SECRET, 0, len(text), len(text),
        redaction.fingerprint(text, KEY)).placeholder


def test_an_unterminated_private_key_stops_at_the_end_of_its_value():
    """The other half of the same fix. Running to end of input on a missing END marker
    would redact the rest of a 300 MB transcript on one stray marker in prose."""
    text = '{"key": "-----BEGIN EC PRIVATE KEY-----' + FAKE_KEY_BODY + '", "other": 1}'  # gitleaks:allow
    clean, findings = redaction.redact(text, key=KEY)
    assert [f.pattern for f in findings] == ["private_key_block"]
    assert FAKE_KEY_BODY not in clean
    assert '"other": 1' in clean, "the rest of the document has to survive"


def test_a_jwt_loses_its_signature():
    """The header and payload are base64 of public JSON. The signature is what makes the
    token usable, and stopping at the dot after the payload left exactly that behind."""
    signature = FAKE_SIGNATURE
    text = f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{signature}"  # gitleaks:allow
    clean, _ = redaction.redact(text, key=KEY)
    assert signature not in clean


def test_a_mask_next_to_a_real_secret_does_not_hide_it():
    """`MASKED_RE.search(value)` was the first version and failed in the dangerous
    direction: any run of eight x characters anywhere in the value suppressed the whole
    finding, so this string was dropped from the record and left in the text."""
    clean, findings = redaction.redact("token=xxxxxxxxREALSECRET123", key=KEY)
    assert [f.pattern for f in findings] == ["keyed_value"]
    assert "REALSECRET123" not in clean


@pytest.mark.parametrize("value,masked", [
    ("Token: gho_************", True),
    ("api_key=xxxxxxxxxxxxxxxx", True),
    ("token=[REDACTED:github_pat:deadbeef]", True),
    ("token=xxxxxxxxREALSECRET123", False),
    ("password=hunter2hunter2", False),
])
def test_is_masked_measures_what_survives_the_mask(value, masked):
    assert redaction.is_masked(value) is masked


def test_a_redactor_never_prints_its_key():
    """The key makes every fingerprint in a run reversible, which is the whole reason it is
    random and never stored. A generated dataclass repr publishes it to any log line, any
    traceback and any debugger that touches the object."""
    r = redaction.Redactor(key=b"a recognisable key value for this test")
    assert "recognisable" not in repr(r)
    assert "recognisable" not in f"{r}"
    assert "recognisable" not in str({"redactor": r})


def test_a_lowercase_bearer_scheme_is_still_a_credential():
    """RFC 9110 makes the Authorization scheme token case-insensitive, and the pattern was
    anchored on the capitalised spelling, so a client sending it lowercase passed through."""
    clean, findings = redaction.redact("authorization: bearer abcdefghijklmnopqrst", key=KEY)
    assert [f.pattern for f in findings] == ["bearer_header"]
    assert "abcdefghijklmnopqrst" not in clean


@pytest.mark.parametrize("shape,build", [
    ("semicolon-separated fields",
     lambda n: ";".join(f"token=abcdefgh{i:06d}" for i in range(n))),
    ("unterminated private-key markers",
     lambda n: " ".join("BEGIN RSA PRIVATE KEY body%d" % i for i in range(n))),  # gitleaks:allow
])
def test_many_matches_do_not_cost_quadratic_time(shape, build):
    """Many matches, not one long string, which is what the other performance test misses.

    That test uses a 60,000-character run of one character and therefore produces a single
    candidate, so it cannot see per-candidate work at all. Widening each match by walking
    right one character was linear per candidate and quadratic in the number of candidates,
    and both inputs here have no terminator between fields. Measured before the fix: 200
    fields took 0.014s and 1,600 took 0.846s, quadrupling as the input doubled.

    Asserted as a ratio rather than a wall time, so it measures growth rather than how busy
    the machine is. An eightfold input costs about eight times as much when the work is
    linear and about sixty-four when it is quadratic. The bound is twenty-four: three times
    the linear answer, so machine noise cannot fail it, and well under the quadratic one.

    Sixty-four was the first bound and it was useless, because it is exactly the number the
    defect produces. Reverting the fix left one of these two shapes green.
    """
    small, large = build(400), build(3200)
    assert len(large) > 7 * len(small)

    def cost(text):
        best = float("inf")
        for _ in range(3):  # the fastest of three, so a scheduling hiccup cannot fail this
            start = time.perf_counter()
            redaction.redact(text, key=KEY)
            best = min(best, time.perf_counter() - start)
        return best

    small_cost, large_cost = cost(small), cost(large)
    assert large_cost < small_cost * 24, (
        f"{shape}: {small_cost:.4f}s at {len(small):,} chars and {large_cost:.4f}s at "
        f"{len(large):,} chars, a factor of {large_cost / small_cost:.0f}. Linear is about "
        f"eight.")


# ---------------------------------------------------------------------------
# https://github.com/beril-doe/langfuse-retro-load/issues/23: a reference is not a secret,
# and the name of what was hidden stays readable.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "export ANTHROPIC_AUTH_TOKEN=$CBORG_API_KEY",
    "ANTHROPIC_AUTH_TOKEN=${CBORG_API_KEY}",
    'api_key: "$OPENAI_API_KEY"',
    "password=<your-password-here>",
    "token: {{ secrets.GITHUB_TOKEN }}",
])
def test_a_variable_reference_is_left_alone(text):
    clean, findings = redaction.redact(text, key=KEY)
    assert clean == text
    assert [f for f in findings if f.category == redaction.SECRET] == []


@pytest.mark.parametrize("node", [
    {"token": "$GITHUB_TOKEN"},
    {"api_key": "${OPENAI_API_KEY}"},
    {"password": "<your-password-here>"},
])
def test_a_reference_under_a_credential_key_is_left_alone(node):
    clean, found = redaction.redact_tree(node, key=KEY)
    assert clean == node
    assert found == []


# Built at runtime so no credential-shaped literal sits in the source for a scanner to flag.
FAKE_VALUE = "abcdef0123456789" * 2
FAKE_BASIC = "ZmFrZXVzZXI6" + "ZmFrZXBhc3N3b3Jk"


@pytest.mark.parametrize("prefix,suffix", [
    ("KBASE_AUTH_TOKEN=", ""),
    ("export ANTHROPIC_AUTH_TOKEN=", ""),
    ('{"api_key": "', '"}'),
])
def test_the_variable_name_survives_and_the_value_does_not(prefix, suffix):
    clean, findings = redaction.redact(prefix + FAKE_VALUE + suffix, key=KEY)
    assert clean.startswith(prefix)
    assert FAKE_VALUE[:16] not in clean
    assert [f.pattern for f in findings] == ["keyed_value"]


def test_a_literal_value_is_still_redacted_beside_a_reference():
    """The negative control for the reference rule: it must not exempt real values."""
    text = "ANTHROPIC_AUTH_TOKEN=$CBORG_API_KEY password=hunter2hunter2"
    clean, findings = redaction.redact(text, key=KEY)
    assert "$CBORG_API_KEY" in clean
    assert "hunter2hunter2" not in clean
    assert [f.pattern for f in findings] == ["keyed_value"]


@pytest.mark.parametrize("text", [
    "Authorization: Basic " + FAKE_BASIC,
    "Proxy-Authorization: Token abcdefghijklmnop",
    "curl -H 'authorization: basic " + FAKE_BASIC + "' https://example.test",
])
def test_basic_and_token_schemes_keep_the_scheme_and_lose_the_credential(text):
    clean, findings = redaction.redact(text, key=KEY)
    assert [f.pattern for f in findings] == ["auth_header"]
    assert FAKE_BASIC not in clean and "abcdefghijklmnop" not in clean
    assert any(scheme in clean.lower() for scheme in ("basic ", "token "))


# ---------------------------------------------------------------------------
# The backslash thread on https://github.com/beril-doe/langfuse-retro-load/pull/20: a
# backslash inside a value is content, and only one escaping a quote ends the value.
# ---------------------------------------------------------------------------

BACKSLASH_TAIL = "ijklmnop"


@pytest.mark.parametrize("text", [
    "password=abcdefgh\\\\" + BACKSLASH_TAIL,
    "password=abcdefgh\\" + BACKSLASH_TAIL,
    "stdout: token=abcdefgh\\\\" + BACKSLASH_TAIL + " and more",
])
def test_a_backslash_inside_a_value_does_not_leave_the_tail_behind(text):
    clean, findings = redaction.redact(text, key=KEY)
    assert BACKSLASH_TAIL not in clean
    assert [f.pattern for f in findings] == ["keyed_value"]


@pytest.mark.parametrize("text,after", [
    ('x \\"token\\":\\"abcdefghijklmnop\\", next', '\\", next'),
    ('x \\\\"token\\\\":\\\\"abcdefghijklmnop\\\\", next', '\\\\", next'),
])
def test_an_escaped_quote_still_ends_the_value(text, after):
    """The case the backslash terminator exists for: JSON quoted inside a JSONL line."""
    clean, _ = redaction.redact(text, key=KEY)
    assert "abcdefghijklmnop" not in clean
    assert clean.endswith(after)


# --- keyed_value on source code, found reviewing the first backfill plan (2026-09-24) -----

@pytest.mark.parametrize("line", [
    'file_token = env_vars.get("KBASE_AUTH_TOKEN", "")',
    "api_key = load_api_key(path)",
    'my_token = request_headers["x"]',
    'password = cfg.values["db"]',
])
def test_code_that_reads_a_credential_is_not_a_credential(line):
    assert [f for f in redaction.detect(line) if f.pattern == "keyed_value"] == []


# Built at run time so the repo's own gitleaks pre-commit scan does not stop on them.
_FAKE_JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0In0", "SflKxwRJSMeKKF2QT4fw"])
_FAKE_LIVE = "sk_" + "live_abcdefgh.1234"
_FAKE_PASSWORD = "hunter2" * 2


@pytest.mark.parametrize("key, value", [
    ("PASSWORD=", _FAKE_PASSWORD),
    ("export API_KEY=", _FAKE_LIVE),
    ("token: ", "abcdefghijklmnop"),
    ("token=", "abcdefghijklmnop.qrstuvwxyz"),
    ("secret = ", "settings_obj.secret_key"),
    ("token=", "abcdefghijklmnop[qrstuvwxyz"),
    ("token=", "abcdefghijklmnop(secretvalue"),
    ('token="', 'abcdefghijklmnop()'),
    ("token='", "abcdefghijklmnop[1]"),
    ("token = ", _FAKE_JWT),
])
def test_values_that_look_like_data_are_still_caught(key, value):
    """A dotted chain stays masked: it cannot be told apart from a real dotted value."""
    line = key + value
    found = [line[f.start:f.end] for f in redaction.detect(line)
             if f.category == redaction.SECRET]
    assert found == [value]


def test_a_call_split_across_lines_is_still_masked():
    """Out of scope on purpose: the exemption covers one-line calls, and anything else falls
    back to masking, which hides a variable name rather than a credential."""
    line = 'file_token = env_vars.get(\n    "KBASE_AUTH_TOKEN",\n)'
    assert [f.pattern for f in redaction.detect(line)] == ["keyed_value"]


@pytest.mark.parametrize("key, literal", [
    ("password = ", "hunter2" * 2),
    ("token = ", "abcdefghijklmnop"),
    ("api_key = ", "sk_" + "live_abcdefgh1234"),
])
def test_a_credential_written_inside_a_call_is_still_masked(key, literal):
    """`get_secret("hunter2hunter2")` is a complete call, but its argument is the secret."""
    line = f'{key}get_secret("{literal}")'
    found = [line[f.start:f.end] for f in redaction.detect(line)
             if f.category == redaction.SECRET]
    assert found == [literal], "mask the argument, not the function name"
