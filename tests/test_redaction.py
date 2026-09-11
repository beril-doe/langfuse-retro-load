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


def test_already_masked_secrets_are_not_reported():
    """`gh auth status` prints Token: gho_************ and a transcript is full of that.
    Counting it buries the one real finding under seventy harmless ones."""
    assert not [f for f in redaction.detect("Token: gho_************", key=KEY)
                if f.category == redaction.SECRET]


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
