"""What the screening pass promises: it finds the thing, it says exactly where, it never
writes the thing down, and it never takes the session with it.

The fixtures are synthetic. The two that look like credentials are shaped like credentials
on purpose, because a test for a credential pattern has to contain one; neither is a real
value and neither came from a real system.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import inventory  # noqa: E402
import redaction  # noqa: E402

KEY = b"a-fixed-key-for-reproducible-tests"

#: Shorter than any pattern in redaction.py accepts, and below gitleaks' entropy floor.
#: Only the key it sits under says it is a credential, which is the whole argument for a
#: structure-aware pass: https://github.com/beril-doe/langfuse-retro-load/issues/10
SHORT_TOKEN = "s3cret"

#: Long enough for the shape patterns, with a backslash in it. The flat-string path stops
#: at the backslash and leaves the tail behind, which is the open review thread at
#: redaction.py:200 that the value-level path is the answer to.
BACKSLASHED = "abcdefghijk\\lmnopqrstuv"


def _resolve(document, pointer: str):
    """RFC 6901, enough of it for these fixtures."""
    node = document
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def test_a_short_token_is_caught_by_the_key_it_sits_under():
    """No pattern matches six characters and no entropy gate passes them. The key name is
    the only evidence there is, and only a pass that walks the structure has it."""
    tree = {"env": {"KBASE_AUTH_TOKEN": SHORT_TOKEN}}
    clean, found = redaction.redact_tree(tree, key=KEY)
    assert SHORT_TOKEN not in json.dumps(clean)
    assert [f.finding.pattern for f in found] == [redaction.CREDENTIAL_KEY]
    assert redaction.detect(SHORT_TOKEN, key=KEY) == [], "no pattern should match it alone"


@pytest.mark.parametrize("name", ["token", "tokens", "auth_token", "KBASE_AUTH_TOKEN",
                                  "x-api-key", "apiKey", "password", "private_key"])
def test_credential_shaped_keys_are_recognised(name):
    clean, found = redaction.redact_tree({name: SHORT_TOKEN}, key=KEY)
    assert found and clean[name] != SHORT_TOKEN


@pytest.mark.parametrize("name", ["token_count", "password_hint", "secret_name",
                                  "tokenizer", "message", "type"])
def test_keys_that_merely_mention_a_credential_are_left_alone(name):
    """The negative control. A rule that redacts every key with `token` in it redacts the
    token counts in every assistant message, and a report nobody can read is not a report."""
    clean, found = redaction.redact_tree({name: "ordinary text, 412 of them"}, key=KEY)
    assert clean[name] == "ordinary text, 412 of them"
    assert found == []


def test_a_value_with_a_backslash_in_it_is_redacted_whole():
    """The thread at redaction.py:200. The flat path used to stop at the backslash and leave
    the tail; a backslash now ends a value only when it escapes a quote, so both paths take
    the whole value."""
    flat, _ = redaction.redact(f"password={BACKSLASHED}", key=KEY)
    assert "lmnopqrstuv" not in flat

    clean, found = redaction.redact_tree({"password": BACKSLASHED}, key=KEY)
    assert BACKSLASHED not in json.dumps(clean)
    assert "lmnopqrstuv" not in json.dumps(clean)
    assert found[0].whole_value is True


def test_an_unterminated_private_key_is_bounded_by_the_value_it_sits_in():
    """The open review thread at redaction.py:206, stated as what is actually true.

    A `BEGIN ... PRIVATE KEY` with no `END` and no quote after it widens to the end of
    whatever is being scanned. The first assertion measures that: two following log lines
    are gone. Walking the parsed structure does not fix it, it bounds it. The end of the
    input becomes the end of one JSON value, so sibling fields and later records survive
    while that one value is still over-redacted.

    Worth being exact about, because the bound is smaller than it looks for a raw .jsonl
    scan: there the next `"` stops the span, which is usually inside the same record. The
    case that runs away is unquoted text, which is what shell output inside a value is."""
    opening = "-----BEGIN RSA PRIVATE KEY-----"  # gitleaks:allow
    prose = f"log: {opening} MIIEowIBAAKCAQEA\nsecond line\nthird line"
    flat, _ = redaction.redact(prose, key=KEY)
    assert "second line" not in flat, "precondition: unquoted prose has no terminator"

    records = [
        {"uuid": "r1", "stdout": prose, "cwd": "/home/someuser/work"},
        {"uuid": "r2", "text": "the next record, which must survive intact"},
    ]
    redactor = redaction.Redactor(key=KEY)
    clean, rows = inventory.redact_records(records, redactor, subject="s")
    assert clean[1]["text"] == "the next record, which must survive intact"
    assert clean[0]["cwd"] == "/home/someuser/work"
    assert "MIIEow" not in clean[0]["stdout"]
    assert "second line" not in clean[0]["stdout"], "still over-redacts, inside the value"
    assert {row.record for row in rows} == {0}


def test_every_record_survives_a_record_that_had_a_secret_in_it():
    """The property the whole thing is for. One tool result printed an environment
    variable; the turn, the session and the other four records still go out."""
    records = [
        {"uuid": f"r{i}", "text": "ordinary research conversation"} for i in range(5)
    ]
    records[2]["toolUseResult"] = {"stdout": f"KBASE_AUTH_TOKEN={'ab12' * 8}"}
    redactor = redaction.Redactor(key=KEY)
    clean, rows = inventory.redact_records(records, redactor, subject="s")
    assert len(clean) == len(records)
    assert [r["uuid"] for r in clean] == [r["uuid"] for r in records]
    assert all(r["text"] == "ordinary research conversation" for r in clean)
    assert "ab12ab12" not in json.dumps(clean)
    assert [row.record for row in rows] == [2]
    assert rows[0].path == "/toolUseResult/stdout"


def test_a_finding_points_at_the_value_that_changed():
    """A pointer that does not resolve is a row nobody can act on."""
    tree = {"a": [{"b": {"note": "write to someone.else@gmail.com"}}]}
    clean, found = redaction.redact_tree(tree, key=KEY)
    assert len(found) == 1
    assert found[0].path == "/a/0/b/note"
    assert _resolve(clean, found[0].path) != _resolve(tree, found[0].path)


def test_a_pointer_escapes_the_two_characters_that_need_it():
    tree = {"a/b": "mail me at someone.else@gmail.com", "c~d": "and at other@lbl.gov"}
    _, found = redaction.redact_tree(tree, key=KEY)
    assert {f.path for f in found} == {"/a~1b", "/c~0d"}


def test_report_only_changes_nothing_and_still_sees_everything():
    """The inventory pass runs with no categories at all. If reporting were tied to
    rewriting, it would write a report saying a value is clean because this run was not
    the run that rewrites."""
    tree = {"env": {"TOKEN": SHORT_TOKEN}, "text": "someone.else@gmail.com"}
    clean, found = redaction.redact_tree(tree, categories=inventory.REPORT_ONLY, key=KEY)
    assert clean == tree
    assert {f.finding.category for f in found} == {redaction.SECRET, redaction.PERSON}


def test_identifiers_are_passed_through_so_turn_assembly_still_works():
    """Rewriting a uuid leaves a record that looks fine and no longer joins to its parent."""
    looks_like_a_token = "ghp_" + "a1b2c3d4" * 4
    records = [{"uuid": looks_like_a_token, "text": looks_like_a_token}]
    redactor = redaction.Redactor(key=KEY)
    clean, rows = inventory.redact_records(records, redactor, subject="s")
    assert clean[0]["uuid"] == looks_like_a_token
    assert clean[0]["text"] != looks_like_a_token
    assert [row.path for row in rows] == ["/text"]


def test_redacting_twice_is_the_same_as_redacting_once():
    tree = {"env": {"TOKEN": SHORT_TOKEN}, "text": f"a token: {'ab12' * 8} and a name"}
    once, _ = redaction.redact_tree(tree, key=KEY)
    twice, _ = redaction.redact_tree(once, key=KEY)
    assert once == twice


def test_no_row_and_no_report_carries_the_value_it_found(tmp_path):
    """The reason a review artifact can be handed to a colleague. Fingerprints, spans and
    pattern names; never the text."""
    records = [{"uuid": "r1", "env": {"TOKEN": SHORT_TOKEN},
                "text": f"and a long one {'ab12' * 8}"}]
    redactor = redaction.Redactor(key=KEY)
    _, rows = inventory.redact_records(records, redactor, subject="s")
    out = tmp_path / "inv.jsonl"
    inventory.write_inventory(rows, out)
    written = out.read_text()
    rendered = inventory.report(rows, detectors=["redaction"])
    for secret in (SHORT_TOKEN, "ab12" * 8):
        assert secret not in written
        assert secret not in rendered
    assert inventory.read_inventory(out) == rows


def test_a_transcript_is_scanned_record_by_record(tmp_path):
    path = tmp_path / "b7f3c2a1-0000-4000-8000-000000000001.jsonl"
    path.write_text(
        json.dumps({"uuid": "r0", "text": "nothing here"}) + "\n"
        + json.dumps({"uuid": "r1", "env": {"TOKEN": SHORT_TOKEN}}) + "\n"
    )
    rows = inventory.scan_transcript(path, redaction.Redactor(key=KEY))
    assert [row.record for row in rows] == [1]
    assert rows[0].record_uuid == "r1"
    assert rows[0].subject == path.stem, "the session id, never the path"


def test_an_unparseable_line_is_still_scanned(tmp_path):
    """A line that will not parse is exactly where something unexpected ended up, so the
    one thing not to do with it is skip it."""
    path = tmp_path / "s.jsonl"
    path.write_text("{this is not json, KBASE_AUTH_TOKEN=" + "ab12" * 8 + "}\n")
    rows = inventory.scan_transcript(path, redaction.Redactor(key=KEY))
    assert [row.category for row in rows] == [redaction.SECRET]
    # No record number: record counts parsed records, as the loader does, and the loader
    # never sends a line it cannot parse.
    assert rows[0].record is None


def test_an_asset_is_addressed_by_its_path_under_the_snapshot_root(tmp_path):
    """A notebook with a token in a cell output should cost that file, not the snapshot."""
    root = tmp_path / "projects"
    (root / "p1" / "notebooks").mkdir(parents=True)
    notebook = root / "p1" / "notebooks" / "01_extract.ipynb"
    notebook.write_text(json.dumps(
        {"cells": [{"outputs": [{"text": "KBASE_AUTH_TOKEN=" + "ab12" * 8}]}]}))
    rows = inventory.scan_asset(notebook, redaction.Redactor(key=KEY), root=root)
    assert rows and rows[0].kind == "asset"
    assert rows[0].subject == "p1/notebooks/01_extract.ipynb"
    assert rows[0].path == "/cells/0/outputs/0/text"


def test_the_loader_can_ask_which_pointers_to_act_on():
    records = [{"uuid": "r0", "text": "clean"},
               {"uuid": "r1", "env": {"TOKEN": SHORT_TOKEN}, "note": "a@gmail.com"}]
    _, rows = inventory.redact_records(records, redaction.Redactor(key=KEY), subject="s")
    secrets_only = inventory.excluded_paths(rows, categories=frozenset({redaction.SECRET}))
    assert secrets_only == {("s", 1): {"/env/TOKEN"}}


def test_a_missing_gitleaks_is_reported_as_no_rows_not_as_a_crash(tmp_path, monkeypatch):
    """The union is better than either half, and a machine without gitleaks installed
    should still produce an inventory. What it must not do is claim gitleaks ran."""
    def missing(*args, **kwargs):
        raise FileNotFoundError("gitleaks")
    monkeypatch.setattr(subprocess, "run", missing)
    assert inventory.gitleaks_rows([tmp_path / "s.jsonl"], kind="transcript", key=KEY) == []


def test_a_trace_with_only_advisory_findings_gets_no_score():
    """The first version wrote four scores on every trace and produced 1,040 of them for one real
    session, almost all reading `secret=0, person=0, kind=account_path`. Home paths are in 64.5% of
    records, so scoring them is scoring the background."""
    import scores
    only_advisory = [inventory.TurnFindings(turn=1, secret=0, person=0, advisory=27,
                                            worst="account_path", pointers=("/cwd",))]
    assert scores.plan_scores(only_advisory, {}) == []


def test_a_trace_with_a_secret_gets_a_count_a_kind_and_a_review_state():
    import scores
    found = [inventory.TurnFindings(turn=7, secret=2, person=1, advisory=9,
                                    worst="keyed_value", pointers=("/toolUseResult/stdout",))]
    plans = scores.plan_scores(found, {7: "trace-abc"})
    assert {(p.name, p.value) for p in plans} == {
        ("sensitivity.secret", 2), ("sensitivity.person", 1),
        ("sensitivity.kind", "keyed_value"), ("sensitivity.review", "open")}
    assert {p.trace_id for p in plans} == {"trace-abc"}


def test_a_cleared_turn_says_so():
    import scores
    found = [inventory.TurnFindings(turn=7, secret=1, person=0, advisory=0,
                                    worst="private_key_block", pointers=())]
    plans = scores.plan_scores(found, {}, any_cleared={7: True})
    assert ("sensitivity.review", "cleared") in {(p.name, p.value) for p in plans}


@pytest.mark.parametrize("clearance,cleared", [
    ({"subject": "s", "pattern": "keyed_value"}, True),
    ({"subject": "s", "pattern": "jwt"}, False),
    ({"subject": "other", "pattern": None}, False),
    ({"subject": None, "fingerprint": "abcd1234"}, True),
    ({"subject": "s", "path": "/toolUseResult/stdout"}, True),
    ({"subject": "s", "path": "/somewhere/else"}, False),
])
def test_a_clearance_narrows_only_by_the_fields_it_names(clearance, cleared):
    import scores
    row = inventory.Row(subject="s", kind="transcript", record=2, record_uuid="u2",
                        path="/toolUseResult/stdout", detector="redaction",
                        pattern="keyed_value", category=redaction.SECRET,
                        fingerprint="abcd1234", length=38, masked=False, whole_value=False)
    assert scores.is_cleared(row, [clearance]) is cleared


@pytest.mark.parametrize("text,flagged", [
    ("git remote set-url origin git@github.com:kbaseincubator/repo.git", False),
    ("noreply@github.com", False),
    ("12345+someone@users.noreply.github.com", False),
    ("mailer-daemon@lbl.gov", False),
    ("write to admin@example.com", False),
    ("someone@lbl.gov", True),
    ("a.person@berkeley.edu", True),
    ("contact j.doe@ornl.gov please", True),
    ("someone.else@gmail.com", True),
])
def test_service_addresses_are_not_people(text, flagged):
    """`git@github.com` is the host half of every SSH remote and has the exact shape of an
    institutional address. Redacting it turned a working instruction inside a loaded trace into
    an unfollowable one, found 2026-09-18 by reading the trace. The rule only ever suppresses in
    the person category: for a secret, over-redaction costs readability and under-redaction ships
    a credential, so nothing there is suppressed on a guess."""
    found = {f.pattern for f in redaction.detect(text, key=KEY)}
    assert bool(found & {"email_institutional", "email_personal"}) is flagged


def test_reveal_shows_a_shape_not_a_value_by_default():
    """The default answers "is this a real credential" without putting one on the screen."""
    import reveal
    leaf = f"KBASE_AUTH_TOKEN={'ab12' * 8} and more text"
    out = reveal.context_for(leaf, 11, 11 + len("TOKEN=") + 32, show_values=False)
    assert "ab12ab12" not in out
    assert "38 chars" in out


def test_reveal_redacts_a_neighbouring_finding_in_the_context():
    """Reading about one credential must not show you a different one."""
    import reveal
    leaf = f"TOKEN={'ab12' * 8} then someone.else@gmail.com then end"
    out = reveal.context_for(leaf, 0, 6 + 32, show_values=False)
    assert "someone.else@gmail.com" not in out
    assert "[REDACTED:email_personal:" in out


def test_reveal_shape_flags_a_placeholder_without_deciding_anything():
    import reveal
    assert "placeholder" in reveal.shape("<your-api-key-here>")
    assert "placeholder" not in reveal.shape("ab12" * 8)


def test_reveal_short_values_do_not_leak_their_ends():
    """First and last two characters of a six-character token is most of the token."""
    import reveal
    assert reveal.shape("s3cret") == "<6 chars>"


@pytest.mark.parametrize("value,expected", [
    ("TOKEN=$CBORG_API_KEY", "variable reference"),
    ("TOKEN=${CBORG_API_KEY}", "variable reference"),
    ("$CBORG_API_KEY", "variable reference"),
    ('API_KEY="your-key-here"', "placeholder"),
    ("TOKEN=" + "ab12" * 8, ""),
])
def test_reveal_names_a_reference_and_a_placeholder_for_what_they_are(value, expected):
    """From the first real use, 2026-09-18: three of six findings in one record were two shell
    variable references and a documentation placeholder, and only the placeholder was labelled,
    so the other two needed --show-values to rule out. A reference holds no value whatever the
    key in front of it is called."""
    import reveal
    out = reveal.shape(value)
    if expected:
        assert expected in out
    else:
        assert "reference" not in out and "placeholder" not in out
