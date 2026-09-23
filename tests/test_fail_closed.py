"""Each place where "could not tell" or "not checked" used to read as "clean" or "not there".

From the first Copilot review of https://github.com/beril-doe/langfuse-retro-load/pull/25.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import inventory  # noqa: E402
import presence  # noqa: E402
import redaction  # noqa: E402

KEY = b"fixed key for reproducible tests, never used outside them"
FAKE = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"


# --- presence.py --------------------------------------------------------------------------

def test_an_unparseable_start_time_is_a_presence_error(monkeypatch):
    def fake_get(host, path, params, auth, timeout):
        return {"data": [{"startTime": "not a time"}], "meta": {}}
    monkeypatch.setattr(presence, "_get", fake_get)
    with pytest.raises(presence.PresenceError):
        presence.covered_through("https://x.test", "pk", "sk", "s-1")


# --- retro_load.py ------------------------------------------------------------------------

@pytest.fixture
def retro_load(monkeypatch, tmp_path):
    pytest.importorskip("dotenv")
    import retro_load as module
    monkeypatch.setattr(module, "MARKER_DIR", tmp_path / "markers")
    for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST", "LANGFUSE_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    return module


def _transcript(tmp_path) -> Path:
    path = tmp_path / "s-1.jsonl"
    path.write_text(json.dumps({"type": "user", "timestamp": "2026-01-01T00:00:00Z",
                                "message": {"role": "user", "content": "hi"}}) + "\n")
    return path


def _run(module, monkeypatch, *argv) -> int:
    monkeypatch.setattr(sys, "argv", ["retro_load.py", *argv])
    return module.main()


def test_a_failed_presence_check_stops_even_with_allow_existing(retro_load, monkeypatch, tmp_path):
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")

    def unreachable(*a, **k):
        raise presence.PresenceError("HTTP 503")
    monkeypatch.setattr(retro_load.presence, "session_observation_count", unreachable)
    assert _run(retro_load, monkeypatch, "--allow-existing", str(_transcript(tmp_path))) == 1


def test_a_dry_run_never_asks_langfuse(retro_load, monkeypatch, tmp_path):
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")

    def must_not_be_called(*a, **k):
        raise AssertionError("dry run queried Langfuse")
    monkeypatch.setattr(retro_load.presence, "session_observation_count", must_not_be_called)
    assert _run(retro_load, monkeypatch, "--dry-run", "--min-idle-days", "0",
                str(_transcript(tmp_path))) == 0


def test_a_marker_for_another_project_does_not_short_circuit(retro_load, monkeypatch, tmp_path):
    path = _transcript(tmp_path)
    retro_load.write_marker(path.resolve(), "s-1", 1, ["claude-code"], redaction_summary={},
                            host="https://a.test", public_key="pk-a")
    monkeypatch.setenv("LANGFUSE_HOST", "https://b.test")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-b")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-b")
    asked = []
    monkeypatch.setattr(retro_load.presence, "session_observation_count",
                        lambda *a, **k: asked.append(a) or 5)
    assert _run(retro_load, monkeypatch, str(path)) == retro_load.EXIT_SKIPPED
    assert asked, "the target project was never asked"


def test_a_marker_for_this_project_is_honoured(retro_load, monkeypatch, tmp_path):
    path = _transcript(tmp_path)
    retro_load.write_marker(path.resolve(), "s-1", 1, ["claude-code"], redaction_summary={},
                            host="https://a.test", public_key="pk-a")
    monkeypatch.setenv("LANGFUSE_HOST", "https://a.test")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-a")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-a")
    monkeypatch.setattr(retro_load.presence, "session_observation_count",
                        lambda *a, **k: pytest.fail("a matching marker should answer first"))
    assert _run(retro_load, monkeypatch, str(path)) == retro_load.EXIT_SKIPPED


def test_a_marker_without_a_destination_never_matches(retro_load):
    assert not retro_load.marker_matches({"session_id": "s-1", "turns_emitted": 3},
                                         "https://a.test", "pk-a", "s-1")


def test_a_marker_for_another_session_id_does_not_match(retro_load):
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a", "redacted": {},
             "turns_emitted": 3, "tags": ["claude-code"]}
    assert retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-1")
    assert not retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-2")


def test_something_already_there_is_not_called_complete(retro_load):
    from datetime import datetime, timezone
    now = datetime(2026, 9, 22, tzinfo=timezone.utc)
    reason = retro_load.skip_reason(last_seen=None, now=now, min_idle_days=0, existing=12,
                                    allow_existing=False)
    assert "failed partway" in reason and "live tracing" in reason


# --- redaction / inventory ----------------------------------------------------------------

def test_a_credential_under_a_nested_id_in_tool_input_is_screened():
    record = {"id": "rec-1", "type": "assistant",
              "message": {"content": [{"type": "tool_use", "id": "toolu_1",
                                       "input": {"id": FAKE, "type": "keep me"}}]}}
    clean, found = redaction.redact_tree(record, key=KEY, skip_keys=inventory.STRUCTURAL_KEYS,
                                         payload_keys=inventory.PAYLOAD_KEYS)
    assert FAKE not in json.dumps(clean)
    assert clean["id"] == "rec-1" and clean["message"]["content"][0]["id"] == "toolu_1"
    assert [f.finding.pattern for f in found] == ["github_pat"]


def test_an_asset_too_large_to_scan_is_not_reported_clean(monkeypatch, tmp_path):
    path = tmp_path / "big.md"
    path.write_text("x" * 10)
    monkeypatch.setattr(inventory, "MAX_ASSET_BYTES", 5)
    rows = inventory.scan_asset(path, redaction.Redactor())
    assert [(r.pattern, r.category) for r in rows] == [
        (inventory.UNSCANNED_TOO_LARGE, redaction.SECRET)]


def test_a_failed_gitleaks_run_raises_rather_than_reading_as_clean(monkeypatch, tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text("{}\n")
    monkeypatch.setattr(inventory.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, returncode=1, stdout="", stderr="boom"))
    with pytest.raises(inventory.GitleaksFailed):
        inventory.gitleaks_rows([path], kind="transcript", key=KEY)


def test_gitleaks_finding_leaks_is_not_a_failure(monkeypatch, tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text("{}\n")
    report = json.dumps([{"RuleID": "github-pat", "Secret": FAKE, "StartLine": 1}])
    monkeypatch.setattr(inventory.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, returncode=2, stdout=report, stderr=""))
    rows = inventory.gitleaks_rows([path], kind="transcript", key=KEY)
    assert [r.pattern for r in rows] == [inventory.GITLEAKS_PREFIX + "github-pat"]


def test_an_unterminated_key_in_raw_jsonl_is_not_cut_at_an_escaped_newline():
    body = "MIIEfakekeybody" + "AbCdEf" * 4
    raw = '{"stdout": "-----BEGIN RSA PRIVATE KEY-----\\n' + body + '\\n' + body + '"}'
    clean, _ = redaction.redact(raw, key=KEY)
    assert body not in clean
    assert clean.endswith('"}')


def test_the_inventory_scan_follows_the_loader_policy(tmp_path):
    # A token-shaped value in a structural field: the loader skips it, so the inventory must too.
    structural = "ghp_" + "zY9xW8vU7tS6rQ5pO4nM3lK2jI1hG0fE9dC8"
    record = {"uuid": "u-1", "type": "assistant", "id": structural,
              "message": {"content": [{"type": "tool_use", "id": "toolu_1",
                                       "input": {"id": FAKE}}]}}
    path = tmp_path / "s-1.jsonl"
    path.write_text(json.dumps(record) + "\n")
    rows = inventory.scan_transcript(path, redaction.Redactor())
    assert [(r.path, r.pattern) for r in rows] == [
        ("/message/content/0/input/id", "github_pat")]


# --- the dry-run contract build_manifest.py depends on (third Copilot review) -------------

@pytest.fixture
def manifest_env(monkeypatch, tmp_path):
    """build_manifest.py runs retro_load.py as a subprocess; keep its markers out of $HOME."""
    pytest.importorskip("dotenv")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST", "LANGFUSE_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    import build_manifest
    return build_manifest


def test_a_recently_active_session_still_gets_a_manifest_turn_count(manifest_env, tmp_path):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = tmp_path / "s-recent.jsonl"
    path.write_text(
        json.dumps({"type": "user", "uuid": "u-1", "timestamp": now,
                    "message": {"role": "user", "content": "hi"}}) + "\n"
        + json.dumps({"type": "assistant", "uuid": "a-1", "parentUuid": "u-1", "timestamp": now,
                      "message": {"role": "assistant", "id": "m-1",
                                  "content": [{"type": "text", "text": "hello"}]}}) + "\n")
    summary = manifest_env.dry_run_summary(path, "2026-05-07")
    assert summary["failed"] is False and summary["turns"] == 1


def test_a_marked_session_still_gets_a_manifest_turn_count(manifest_env, monkeypatch, tmp_path):
    path = _transcript(tmp_path).resolve()
    monkeypatch.setenv("LANGFUSE_HOST", "https://a.test")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-a")
    import retro_load
    monkeypatch.setattr(retro_load, "MARKER_DIR", tmp_path / "home" / ".retro_load_markers")
    retro_load.write_marker(path, "s-1", 4, ["claude-code", "event_day:2026-05-07"],
                            redaction_summary={}, host="https://a.test", public_key="pk-a")
    summary = manifest_env.dry_run_summary(path, "2026-05-07")
    assert summary == {"turns": 4, "event_day": True, "failed": False}


def test_one_unreadable_timestamp_makes_last_activity_unknown(retro_load):
    msgs = [{"timestamp": "2026-01-01T00:00:00Z"}, {"timestamp": "not a time"}]
    assert retro_load.last_activity(msgs) is None


@pytest.mark.parametrize("stdout", ["", "not json", "[]"])
def test_gitleaks_exit_2_without_a_usable_report_is_a_failure(monkeypatch, tmp_path, stdout):
    path = tmp_path / "t.jsonl"
    path.write_text("{}\n")
    monkeypatch.setattr(inventory.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, returncode=2, stdout=stdout, stderr=""))
    with pytest.raises(inventory.GitleaksFailed):
        inventory.gitleaks_rows([path], kind="transcript", key=KEY)


def test_presence_counts_from_1970():
    assert presence._FROM.startswith("1970-01-01")


# --- fourth Copilot review, and the "previously missed" items in the second and third -----

def test_an_unscreened_marker_does_not_satisfy_a_screened_run(retro_load):
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a", "redacted": None,
             "turns_emitted": 3, "tags": ["claude-code"]}
    assert not retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-1", screened=True)
    assert retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-1", screened=False)


@pytest.mark.parametrize("body", [{"data": "x"}, {"data": [None]}, {"data": ["row"]}])
def test_a_malformed_observations_response_is_a_presence_error(monkeypatch, body):
    monkeypatch.setattr(presence, "_get", lambda *a, **k: body)
    with pytest.raises(presence.PresenceError):
        presence.covered_through("https://x.test", "pk", "sk", "s-1")


@pytest.mark.parametrize("body", [{"data": "x"}, {"data": [None]}])
def test_a_malformed_metrics_response_is_a_presence_error(monkeypatch, body):
    monkeypatch.setattr(presence, "_get", lambda *a, **k: body)
    with pytest.raises(presence.PresenceError):
        presence.session_observation_count("https://x.test", "pk", "sk", "s-1")


def test_a_report_only_credential_key_finding_is_marked_whole_value():
    _, found = redaction.redact_tree({"TOKEN": "s3cret"}, categories=frozenset(), key=KEY)
    assert [f.whole_value for f in found] == [True]


def test_record_numbers_count_parsed_records_like_the_loader(tmp_path):
    """The previously-missed item in review 5284462504: one record-number contract."""
    path = tmp_path / "s-1.jsonl"
    path.write_text("\n" + "not json " + FAKE + "\n" + json.dumps({"token": FAKE}) + "\n")
    rows = inventory.scan_transcript(path, redaction.Redactor())
    by_record = sorted(((r.record, r.path) for r in rows if r.category == redaction.SECRET),
                       key=lambda pair: (pair[0] is None, pair))
    # Line 3 is the first parsed record, so record 0; the unparseable line 2 has no number.
    assert by_record == [(0, "/token"), (None, "")]
    assert inventory.record_numbers(path) == {2: 0}


def test_gitleaks_rows_use_the_same_record_numbers(monkeypatch, tmp_path):
    path = tmp_path / "s-1.jsonl"
    path.write_text("\n" + json.dumps({"a": 1}) + "\n")
    report = json.dumps([{"RuleID": "github-pat", "Secret": FAKE, "StartLine": 2}])
    monkeypatch.setattr(inventory.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, returncode=2, stdout=report, stderr=""))
    rows = inventory.gitleaks_rows([path], kind="transcript", key=KEY)
    assert [r.record for r in rows] == [0]


# --- sixth Copilot review: an angle-bracketed value is a placeholder only if it is words -

@pytest.mark.parametrize("node", [
    {"token": "<" + FAKE + ">"},
    {"api_key": "<sk-proj-" + "B" * 40 + ">"},
    {"password": "<hunter2hunter2>"},
])
def test_a_real_value_in_angle_brackets_is_still_a_credential(node):
    clean, found = redaction.redact_tree(node, key=KEY)
    assert clean != node and found


@pytest.mark.parametrize("value", ["<your-token-here>", "<API KEY>", "<your_password>"])
def test_a_words_only_placeholder_is_still_left_alone(value):
    clean, found = redaction.redact_tree({"token": value}, key=KEY)
    assert clean == {"token": value} and found == []


# --- seventh Copilot review ----------------------------------------------------------------

@pytest.mark.parametrize("text,tail", [
    ('password="abcdefgh,ijklmnop"', "ijklmnop"),
    ("token='abcdefgh ijklmnop'", "ijklmnop"),
    ('{\\"api_key\\":\\"abcdefgh,ijklmnop\\"}', "ijklmnop"),
])
def test_a_comma_or_space_inside_a_quoted_value_does_not_leave_the_tail(text, tail):
    clean, findings = redaction.redact(text, key=KEY)
    assert tail not in clean
    assert [f.pattern for f in findings] == ["keyed_value"]


def test_an_unquoted_value_still_ends_at_a_comma():
    """The control: without quotes a comma is usually a separator, and what follows stays."""
    clean, _ = redaction.redact("token=abcdefghijklmnop, next=value", key=KEY)
    assert clean.endswith(", next=value")


def test_a_start_time_without_a_timezone_is_a_presence_error(monkeypatch):
    monkeypatch.setattr(presence, "_get", lambda *a, **k: {
        "data": [{"startTime": "2026-05-07T21:34:03"}], "meta": {}})
    with pytest.raises(presence.PresenceError):
        presence.covered_through("https://x.test", "pk", "sk", "s-1")


# --- eighth Copilot review ----------------------------------------------------------------

def test_an_unterminated_key_does_not_reach_an_end_marker_in_a_later_field():
    body = "MIIEfakekeybody" + "AbCdEf" * 4
    key_word = "PRIVATE" + " KEY"  # split so no key marker sits in the source
    text = ('{"a": "-----BEGIN RSA ' + key_word + '-----\\n' + body + '", "b": "kept text", '
            '"c": "-----END RSA ' + key_word + '-----"}')
    clean, _ = redaction.redact(text, key=KEY)
    assert body not in clean
    assert '"b": "kept text"' in clean


@pytest.mark.parametrize("name", ["authToken", "accessToken", "clientSecret", "apiKey"])
def test_camel_case_credential_keys_are_recognised(name):
    clean, found = redaction.redact_tree({name: "s3cret"}, key=KEY)
    assert clean[name] != "s3cret" and found


@pytest.mark.parametrize("name", ["tokenCount", "secretName", "passwordHint"])
def test_camel_case_keys_that_only_mention_a_credential_are_left_alone(name):
    clean, found = redaction.redact_tree({name: "ordinary"}, key=KEY)
    assert clean == {name: "ordinary"} and found == []


def test_a_timestamp_without_a_zone_makes_last_activity_unknown(retro_load):
    assert retro_load.last_activity([{"timestamp": "2026-05-07T21:34:03"}]) is None


# --- ninth Copilot review: a malformed marker is no marker ---------------------------------

@pytest.mark.parametrize("prior", [
    [],
    "loaded",
    {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a", "redacted": {}},
    {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a", "redacted": {},
     "turns_emitted": "3", "tags": []},
])
def test_a_malformed_marker_never_matches(retro_load, prior):
    assert retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-1") is False


# --- tenth Copilot review: one marker validity check, used everywhere ---------------------

@pytest.mark.parametrize("redacted", ["screened", ["x"], 0])
def test_a_marker_with_a_malformed_redacted_field_never_matches(retro_load, redacted):
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a",
             "turns_emitted": 3, "tags": [], "redacted": redacted}
    assert retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-1") is False


def test_the_manifest_dry_run_survives_a_malformed_marker(retro_load, monkeypatch, tmp_path):
    import run_manifest
    path = _transcript(tmp_path)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([{"session_id": "s-1", "user_id": "u", "event_day": False,
                                     "source": "test", "find_root": str(tmp_path)}]))
    monkeypatch.setattr(run_manifest, "resolve_path", lambda root, sid: path)
    monkeypatch.setattr(run_manifest, "already_loaded", lambda p: {"host": "https://a.test"})
    monkeypatch.setattr(sys, "argv", ["run_manifest.py", "--manifest", str(manifest), "--dry-run"])
    assert run_manifest.main() == 0


# --- eleventh Copilot review ---------------------------------------------------------------

def test_a_credential_under_id_in_tool_result_content_is_screened():
    record = {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "toolu_1",
         "content": [{"type": "text", "id": FAKE, "text": "output"}]}]}}
    clean, found = redaction.redact_tree(
        record, key=KEY, skip_keys=inventory.STRUCTURAL_KEYS,
        payload_keys=inventory.PAYLOAD_KEYS, payload_by_type=inventory.PAYLOAD_BY_TYPE)
    assert FAKE not in json.dumps(clean)
    assert clean["message"]["content"][0]["tool_use_id"] == "toolu_1"
    assert [f.finding.pattern for f in found] == ["github_pat"]


def test_the_tool_use_blocks_own_id_stays_structural():
    record = {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": FAKE, "input": {"q": "x"}}]}}
    clean, found = redaction.redact_tree(
        record, key=KEY, skip_keys=inventory.STRUCTURAL_KEYS,
        payload_keys=inventory.PAYLOAD_KEYS, payload_by_type=inventory.PAYLOAD_BY_TYPE)
    assert clean == record and found == []


@pytest.mark.parametrize("turns", [True, False, -1])
def test_a_boolean_or_negative_turn_count_is_malformed(retro_load, turns):
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a",
             "turns_emitted": turns, "tags": [], "redacted": {}}
    assert retro_load.valid_marker(prior) is False


# --- twelfth Copilot review ----------------------------------------------------------------

def test_a_value_that_only_looks_like_a_placeholder_is_still_redacted():
    fake = "[REDACTED:made_up:deadbeef]"
    clean, found = redaction.redact_tree({"token": fake}, key=KEY)
    assert clean["token"] != fake and found


def test_this_modules_own_placeholder_is_left_alone():
    once, _ = redaction.redact_tree({"token": "s3cret-value"}, key=KEY)
    twice, found = redaction.redact_tree(once, key=KEY)
    assert twice == once and found == []


def test_an_unparseable_structured_asset_is_blocked(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text('{"TOKEN": "s3cret",')
    rows = inventory.scan_asset(path, redaction.Redactor())
    assert inventory.UNSCANNED_UNPARSEABLE in [r.pattern for r in rows]


def test_a_negative_count_is_a_presence_error(monkeypatch):
    monkeypatch.setattr(presence, "_get", lambda *a, **k: {"data": [{"count_count": "-1"}]})
    with pytest.raises(presence.PresenceError):
        presence.session_observation_count("https://x.test", "pk", "sk", "s-1")


# --- fourteenth Copilot review -------------------------------------------------------------

def test_the_inventory_path_cannot_be_the_transcript(retro_load, monkeypatch, tmp_path):
    path = _transcript(tmp_path)
    before = path.read_bytes()
    assert _run(retro_load, monkeypatch, "--dry-run", "--inventory", str(path), str(path)) == 1
    assert path.read_bytes() == before


@pytest.mark.parametrize("count", [False, True])
def test_a_boolean_count_is_a_presence_error(monkeypatch, count):
    monkeypatch.setattr(presence, "_get", lambda *a, **k: {"data": [{"count_count": count}]})
    with pytest.raises(presence.PresenceError):
        presence.session_observation_count("https://x.test", "pk", "sk", "s-1")


# --- fifteenth Copilot review --------------------------------------------------------------

@pytest.mark.parametrize("flag", ["--out", "--report"])
def test_inventory_refuses_to_overwrite_an_input(monkeypatch, tmp_path, flag):
    path = _transcript(tmp_path)
    before = path.read_bytes()
    out = path if flag == "--out" else tmp_path / "inv.jsonl"
    argv = ["inventory.py", "--no-gitleaks", "--out", str(out)]
    if flag == "--report":
        argv += ["--report", str(path)]
    monkeypatch.setattr(sys, "argv", argv + [str(path)])
    with pytest.raises(SystemExit):
        inventory.main()
    assert path.read_bytes() == before


@pytest.mark.parametrize("text", [
    '{\\"Authorization\\":\\"Basic ZmFrZXVzZXI6ZmFrZXBhc3M=\\"}',
    '{\\\\"authorization\\\\": \\\\"Token abcdefghijklmnop\\\\"}',
])
def test_an_escaped_authorization_header_is_redacted(text):
    clean, findings = redaction.redact(text, key=KEY)
    assert "ZmFrZXVzZXI6ZmFrZXBhc3M" not in clean and "abcdefghijklmnop" not in clean
    assert [f.pattern for f in findings] == ["auth_header"]


def test_a_semicolon_ends_an_unquoted_value():
    clean, findings = redaction.redact("token=abcdefghij;token=klmnopqrst", key=KEY)
    assert [f.pattern for f in findings] == ["keyed_value", "keyed_value"]
    assert ";token=" in clean


def test_a_semicolon_inside_a_quoted_value_is_content():
    clean, _ = redaction.redact('password="abcdefgh;ijklmnop"', key=KEY)
    assert "ijklmnop" not in clean


@pytest.mark.parametrize("count", [0.9, "0.9", 1.5])
def test_a_fractional_count_is_a_presence_error(monkeypatch, count):
    monkeypatch.setattr(presence, "_get", lambda *a, **k: {"data": [{"count_count": count}]})
    with pytest.raises(presence.PresenceError):
        presence.session_observation_count("https://x.test", "pk", "sk", "s-1")


@pytest.mark.parametrize("stamp", ["", 0, []])
def test_a_present_but_malformed_start_time_is_a_presence_error(monkeypatch, stamp):
    monkeypatch.setattr(presence, "_get", lambda *a, **k: {"data": [
        {"startTime": "2026-05-07T21:34:03Z"}, {"startTime": stamp}], "meta": {}})
    with pytest.raises(presence.PresenceError):
        presence.covered_through("https://x.test", "pk", "sk", "s-1")


# --- sixteenth Copilot review --------------------------------------------------------------

def test_inventory_refuses_the_same_path_for_out_and_report(monkeypatch, tmp_path):
    path = _transcript(tmp_path)
    same = tmp_path / "both.txt"
    monkeypatch.setattr(sys, "argv", ["inventory.py", "--no-gitleaks", "--out", str(same),
                                      "--report", str(same), str(path)])
    with pytest.raises(SystemExit):
        inventory.main()
    assert not same.exists()


@pytest.mark.parametrize("text,tail", [
    ('password="abcdefgh\\"ijklmnop"', "ijklmnop"),
    ('{\\"password\\":\\"abcdefgh\\\\\\"ijklmnop\\"}', "ijklmnop"),
])
def test_an_escaped_quote_inside_a_quoted_value_is_content(text, tail):
    clean, _ = redaction.redact(text, key=KEY)
    assert tail not in clean


def test_nested_json_still_closes_at_its_own_quote():
    """The control: in JSON inside a JSONL line, the escaped quote is the delimiter."""
    clean, _ = redaction.redact('{\\"password\\":\\"abcdefghijkl\\",\\"next\\":\\"kept\\"}', key=KEY)
    assert clean.endswith('\\",\\"next\\":\\"kept\\"}')


@pytest.mark.parametrize("value", ["-1", "nan", "inf", "x"])
def test_min_idle_days_must_be_finite_and_non_negative(retro_load, monkeypatch, tmp_path, value):
    monkeypatch.setattr(sys, "argv", ["retro_load.py", "--dry-run", "--min-idle-days", value,
                                      str(_transcript(tmp_path))])
    with pytest.raises(SystemExit):
        retro_load.main()


def test_skip_reason_fails_closed_on_a_bad_idle_value(retro_load):
    from datetime import datetime, timezone
    now = datetime(2026, 9, 22, tzinfo=timezone.utc)
    assert retro_load.skip_reason(last_seen=now, now=now, min_idle_days=float("nan"),
                                  existing=0, allow_existing=False)


# --- seventeenth Copilot review ------------------------------------------------------------

@pytest.mark.parametrize("node", [
    {"token": {"value": "s3cret"}},
    {"credentials": {"github": {"pat": "s3cret-value"}}},
])
def test_a_secret_nested_under_a_credential_key_is_redacted(node):
    clean, found = redaction.redact_tree(node, key=KEY)
    assert "s3cret" not in json.dumps(clean) and found


def test_a_marker_with_non_string_tags_never_matches(retro_load):
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a",
             "turns_emitted": 3, "tags": [1], "redacted": {}}
    assert retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-1") is False


# --- eighteenth Copilot review -------------------------------------------------------------

def test_a_personal_detail_beside_a_secret_in_one_value_is_still_reported():
    value = "token=" + FAKE + " owner a.b@gmail.com"
    clean, found = redaction.redact_tree({"api_key": value}, key=KEY)
    assert FAKE not in json.dumps(clean) and "a.b@gmail.com" not in json.dumps(clean)
    assert {f.finding.category for f in found} == {redaction.SECRET, redaction.PERSON}


def test_a_structural_name_under_a_credential_key_is_screened():
    node = {"token": {"id": "s3cret", "type": "bearer-ish"}}
    clean, found = redaction.redact_tree(node, key=KEY, skip_keys=inventory.STRUCTURAL_KEYS,
                                         payload_keys=inventory.PAYLOAD_KEYS)
    assert "s3cret" not in json.dumps(clean) and found


@pytest.mark.parametrize("report", ["{}", "[null]", '["x"]'])
def test_a_gitleaks_report_of_the_wrong_shape_is_a_failure(monkeypatch, tmp_path, report):
    path = tmp_path / "t.jsonl"
    path.write_text("{}\n")
    monkeypatch.setattr(inventory.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, returncode=2, stdout=report, stderr=""))
    with pytest.raises(inventory.GitleaksFailed):
        inventory.gitleaks_rows([path], kind="transcript", key=KEY)


# --- nineteenth Copilot review -------------------------------------------------------------

@pytest.mark.parametrize("name,text", [
    ("config.env", "KBASE_AUTH_TOKEN=s3cret\nOTHER=value\n"),
    ("config.env", "export API_KEY='s3cret'\n"),
    ("config.yaml", "service:\n  token: s3cret\n"),
])
def test_a_short_keyed_secret_in_a_text_asset_is_found(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    rows = inventory.scan_asset(path, redaction.Redactor())
    assert [r.pattern for r in rows if r.category == redaction.SECRET] == [redaction.CREDENTIAL_KEY]


def test_a_keyed_line_that_only_mentions_a_credential_is_left_alone(tmp_path):
    path = tmp_path / "config.env"
    path.write_text("TOKEN_COUNT=12\nSECRET_NAME=prod\nAPI_KEY=$FROM_VAULT\n")
    assert inventory.scan_asset(path, redaction.Redactor()) == []


@pytest.mark.parametrize("summary", [{"secret": "oops"}, {"secret": -1}, {"secret": True},
                                     {"nonsense": 1}])
def test_a_marker_with_a_malformed_summary_never_matches(retro_load, summary):
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a",
             "turns_emitted": 3, "tags": [], "redacted": summary}
    assert retro_load.marker_matches(prior, "https://a.test", "pk-a", "s-1") is False


# --- twentieth Copilot review --------------------------------------------------------------

@pytest.mark.parametrize("text", ['password="abcdefgh,ijklmnop', "token='abcdefgh ijklmnop"])
def test_an_unterminated_quoted_value_is_redacted_to_the_end(text):
    clean, findings = redaction.redact(text, key=KEY)
    assert "ijklmnop" not in clean and findings
