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
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a", "redacted": {}}
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


# --- scores.py ----------------------------------------------------------------------------

def test_scores_never_mixes_prefixed_and_unprefixed_keys(monkeypatch):
    pytest.importorskip("langfuse")
    import langfuse_admin
    import scores
    monkeypatch.setattr(langfuse_admin, "load_env", lambda: (
        {"BERIL_LANGFUSE_PUBLIC_KEY": "pk-beril", "LANGFUSE_SECRET_KEY": "sk-other",
         "LANGFUSE_HOST": "https://other.test"}, None))
    assert scores.client_for("BERIL") is None


def test_scores_without_a_transcript_is_a_usage_error(monkeypatch):
    import scores
    monkeypatch.setattr(sys, "argv", ["scores.py"])
    with pytest.raises(SystemExit) as exit_info:
        scores.main()
    assert exit_info.value.code == 2


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
    prior = {"session_id": "s-1", "host": "https://a.test", "public_key": "pk-a", "redacted": None}
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
