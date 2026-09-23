"""The duplicate-upload checks, offline: presence.py against canned responses, and the skip
decision in retro_load.py on its own. The same functions were run read-only against the
real `beril-usage` project on 2026-09-22; these tests pin the behaviour without a network."""
import io
import json
import sys
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import presence  # noqa: E402

HOST, PK, SK = "https://langfuse.test", "pk-test", "sk-test"


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _serve(monkeypatch, pages):
    """Answer successive requests with successive bodies; record what was asked."""
    seen = []

    def fake_urlopen(request, timeout):
        seen.append(request.full_url)
        body = pages.pop(0)
        if isinstance(body, Exception):
            raise body
        return _Response(json.dumps(body).encode())

    monkeypatch.setattr(presence.urllib.request, "urlopen", fake_urlopen)
    return seen


def test_count_reads_the_metrics_total_and_filters_on_the_session(monkeypatch):
    seen = _serve(monkeypatch, [{"data": [{"count_count": "221"}]}])
    assert presence.session_observation_count(HOST, PK, SK, "s-1") == 221
    query = json.loads(urllib.parse.parse_qs(urllib.parse.urlsplit(seen[0]).query)["query"][0])
    assert "/api/public/v2/metrics" in seen[0]
    assert query["filters"] == [{"column": "sessionId", "operator": "=", "value": "s-1",
                                 "type": "string"}]


def test_count_of_an_unknown_session_is_zero(monkeypatch):
    _serve(monkeypatch, [{"data": [{"count_count": "0"}]}])
    assert presence.session_observation_count(HOST, PK, SK, "nope") == 0


def test_an_empty_data_list_is_zero_not_an_error(monkeypatch):
    _serve(monkeypatch, [{"data": []}])
    assert presence.session_observation_count(HOST, PK, SK, "nope") == 0


@pytest.mark.parametrize("failure", [
    urllib.error.HTTPError(HOST, 401, "Unauthorized", {}, None),
    urllib.error.URLError("no route to host"),
    TimeoutError("timed out"),
])
def test_could_not_tell_raises_rather_than_reporting_absent(monkeypatch, failure):
    _serve(monkeypatch, [failure])
    with pytest.raises(presence.PresenceError):
        presence.session_observation_count(HOST, PK, SK, "s-1")


def test_an_unrecognised_response_raises(monkeypatch):
    _serve(monkeypatch, [{"unexpected": True}])
    with pytest.raises(presence.PresenceError):
        presence.session_observation_count(HOST, PK, SK, "s-1")


def test_covered_through_walks_every_page_and_returns_the_latest_start(monkeypatch):
    seen = _serve(monkeypatch, [
        {"data": [{"startTime": "2026-05-07T20:00:00.000Z"},
                  {"startTime": "2026-05-07T21:34:03.884Z"}], "meta": {"cursor": "c2"}},
        {"data": [{"startTime": "2026-05-07T19:00:00.000Z"}, {"startTime": None}],
         "meta": {}},
    ])
    latest = presence.covered_through(HOST, PK, SK, "s-1")
    assert latest == datetime(2026, 5, 7, 21, 34, 3, 884000, tzinfo=timezone.utc)
    assert len(seen) == 2 and "cursor=c2" in seen[1] and "sessionId=s-1" in seen[0]


def test_covered_through_is_none_for_a_session_with_nothing(monkeypatch):
    _serve(monkeypatch, [{"data": [], "meta": {}}])
    assert presence.covered_through(HOST, PK, SK, "nope") is None


# --- the decision in retro_load.py ------------------------------------------------------

@pytest.fixture
def retro_load():
    pytest.importorskip("dotenv")
    import retro_load as module
    return module


NOW = datetime(2026, 9, 22, 12, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=30)


def test_a_session_the_project_already_holds_is_skipped(retro_load):
    reason = retro_load.skip_reason(last_seen=OLD, now=NOW, min_idle_days=7, existing=221,
                                    allow_existing=False)
    assert reason and "221" in reason


def test_allow_existing_sends_it_anyway(retro_load):
    assert retro_load.skip_reason(last_seen=OLD, now=NOW, min_idle_days=7, existing=221,
                                  allow_existing=True) is None


def test_a_recently_active_session_is_skipped(retro_load):
    reason = retro_load.skip_reason(last_seen=NOW - timedelta(days=2), now=NOW,
                                    min_idle_days=7, existing=0, allow_existing=False)
    assert reason and "2.0 days" in reason


def test_an_idle_session_not_in_the_project_is_sent(retro_load):
    assert retro_load.skip_reason(last_seen=OLD, now=NOW, min_idle_days=7, existing=0,
                                  allow_existing=False) is None


def test_no_timestamps_means_no_way_to_tell_so_skip(retro_load):
    assert retro_load.skip_reason(last_seen=None, now=NOW, min_idle_days=7, existing=0,
                                  allow_existing=False)


def test_min_idle_days_zero_turns_the_idle_check_off(retro_load):
    assert retro_load.skip_reason(last_seen=None, now=NOW, min_idle_days=0, existing=0,
                                  allow_existing=False) is None


def test_last_activity_is_the_latest_record_timestamp(retro_load):
    msgs = [{"timestamp": "2026-05-07T20:00:00Z"}, {"type": "summary"},
            {"timestamp": "2026-05-07T21:00:00Z"}]
    assert retro_load.last_activity(msgs) == datetime(2026, 5, 7, 21, tzinfo=timezone.utc)
