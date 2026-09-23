"""Counting and trace enumeration through the routes that survive 2026-11-16.

`langfuse_admin.py` used to read /api/public/traces, /observations, /sessions and
/v2/scores, which Langfuse removes from Cloud on that date. These tests pin the
replacement: one cursor walk of v2/observations for observations, traces and sessions,
v3/scores for scores, and v2/metrics as an independent check on the walk.
"""
import json
import sys
import urllib.error
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import langfuse_admin


class FakeLangfuse:
    """Answers the three routes from fixed data, paging by cursor like the real service."""

    def __init__(self, observations, scores=(), metrics_count=None, page=2, fail=None):
        self.observations = list(observations)
        self.scores = list(scores)
        self.metrics_count = len(self.observations) if metrics_count is None else metrics_count
        self.page = page
        self.fail = fail or set()
        self.paths = []

    def __call__(self, path, header, host, data=None, method="GET"):
        assert method == "GET", "counting must never send anything but GET"
        self.paths.append(path)
        route, _, query = path.partition("?")
        params = dict(urllib.parse.parse_qsl(query))
        if route in self.fail:
            raise urllib.error.HTTPError(path, 503, "unavailable", None, None)
        if route == "/api/public/v2/metrics":
            return 200, {"data": [{"count_count": str(self.metrics_count)}]}
        items = {"/api/public/v2/observations": self.observations,
                 "/api/public/v3/scores": self.scores}[route]
        start = int(params.get("cursor", 0))
        chunk = items[start:start + self.page]
        more = start + self.page < len(items)
        return 200, {"data": chunk, "meta": {"cursor": str(start + self.page)} if more else {}}


def obs(i, trace, session=None, start="2026-01-01T00:00:00Z", name="t"):
    return {"id": f"o{i}", "traceId": trace, "sessionId": session, "userId": "u",
            "startTime": start, "traceName": name}


def test_census_counts_distinct_traces_and_sessions_across_pages(monkeypatch):
    fake = FakeLangfuse([obs(1, "a", "s1"), obs(2, "a", "s1"), obs(3, "b", None),
                         obs(4, "c", "s2"), obs(5, "c", "s2")], page=2)
    monkeypatch.setattr(langfuse_admin, "api", fake)
    counts, note = langfuse_admin.observation_census("h", "x")
    assert counts == {"observation": 5, "trace": 3, "session": 2}
    assert note is None
    walked = [p for p in fake.paths if p.startswith("/api/public/v2/observations")]
    assert len(walked) == 3, "stopped before the last cursor page"


def test_census_asks_from_the_epoch(monkeypatch):
    """Without a lower bound a deployment default window could shrink the walk."""
    fake = FakeLangfuse([obs(1, "a")])
    monkeypatch.setattr(langfuse_admin, "api", fake)
    langfuse_admin.observation_census("h", "x")
    params = dict(urllib.parse.parse_qsl(fake.paths[0].partition("?")[2]))
    assert params["fromStartTime"] == langfuse_admin.ALL_TIME


def test_census_reports_a_metrics_disagreement(monkeypatch):
    monkeypatch.setattr(langfuse_admin, "api", FakeLangfuse([obs(1, "a")], metrics_count=4))
    counts, note = langfuse_admin.observation_census("h", "x")
    assert counts["observation"] == 1
    assert "v2/metrics says 4" in note


def test_a_failed_walk_counts_nothing_rather_than_part(monkeypatch):
    monkeypatch.setattr(langfuse_admin, "api",
                        FakeLangfuse([obs(1, "a")], fail={"/api/public/v2/observations"}))
    counts, note = langfuse_admin.observation_census("h", "x")
    assert counts == {}
    assert "HTTP 503" in note


def test_scores_are_walked_from_v3(monkeypatch):
    fake = FakeLangfuse([], scores=[{"id": str(i)} for i in range(5)], page=2)
    monkeypatch.setattr(langfuse_admin, "api", fake)
    assert langfuse_admin.count_scores("h", "x") == (5, None)
    assert all(p.startswith("/api/public/v3/scores") for p in fake.paths)


def test_no_removed_route_is_read(monkeypatch, capsys):
    """The point of the change: count touches none of the four removed routes."""
    fake = FakeLangfuse([obs(1, "a", "s")], scores=[{"id": "1"}])
    real = fake.__call__

    def answer(path, *a, **k):
        route = path.partition("?")[0]
        if route in ("/api/public/v2/observations", "/api/public/v3/scores",
                     "/api/public/v2/metrics"):
            return real(path, *a, **k)
        fake.paths.append(path)
        return 200, {"data": [], "meta": {"totalItems": 0}}

    monkeypatch.setattr(langfuse_admin, "api", answer)
    monkeypatch.setattr(langfuse_admin, "auth_for_project", lambda p: ("h", "https://x"))
    monkeypatch.setattr(langfuse_admin, "confirm_project", lambda p, h, host: "O / P")
    langfuse_admin.cmd_count(type("A", (), {"project": "p"})())
    removed = {"/api/public/traces", "/api/public/observations", "/api/public/sessions",
               "/api/public/v2/scores"}
    assert not {p.partition("?")[0] for p in fake.paths} & removed
    out = capsys.readouterr().out
    assert "trace" in out and "session" in out


def test_enumeration_groups_by_trace_and_keeps_the_earliest_start(monkeypatch):
    fake = FakeLangfuse([obs(1, "a", "s1", "2026-03-02T00:00:00Z", "n"),
                         obs(2, "a", None, "2026-03-01T00:00:00Z", "n"),
                         obs(3, "b", "s2", "2026-04-01T00:00:00Z", "n")])
    monkeypatch.setattr(langfuse_admin, "api", fake)
    traces = {t["id"]: t for t in langfuse_admin.enumerate_traces("h", "x", "n")}
    assert set(traces) == {"a", "b"}
    assert traces["a"]["timestamp"] == "2026-03-01T00:00:00Z"
    assert traces["a"]["sessionId"] == "s1"
    assert traces["a"]["name"] == "n"


def test_enumeration_puts_the_bound_and_the_name_inside_the_filter(monkeypatch):
    """`filter` overrides the plain query parameters, so the bound has to be in it."""
    fake = FakeLangfuse([])
    monkeypatch.setattr(langfuse_admin, "api", fake)
    langfuse_admin.enumerate_traces("h", "x", "my trace")
    params = dict(urllib.parse.parse_qsl(fake.paths[0].partition("?")[2]))
    conditions = json.loads(params["filter"])
    assert {"type": "datetime", "column": "startTime", "operator": ">=",
            "value": langfuse_admin.ALL_TIME} in conditions
    assert {"type": "string", "column": "traceName", "operator": "=",
            "value": "my trace"} in conditions
    assert "trace_context" in params["fields"], "traceName is only returned in trace_context"
