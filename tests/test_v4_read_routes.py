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


def test_the_earliest_start_is_chosen_by_time_not_by_string(monkeypatch):
    """As strings, "...00.5Z" sorts before "...00Z", although it is later."""
    fake = FakeLangfuse([obs(1, "a", None, "2026-03-01T00:00:00.500Z"),
                         obs(2, "a", None, "2026-03-01T00:00:00Z")])
    monkeypatch.setattr(langfuse_admin, "api", fake)
    [trace] = langfuse_admin.enumerate_traces("h", "x", None)
    assert trace["timestamp"] == "2026-03-01T00:00:00Z"


def test_a_dry_run_with_no_timestamps_still_reports(monkeypatch, capsys):
    fake = FakeLangfuse([obs(1, "a", "s", start=None)])
    monkeypatch.setattr(langfuse_admin, "api", fake)
    monkeypatch.setattr(langfuse_admin, "auth_for_project", lambda p: ("h", "https://x"))
    monkeypatch.setattr(langfuse_admin, "confirm_project", lambda p, h, host: "O / P")
    args = type("A", (), dict(project="p", type="trace", name=None, all=True,
                              dry_run=True, yes=False, record=None))()
    assert langfuse_admin.cmd_delete(args) == 0
    assert "unknown, no target has a timestamp" in capsys.readouterr().out


def tagged(i, trace, tags, user="u"):
    o = obs(i, trace)
    o["tags"], o["userId"] = list(tags), user
    return o


def test_tag_filter_goes_to_the_server_as_all_of(monkeypatch):
    fake = FakeLangfuse([])
    monkeypatch.setattr(langfuse_admin, "api", fake)
    langfuse_admin.enumerate_traces("h", "x", None, ["retro-load", "batch-1"])
    params = dict(urllib.parse.parse_qsl(fake.paths[0].partition("?")[2]))
    assert {"type": "arrayOptions", "column": "tags", "operator": "all of",
            "value": ["retro-load", "batch-1"]} in json.loads(params["filter"])


def delete_args(**kw):
    base = dict(project="p", type="trace", name=None, all=False, tag=None,
                dry_run=True, yes=False, record=None)
    base.update(kw)
    return type("A", (), base)()


def wired(monkeypatch, fake):
    monkeypatch.setattr(langfuse_admin, "api", fake)
    monkeypatch.setattr(langfuse_admin, "auth_for_project", lambda p: ("h", "https://x"))
    monkeypatch.setattr(langfuse_admin, "confirm_project", lambda p, h, host: "O / P")


def test_tag_selection_is_checked_locally_too(monkeypatch, capsys):
    """The server filter narrows; the local check decides. A trace the server returned
    without the tag must not become a target."""
    wired(monkeypatch, FakeLangfuse([tagged(1, "a", ["claude-code", "retro-load"], "mamillerpa"),
                                     tagged(2, "b", ["claude-code"], "hub-smoke-test")]))
    assert langfuse_admin.cmd_delete(delete_args(tag=["retro-load"])) == 0
    out = capsys.readouterr().out
    assert "2 traces tagged retro-load, 1 to delete" in out
    assert "mamillerpa (1)" in out and "hub-smoke-test" not in out


def test_the_dry_run_counts_the_scores_that_go_with_the_traces(monkeypatch, capsys):
    wired(monkeypatch, FakeLangfuse([tagged(1, "a", ["retro-load"])],
                                    scores=[{"id": "s1"}, {"id": "s2"}]))
    langfuse_admin.cmd_delete(delete_args(tag=["retro-load"]))
    assert "scores deleted with them: 2" in capsys.readouterr().out


def test_tag_alone_is_a_selector(monkeypatch, capsys):
    """Without this, --tag would be refused as 'no selector' before enumerating."""
    wired(monkeypatch, FakeLangfuse([]))
    assert langfuse_admin.cmd_delete(delete_args(tag=["retro-load"])) == 0
    assert "give --name" not in capsys.readouterr().err


class DeletingFake(FakeLangfuse):
    """FakeLangfuse that also accepts the bulk DELETE, for the --record path."""

    def __call__(self, path, header, host, data=None, method="GET"):
        if method == "DELETE":
            self.paths.append(("DELETE", path, data))
            return 200, {"message": "accepted"}
        return super().__call__(path, header, host, data, method)


def test_the_record_carries_tags_and_the_score_count(monkeypatch, tmp_path):
    fake = DeletingFake([tagged(1, "a", ["retro-load", "batch-1", "claude-code"]),
                         tagged(2, "b", ["retro-load", "batch-1"]),
                         tagged(3, "c", ["retro-load"])],
                        scores=[{"id": "s1"}, {"id": "s2"}, {"id": "s3"}])
    wired(monkeypatch, fake)
    record = tmp_path / "deleted.json"
    code = langfuse_admin.cmd_delete(delete_args(tag=["retro-load", "batch-1"], dry_run=False,
                                                 yes=True, record=str(record)))
    assert code == 0
    written = json.loads(record.read_text())
    assert written["match"] == {"tags": ["retro-load", "batch-1"]}
    assert written["scores_deleted_with_them"] == 3
    assert {t["id"]: t["tags"] for t in written["traces"]} == {
        "a": ["batch-1", "claude-code", "retro-load"], "b": ["batch-1", "retro-load"]}
    deletes = [p for p in fake.paths if isinstance(p, tuple)]
    assert deletes and sorted(deletes[0][2]["traceIds"]) == ["a", "b"], "c lacks batch-1"


def test_scores_are_looked_up_for_all_targets_in_one_comma_separated_filter(monkeypatch):
    """v3/scores documents traceId as "Comma-separated list of trace IDs to filter by"."""
    fake = FakeLangfuse([], scores=[])
    monkeypatch.setattr(langfuse_admin, "api", fake)
    langfuse_admin.count_trace_scores(["a", "b", "c"], "h", "x")
    params = dict(urllib.parse.parse_qsl(fake.paths[0].partition("?")[2]))
    assert params["traceId"] == "a,b,c"
