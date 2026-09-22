"""Ask Langfuse what it already holds for a session, before sending that session again.

Three ways the same session can land in a project twice, and what answers each:

1. This loader runs twice. The local marker in ~/.retro_load_markers/ says nothing about
   which project a session went to, so it cannot answer "is it in *this* project". Ask
   the project: `session_observation_count()`.
2. The loader runs after live tracing already sent the session. Same question, same answer,
   because live traces carry the same session id.
3. Someone resumes a backfilled session after opting in to live tracing. The live hook has no
   state for it and re-sends every earlier turn, backdated to when it happened. Whoever
   forwards those spans can drop the ones that start at or before `covered_through()`: the
   latest start time the project already holds for that session. New turns start later and
   pass. In BERIL that forwarder is the relay (ui/app/routes/langfuse.py), which holds the
   project keys this needs; the hooks themselves cannot read.

Standard library only, and no import from the rest of this repo, so it can be copied into
another codebase unchanged. It uses only read routes that survive the 2026-11-16 removal
(`/api/public/v2/metrics`, `/api/public/v2/observations`), and v2/metrics is documented as a
real-time read path, where the older list routes can lag by about ten minutes.

Any failure to get an answer raises. A caller deciding whether to upload should treat "could
not tell" as "do not upload": a skipped session can be loaded later, a duplicate cannot be
removed without deleting whole traces.
"""
from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from datetime import datetime

#: Wide enough to cover any backdated transcript. v2/metrics requires both bounds. 1970 to
#: match langfuse_admin.ALL_TIME; on 2026-09-22 it counted the same as 2000 on both projects.
_FROM = "1970-01-01T00:00:00Z"
_TO = "2100-01-01T00:00:00Z"


class PresenceError(RuntimeError):
    """Langfuse could not be asked, or answered in a shape this module does not recognise."""


def _auth(public_key: str, secret_key: str) -> str:
    return "Basic " + base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()


def _get(host: str, path: str, params: dict, auth: str, timeout: float) -> dict:
    url = host.rstrip("/") + path + "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"{}")
    except Exception as exc:  # noqa: BLE001 -- every failure means "could not tell"
        raise PresenceError(f"GET {path} failed: {type(exc).__name__}: {exc}") from exc


def session_observation_count(host: str, public_key: str, secret_key: str, session_id: str,
                              *, timeout: float = 30) -> int:
    """How many observations the project already holds for this session id."""
    query = {
        "view": "observations",
        "metrics": [{"measure": "count", "aggregation": "count"}],
        "filters": [{"column": "sessionId", "operator": "=", "value": session_id,
                     "type": "string"}],
        "fromTimestamp": _FROM, "toTimestamp": _TO,
    }
    body = _get(host, "/api/public/v2/metrics", {"query": json.dumps(query)},
                _auth(public_key, secret_key), timeout)
    try:
        rows = body["data"]
        if not isinstance(rows, list):
            raise TypeError("data is not a list")
        return int(rows[0]["count_count"]) if rows else 0
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
        raise PresenceError(f"unexpected v2/metrics response: {str(body)[:200]}") from exc


def covered_through(host: str, public_key: str, secret_key: str, session_id: str,
                    *, timeout: float = 30, page_size: int = 1000) -> datetime | None:
    """The latest start time among the session's observations, or None if it has none.

    Walks every page. v2/observations has no max aggregate and no total, and a session is at
    most a few thousand observations, so a full walk is a handful of requests.
    """
    auth = _auth(public_key, secret_key)
    params: dict = {"sessionId": session_id, "fields": "core", "limit": page_size}
    latest: datetime | None = None
    while True:
        body = _get(host, "/api/public/v2/observations", params, auth, timeout)
        try:
            rows = body["data"]
            cursor = (body.get("meta") or {}).get("cursor")
            if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                raise TypeError("data is not a list of objects")
        except (KeyError, TypeError, AttributeError) as exc:
            raise PresenceError(f"unexpected v2/observations response: {str(body)[:200]}") from exc
        for row in rows:
            stamp = row.get("startTime")
            if not stamp:
                continue
            try:
                when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
            except ValueError as exc:
                raise PresenceError(f"unparseable startTime in v2/observations: {stamp!r}") from exc
            if latest is None or when > latest:
                latest = when
        if not cursor or not rows:
            return latest
        params = {**params, "cursor": cursor}
