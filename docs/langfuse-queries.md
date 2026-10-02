# Querying the backfilled traces in Langfuse

These are worked queries over the Langfuse project beril-usage, for anyone checking what the
retro-load put there. Every count below came from running the query once on 2026-10-02.
The counts change as more people are loaded. The status page,
[backfill-status.md](backfill-status.md), keeps the current totals and the deletion log.
This page is public, so it shows counts only, never names, account names or ORCIDs.

## Before you start

- **Credentials:** run from a checkout of this repository, with the same Langfuse keys
  `langfuse_admin.py` uses. It finds them itself and never prints them.
- **The UI hides backdated traces:** every Langfuse view defaults to a recent time window, but
  retro-loaded traces are dated when the conversation happened (May 2026). Set the date range
  to include 2026-05-07, or a view will show no results over data that is there.
- **Read through observations, not `/api/public/traces`:** Langfuse removes the
  `/api/public/traces`, `/observations` and `/sessions` routes from Cloud on 2026-11-16 (see
  the note in `langfuse_admin.py`). The examples use `enumerate_traces`, which builds each
  trace from `/api/public/v2/observations`.

## 1. Totals for the project

```bash
uv run python langfuse_admin.py count --project beril
```

On 2026-10-02 this gave 731 traces, 11,271 observations and 150 sessions.

## 2. Retro-loaded traces, turns and artifact spans

Every retro-loaded trace carries the tag `retro-load`. Artifact spans also carry `artifacts`,
`beril` and the project name. Each consenter's turns also carry their batch tag,
`backfill-<account>-<date>`.

```bash
uv run python - <<'PY'
import langfuse_admin as la
project_id, prefix = la.resolve_project("beril")
header, host = la.auth_for_project(project_id, prefix)
traces = la.enumerate_traces(header, host, None)
retro = [t for t in traces if "retro-load" in t["tags"]]
spans = [t for t in retro if "artifacts" in t["tags"]]
turns = [t for t in retro if "artifacts" not in t["tags"]]
day = [t for t in turns if (t["timestamp"] or "").startswith("2026-05-07")]
print("all", len(traces), "retro-load", len(retro), "turns", len(turns),
      "artifact spans", len(spans), "turns on the day", len(day))
PY
```

On 2026-10-02 this gave the following:

| what | count |
|---|---|
| all traces | 731 |
| retro-loaded (`retro-load`) | 717 |
| retro-loaded turns | 694 |
| retro-loaded artifact spans (`retro-load` and `artifacts`) | 23 |
| turns dated 2026-05-07, UTC | 634 |
| turns on other days | 60 |

The 60 other-day turns all belong to the BERIL developer and are kept by decision. Everyone
else is loaded for the workshop day only. To filter on the server instead, pass tags:
`la.enumerate_traces(header, host, None, ["retro-load", "artifacts"])` returns the 23 spans
without reading the rest.

## 3. Workshop-day turns and artifact spans per person

```bash
uv run python - <<'PY'
import collections, langfuse_admin as la
project_id, prefix = la.resolve_project("beril")
header, host = la.auth_for_project(project_id, prefix)
retro = la.enumerate_traces(header, host, None, ["retro-load"])
day = collections.Counter(t["userId"] for t in retro
                          if "artifacts" not in t["tags"]
                          and (t["timestamp"] or "").startswith("2026-05-07"))
spans = collections.Counter(t["userId"] for t in retro if "artifacts" in t["tags"])
for n, (user, count) in enumerate(day.most_common(), 1):
    print(f"person {n:2}: {count:3} turns, {spans[user]} artifact spans")
PY
```

User ids are ORCIDs, so the code numbers people instead of printing them. On 2026-10-02,
16 people had workshop-day turns:

| person | workshop-day turns | artifact spans |
|---|---|---|
| 1 | 82 | 4 |
| 2 | 70 | 3 |
| 3 | 54 | 3 |
| 4 | 53 | 1 |
| 5 | 53 | 1 |
| 6 | 46 | 2 |
| 7 | 46 | 1 |
| 8 | 41 | 1 |
| 9 | 40 | 1 |
| 10 | 34 | 0 |
| 11 | 28 | 1 |
| 12 | 23 | 1 |
| 13 | 20 | 1 |
| 14 | 19 | 1 |
| 15 | 18 | 1 |
| 16 | 7 | 1 |

## 4. One person's traces and sessions

The user id is the person's ORCID, as BERIL's live hook records it.

```bash
uv run python - <<'PY'
import langfuse_admin as la
ORCID = "0000-0000-0000-0000"   # the person's ORCID
project_id, prefix = la.resolve_project("beril")
header, host = la.auth_for_project(project_id, prefix)
mine = [t for t in la.enumerate_traces(header, host, None, ["retro-load"])
        if t["userId"] == ORCID]
print(len(mine), "traces in", len({t["sessionId"] for t in mine}), "sessions")
PY
```

For the person with the most turns, this gave 86 traces (82 turns and 4 artifact spans) in 15
sessions. In the Langfuse UI, the same view is Traces, filtered on User ID.

To list what a deletion would remove, without removing anything, use a dry run:
`langfuse_admin.py delete --project beril --type trace --tag retro-load --user-id <orcid> --dry-run`.
It prints the count, the sessions touched and the date range.

## 5. Retro-loaded traces next to live BERIL traces

Traces sent by BERIL's live hook have no `retro-load` tag:

```bash
uv run python - <<'PY'
import collections, langfuse_admin as la
project_id, prefix = la.resolve_project("beril")
header, host = la.auth_for_project(project_id, prefix)
live = [t for t in la.enumerate_traces(header, host, None) if "retro-load" not in t["tags"]]
print(len(live), "traces,", len({t["sessionId"] for t in live if t["sessionId"]}), "sessions,",
      len({t["userId"] for t in live if t["userId"]}), "users")
print(collections.Counter("artifacts" if "artifacts" in t["tags"] else "turn" for t in live))
PY
```

On 2026-10-02 this gave 14 traces in 5 sessions from 1 user: 9 turns and 5 artifact spans.
All of them are the BERIL developer's tests of the live hook, so beril-usage holds no live
workshop traffic to compare against yet. Both kinds of trace have the same shape: turn traces
named `Claude Code - Turn <n>` and artifact spans named `BERIL artifacts — <project>`. So a
query that works on one works on the other, with the `retro-load` tag as the only filter.
