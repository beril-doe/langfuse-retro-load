#!/usr/bin/env python3
"""Count and delete Langfuse objects for a named project, without guessing the target.

Two things this exists for.

**Counting.** Every view in the Langfuse UI defaults to a short time window, and this
project's traces are backdated to when the conversation happened. On 2026-09-11 the
`beril-usage` project card read "No traces in the last 30d" while holding 483 traces,
and a traces view set to "Past 1 day" showed "No results" over the same data. Anyone
reading those as totals concludes the project is empty. This prints real totals.

**Deleting by type.** The API has 21 delete operations and it is not obvious which apply
to what. Observations and sessions cannot be deleted at all; media has no delete endpoint
but does go when its trace goes. Asking for something undeletable should say so rather
than silently succeed at nothing.

Usage:

    python3 langfuse_admin.py count  --project cmt1obua000uhad0dxp5tyu49
    python3 langfuse_admin.py delete --project <id> --type trace --dry-run
    python3 langfuse_admin.py delete --project <id> --type trace --name beril.artifact_snapshot --yes
    python3 langfuse_admin.py delete --project <id> --type trace --all --yes

The project id is always explicit. A tool that deletes should never infer its own target
from whichever key happens to be in the environment, which is the same class of mistake
as an idempotency marker that records that work was done but not where it went.

Credentials come from `~/.env`, matched to the project by id: the script looks for any
`<PREFIX>_LANGFUSE_PROJECT_ID` equal to `--project` and uses that prefix's keys. Values
are read in-process and never printed. If an org key is present as
`<PREFIX>_LANGFUSE_ORG_PUBLIC_KEY` / `_SECRET_KEY`, project enumeration becomes possible;
without one, a project key can only ever see its own project.
"""
import argparse
import base64
import datetime
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

HOST = "https://us.cloud.langfuse.com"

#: Every listable object type, and the endpoint that reports a total for it.
#: Endpoints that page by cursor do not return `meta.totalItems`; those are marked so the
#: count falls back to walking pages rather than silently reporting the page size.
COUNTABLE = {
    "trace": ("/api/public/traces", True),
    "observation": ("/api/public/observations", True),
    "session": ("/api/public/sessions", True),
    "score": ("/api/public/v2/scores", True),
    "score-config": ("/api/public/score-configs", True),
    "dataset": ("/api/public/v2/datasets", True),
    "dataset-item": ("/api/public/dataset-items", True),
    "prompt": ("/api/public/v2/prompts", True),
    "annotation-queue": ("/api/public/annotation-queues", True),
    "comment": ("/api/public/comments", True),
    "model": ("/api/public/models", True),
    "llm-connection": ("/api/public/llm-connections", True),
    "dashboard": ("/api/public/unstable/dashboards", True),
    "dashboard-widget": ("/api/public/unstable/dashboard-widgets", True),
}

#: What can actually be removed, and how. Anything absent here has no delete, and saying
#: so is the point: a purge that quietly skips a type is worse than one that refuses.
DELETABLE = {
    "trace": "bulk",       # DELETE /api/public/traces with a traceIds body
    "score": "by-id",
    "dataset-item": "by-id",
    "prompt": "by-name",
    "model": "by-id",
    "llm-connection": "by-id",
    "dashboard": "by-id",
    "dashboard-widget": "by-id",
}

UNDELETABLE_REASON = {
    "observation": "no delete exists at any version. Delete its trace, which takes every observation in it.",
    "session": "not a stored object. It is a string that traces carry, and it stops appearing once its traces are gone.",
    "comment": "no delete endpoint.",
    "media": "no delete endpoint, but media is removed when its trace is deleted (verified 2026-09-11).",
    "annotation-queue": "the queue itself has no delete. Its items and assignments do.",
    "score-config": "no delete endpoint.",
    "dataset": "no delete for the dataset itself. Runs and items can go.",
}


def load_env() -> dict:
    env = {}
    path = Path.home() / ".env"
    if not path.exists():
        return env
    for line in path.read_text(errors="replace").splitlines():
        key, sep, value = line.partition("=")
        key = key.strip().removeprefix("export ")
        if sep and not key.startswith("#"):
            env[key] = value.strip().strip('"').strip("'")
    return env


def auth_for_project(project_id: str) -> str:
    """Find the key whose PROJECT_ID matches. Never fall back to 'the only key present'."""
    env = load_env()
    prefixes = sorted({k.split("_LANGFUSE_")[0] for k in env if "_LANGFUSE_" in k})
    for prefix in prefixes:
        if env.get(f"{prefix}_LANGFUSE_PROJECT_ID") != project_id:
            continue
        public = env.get(f"{prefix}_LANGFUSE_PUBLIC_KEY")
        secret = env.get(f"{prefix}_LANGFUSE_SECRET_KEY")
        if public and secret:
            return "Basic " + base64.b64encode(f"{public}:{secret}".encode()).decode()
    known = [p for p in prefixes if env.get(f"{p}_LANGFUSE_PROJECT_ID")]
    raise SystemExit(
        f"no key in ~/.env names project {project_id}.\n"
        f"prefixes that name a project: {', '.join(known) or '(none)'}\n"
        "A project key sees only its own project. To reach another one, create an "
        "organization API key and add <PREFIX>_LANGFUSE_ORG_PUBLIC_KEY / _SECRET_KEY."
    )


def api(path: str, header: str, data=None, method="GET"):
    request = urllib.request.Request(
        HOST + path,
        data=json.dumps(data).encode() if data is not None else None,
        method=method,
        headers={"Authorization": header, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.status, json.loads(response.read() or b"{}")


def total(path: str, header: str):
    """Real total, or a walked count when the endpoint pages by cursor."""
    try:
        _, body = api(f"{path}?limit=1", header)
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    meta = body.get("meta") or {}
    if "totalItems" in meta:
        return meta["totalItems"]
    seen, page = 0, 1
    while True:
        _, body = api(f"{path}?limit=100&page={page}", header)
        seen += len(body.get("data") or [])
        if page >= (body.get("meta") or {}).get("totalPages", 1):
            return seen
        page += 1


def confirm_project(project_id: str, header: str) -> str:
    _, body = api("/api/public/projects", header)
    for project in body.get("data", []):
        if project["id"] == project_id:
            return f"{project['organization']['name']} / {project['name']}"
    raise SystemExit(f"the key resolved for {project_id} does not actually serve it")


def cmd_count(args) -> int:
    header = auth_for_project(args.project)
    where = confirm_project(args.project, header)
    print(f"{where}  ({args.project})\n")
    print(f"{'object':<20}{'count':>10}")
    for name, (path, _) in COUNTABLE.items():
        print(f"{name:<20}{str(total(path, header)):>10}")
    return 0


def cmd_delete(args) -> int:
    if args.type in UNDELETABLE_REASON:
        print(f"{args.type}: {UNDELETABLE_REASON[args.type]}", file=sys.stderr)
        return 2
    if args.type not in DELETABLE:
        print(f"unknown or undeletable type: {args.type}", file=sys.stderr)
        print(f"deletable: {', '.join(sorted(DELETABLE))}", file=sys.stderr)
        return 2
    if args.type != "trace":
        print(f"{args.type} deletion is not implemented yet; only traces are.", file=sys.stderr)
        return 2
    if not args.name and not args.all:
        print("give --name to match a trace name, or --all to mean every trace", file=sys.stderr)
        return 2

    header = auth_for_project(args.project)
    where = confirm_project(args.project, header)

    traces, page = [], 1
    while True:
        _, body = api(f"/api/public/traces?limit=100&page={page}", header)
        traces += body["data"]
        if page >= (body.get("meta") or {}).get("totalPages", 1):
            break
        page += 1
    targets = traces if args.all else [t for t in traces if t.get("name") == args.name]

    print(f"{where}: {len(traces)} traces, {len(targets)} match")
    if not targets:
        return 0
    stamps = sorted(t["timestamp"] for t in targets if t.get("timestamp"))
    sessions = {t.get("sessionId") for t in targets if t.get("sessionId")}
    print(f"  sessions touched: {len(sessions)}")
    print(f"  date range      : {stamps[0][:19]} to {stamps[-1][:19]}")
    if args.dry_run:
        print("dry run, nothing sent")
        return 0
    if not args.yes:
        print("refusing without --yes", file=sys.stderr)
        return 1

    if args.record:
        Path(args.record).write_text(json.dumps({
            "deleted_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "project": args.project, "where": where,
            "match": "all" if args.all else args.name,
            "count": len(targets),
            "traces": [{"id": t["id"], "sessionId": t.get("sessionId"),
                        "userId": t.get("userId"), "name": t.get("name"),
                        "timestamp": t.get("timestamp")} for t in targets],
        }, indent=2) + "\n")
        print(f"recorded to {args.record}")

    status, body = api("/api/public/traces", header,
                       {"traceIds": [t["id"] for t in targets]}, "DELETE")
    print(f"HTTP {status}: {json.dumps(body)[:200]}")
    print("Deletion is asynchronous. Re-run count to confirm.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    c = sub.add_parser("count", help="count every object type in a project")
    c.add_argument("--project", required=True)
    c.set_defaults(func=cmd_count)

    d = sub.add_parser("delete", help="delete objects of one type")
    d.add_argument("--project", required=True)
    d.add_argument("--type", required=True)
    d.add_argument("--name", help="match traces with this exact name")
    d.add_argument("--all", action="store_true", help="every trace in the project")
    d.add_argument("--dry-run", action="store_true")
    d.add_argument("--yes", action="store_true", help="required for a real delete")
    d.add_argument("--record", help="write a manifest of what is deleted to this path")
    d.set_defaults(func=cmd_delete)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
