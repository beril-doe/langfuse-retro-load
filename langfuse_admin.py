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
    python3 langfuse_admin.py delete --project <id> --type trace --all --dry-run
    python3 langfuse_admin.py delete --project <id> --type trace --name beril.artifact_snapshot --yes
    python3 langfuse_admin.py projects --org BERIL          # needs an organization key

The project id is always explicit. A tool that deletes should never infer its own target
from whichever key happens to be in the environment, which is the same class of mistake
as an idempotency marker that records that work was done but not where it went.

Credentials come from a `.env` beside this script if one exists, otherwise `~/.env`. That
order matches the repo's documented setup, which puts a `.env` next to `retro_load.py` on
the pod. The script looks for any `<PREFIX>_LANGFUSE_PROJECT_ID` equal to `--project` and
uses that prefix's keys. Values are read in-process and never printed.

The host follows the same prefix: `<PREFIX>_LANGFUSE_BASE_URL` or `<PREFIX>_LANGFUSE_HOST`,
falling back to the unprefixed names and finally to US cloud. An EU or self-hosted project
would otherwise be queried at the wrong service and silently report nothing.

Organization keys are used by `projects` only. `count` and `delete` still need a project
key for the project named, because this script does not mint one.
"""
import argparse
import base64
import datetime
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_HOST = "https://us.cloud.langfuse.com"

#: Langfuse rejects a bulk delete body with more than this many traceIds.
BULK_DELETE_LIMIT = 1000

#: Every listable object type, and the endpoint that reports a total for it.
#: Endpoints that page by cursor do not return `meta.totalItems`; those are marked so the
#: count falls back to walking pages rather than silently reporting the page size.
#: Traces are the one endpoint that can apply a server-configured default date
#: window when fromTimestamp is absent (LANGFUSE_API_TRACES_DEFAULT_DATE_RANGE_DAYS
#: on a self-hosted deployment). This tool exists because short windows hide
#: backdated data, so inheriting one silently would be the exact defect it prevents.
#:
#: Passing a lower bound is not a free fix. Measured on the NMDC project 2026-09-11:
#: unbounded returns 71 traces, fromTimestamp=2000-01-01 returns 70, reproducibly.
#: Something is excluded by the bound. So ask both ways and take the larger,
#: reporting when they disagree rather than silently choosing.
ALL_TIME = "1970-01-01T00:00:00Z"

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
    # Named so they report "not implemented" rather than falling through to "unknown
    # type", which would contradict UNDELETABLE_REASON saying these can be deleted.
    "annotation-queue-item": "by-id",
    "annotation-queue-assignment": "by-id",
    "dataset-run": "by-name",
}

UNDELETABLE_REASON = {
    "observation": "no delete exists at any version. Delete its trace, which takes every observation in it.",
    "session": ("no delete endpoint exists. A session is a label traces carry, but deleting "
                "every trace does not clear it: beril-usage reported 103 sessions with 0 traces "
                "and 0 observations on 2026-09-11. Whether they are eventually collected is "
                "unknown, so do not plan on it."),
    "comment": "no delete endpoint.",
    "media": "no delete endpoint, but media is removed when its trace is deleted (verified 2026-09-11).",
    "annotation-queue": "the queue itself has no delete. Its items and assignments do.",
    "score-config": "no delete endpoint.",
    "dataset": "no delete for the dataset itself. Runs and items can go.",
}


def load_env() -> tuple[dict, Path | None]:
    """A .env beside this script wins over ~/.env, matching the documented pod setup.

    Returns the file actually read, so an error can name it. Saying "~/.env" when a
    local .env shadowed it sends the operator to edit the wrong credential file.
    """
    env = {}
    local = Path(__file__).resolve().parent / ".env"
    path = local if local.exists() else Path.home() / ".env"
    if not path.exists():
        return env, None
    for line in path.read_text(errors="replace").splitlines():
        key, sep, value = line.partition("=")
        key = key.strip().removeprefix("export ")
        if sep and not key.startswith("#"):
            env[key] = value.strip().strip('"').strip("'")
    return env, path


def auth_for_project(project_id: str) -> tuple[str, str]:
    """Find the key whose PROJECT_ID matches, and the host that goes with it.

    Never falls back to "the only key present". Returns (auth header, host).
    """
    env, source = load_env()
    prefixes = sorted({k.split("_LANGFUSE_")[0] for k in env if "_LANGFUSE_" in k})
    for prefix in prefixes:
        if env.get(f"{prefix}_LANGFUSE_PROJECT_ID") != project_id:
            continue
        public = env.get(f"{prefix}_LANGFUSE_PUBLIC_KEY")
        secret = env.get(f"{prefix}_LANGFUSE_SECRET_KEY")
        if public and secret:
            host = (env.get(f"{prefix}_LANGFUSE_BASE_URL") or env.get(f"{prefix}_LANGFUSE_HOST")
                    or env.get("LANGFUSE_BASE_URL") or env.get("LANGFUSE_HOST") or DEFAULT_HOST)
            header = "Basic " + base64.b64encode(f"{public}:{secret}".encode()).decode()
            return header, host.rstrip("/")
    known = [p for p in prefixes if env.get(f"{p}_LANGFUSE_PROJECT_ID")]
    raise SystemExit(
        f"no key in {source or '(no .env found)'} names project {project_id}.\n"
        f"prefixes that name a project: {', '.join(known) or '(none)'}\n"
        "count and delete need a PROJECT key for that project specifically. Add\n"
        "<PREFIX>_LANGFUSE_PROJECT_ID, _PUBLIC_KEY and _SECRET_KEY for it. An\n"
        "organization key does not help here; it is only used by `projects`."
    )


def api(path: str, header: str, host: str, data=None, method="GET"):
    request = urllib.request.Request(
        host + path,
        data=json.dumps(data).encode() if data is not None else None,
        method=method,
        headers={"Authorization": header, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.status, json.loads(response.read() or b"{}")


def total(path: str, header: str, host: str) -> tuple[object, str | None]:
    """Return (count, note). A count of None means it could not be counted.

    A note with a count present is information, not failure.

    Three shapes of response. `meta.totalItems` is the easy case. `meta.totalPages` means
    page-numbered, so walk pages. Anything else is cursor-paged, and walking it by page
    number would silently re-read page one forever, so report that we cannot count it
    rather than return a number that looks fine and is wrong.
    """
    try:
        _, body = api(f"{path}?limit=1", header, host)
        if path.endswith("/traces"):
            # See ALL_TIME. Ask both ways; disagreement means one of them is filtered.
            _, bounded = api(f"{path}?limit=1&fromTimestamp={ALL_TIME}", header, host)
            a = (body.get("meta") or {}).get("totalItems")
            b = (bounded.get("meta") or {}).get("totalItems")
            if a is not None and b is not None and a != b:
                return max(a, b), f"unbounded={a}, from {ALL_TIME[:10]}={b}; reporting the larger"
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except OSError as exc:
        return None, type(exc).__name__
    meta = body.get("meta") or {}
    if "totalItems" in meta:
        return meta["totalItems"], None
    if "totalPages" not in meta:
        return None, "cursor-paged, no total reported"
    seen, page = 0, 1
    while True:
        try:
            _, body = api(f"{path}?limit=100&page={page}", header, host)
        except urllib.error.HTTPError as exc:
            return None, f"HTTP {exc.code} on page {page}"
        except OSError as exc:
            # A timeout on page 2 should mark this type uncountable and let the rest
            # of the inventory finish, not abort the whole command.
            return None, f"{type(exc).__name__} on page {page}"
        seen += len(body.get("data") or [])
        if page >= (body.get("meta") or {}).get("totalPages", 1):
            return seen, None
        page += 1


def confirm_project(project_id: str, header: str, host: str) -> str:
    _, body = api("/api/public/projects", header, host)
    for project in body.get("data", []):
        if project["id"] == project_id:
            return f"{project['organization']['name']} / {project['name']}"
    raise SystemExit(f"the key resolved for {project_id} does not actually serve it")


def cmd_count(args) -> int:
    header, host = auth_for_project(args.project)
    where = confirm_project(args.project, header, host)
    print(f"{where}  ({args.project})  at {host}\n")
    print(f"{'object':<20}{'count':>10}  {'note'}")
    failed = []
    for name, (path, _) in COUNTABLE.items():
        count, note = total(path, header, host)
        # A note alongside a count is information, not failure. Only a missing count
        # means the type could not be counted.
        if count is None:
            failed.append((name, note))
            print(f"{name:<20}{'-':>10}  {note}")
        else:
            print(f"{name:<20}{count:>10}" + (f"  {note}" if note else ""))
    if failed:
        # Exit nonzero so a caller checking status is not told an incomplete count
        # succeeded. This is the whole point: a silent partial count is worse than none.
        print(f"\n{len(failed)} object type(s) could not be counted", file=sys.stderr)
        return 1
    return 0


def cmd_projects(args) -> int:
    """List every project in an organization. Needs an organization key."""
    env, _ = load_env()
    prefix = args.org.upper()
    public = env.get(f"{prefix}_LANGFUSE_ORG_PUBLIC_KEY")
    secret = env.get(f"{prefix}_LANGFUSE_ORG_SECRET_KEY")
    if not (public and secret):
        print(f"no {prefix}_LANGFUSE_ORG_PUBLIC_KEY / _SECRET_KEY found.\n"
              "A project key cannot enumerate its siblings: /api/public/organizations/projects\n"
              "returns 403 with one. Create an organization API key in the Langfuse UI under\n"
              "the organization's settings.", file=sys.stderr)
        return 2
    # Same resolution as auth_for_project. Omitting the _HOST forms sent an
    # organization key to US cloud for a self-hosted or EU organization.
    host = (env.get(f"{prefix}_LANGFUSE_BASE_URL") or env.get(f"{prefix}_LANGFUSE_HOST")
            or env.get("LANGFUSE_BASE_URL") or env.get("LANGFUSE_HOST")
            or DEFAULT_HOST).rstrip("/")
    header = "Basic " + base64.b64encode(f"{public}:{secret}".encode()).decode()
    try:
        _, body = api("/api/public/organizations/projects", header, host)
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}. An organization key is required here, not a project key.",
              file=sys.stderr)
        return 1
    # The organization endpoint returns its array under "projects" while the
    # project endpoint uses "data". Accept either rather than silently print
    # nothing, which is what reading only "data" did.
    found = body.get("projects") or body.get("data") or []
    if not found:
        print("no projects returned", file=sys.stderr)
        return 1
    for project in found:
        print(f"{project['id']}  {project.get('name')}")
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
    # Checked here rather than by argparse, so an undeletable type reaches its
    # explanation above instead of dying on a missing selector.
    if not args.name and not args.all:
        print("give --name to match a trace name, or --all to mean every trace",
              file=sys.stderr)
        return 2
    header, host = auth_for_project(args.project)
    where = confirm_project(args.project, header, host)

    traces, page = [], 1
    while True:
        # Explicit lower bound so --all cannot enumerate only a recent subset on a
        # deployment with a default window, then report it as the whole project.
        _, body = api(f"/api/public/traces?limit=100&page={page}&fromTimestamp={ALL_TIME}",
                      header, host)
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
            # Named for what it is. The DELETE below is asynchronous, so this is when the
            # request was made, not when anything was removed. A field called deleted_at
            # would be read later as evidence that it completed.
            "delete_requested_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "project": args.project, "where": where, "host": host,
            "match": "all" if args.all else args.name,
            "count": len(targets),
            "traces": [{"id": t["id"], "sessionId": t.get("sessionId"),
                        "userId": t.get("userId"), "name": t.get("name"),
                        "timestamp": t.get("timestamp")} for t in targets],
        }, indent=2) + "\n")
        print(f"recorded to {args.record}")

    # Langfuse rejects a bulk body carrying more than 1,000 traceIds. The two real
    # deletions on 2026-09-11 were 67 and 483, both under it, so this never showed up.
    # A larger project would have received HTTP 400 and deleted nothing.
    ids = [t["id"] for t in targets]
    batches = [ids[i:i + BULK_DELETE_LIMIT] for i in range(0, len(ids), BULK_DELETE_LIMIT)]
    for n, batch in enumerate(batches, 1):
        label = f"batch {n}/{len(batches)}" if len(batches) > 1 else "all"
        # urlopen raises HTTPError for any 4xx or 5xx, so api() never returns a failing
        # status and a `if status >= 300` branch here could never execute. A rejected
        # batch used to end in a traceback instead of this message.
        try:
            status, body = api("/api/public/traces", header, host, {"traceIds": batch}, "DELETE")
        except urllib.error.HTTPError as exc:
            print(f"  {label}: {len(batch)} traces, HTTP {exc.code}", file=sys.stderr)
            print("stopping: a batch was rejected, later batches not sent", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"  {label}: {type(exc).__name__}", file=sys.stderr)
            print("stopping: a batch failed to send, later batches not sent", file=sys.stderr)
            return 1
        print(f"  {label}: {len(batch)} traces, HTTP {status}: {json.dumps(body)[:120]}")
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
    # Mutually exclusive but NOT required at parse time. Requiring it here meant
    # `delete --type observation` died on "one of --name/--all is required" and never
    # reached the explanation that observations cannot be deleted at all. The type
    # checks run first now, and cmd_delete requires a selector afterwards.
    selector = d.add_mutually_exclusive_group(required=False)
    selector.add_argument("--name", help="match traces with this exact name")
    selector.add_argument("--all", action="store_true", help="every trace in the project")
    d.add_argument("--dry-run", action="store_true")
    d.add_argument("--yes", action="store_true", help="required for a real delete")
    d.add_argument("--record", help="write a manifest of what is deleted to this path")
    d.set_defaults(func=cmd_delete)

    p = sub.add_parser("projects", help="list an organization's projects (needs an org key)")
    p.add_argument("--org", required=True, help="env prefix, e.g. BERIL or NMDC")
    p.set_defaults(func=cmd_projects)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
