# Every operation in this repo, with its preconditions stated.
#
# These scripts read and write a shared Langfuse project, and some of them
# delete from it. A command you half remember is how the wrong thing gets sent,
# so each one lives here rather than in someone's shell history.
#
# uv is not yet installed on the BERDL pod, where these actually run. Until it
# is, PY resolves to plain python3 there. See issue #15.
#
# Two recipes call scripts that are not on main yet: scan and scan-detail need
# scan_transcript.py from pull request #6, and count, projects, delete-dry and
# delete need langfuse_admin.py from pull request #9. They check and say so
# rather than failing with "no such file".

# Two forms, because they are not interchangeable. PY runs a script file.
# PYBIN is an interpreter you can pass -c to: `uv run -c ...` is not valid, uv
# reads -c as its own flag.
PY := `command -v uv >/dev/null 2>&1 && echo "uv run" || echo "python3"`
PYBIN := `command -v uv >/dev/null 2>&1 && echo "uv run python" || echo "python3"`

# List the targets.
default:
    @just --list

# Reproduce the environment. No-op where uv is unavailable.
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    # Not `uv sync || echo`: that turns a resolver or network failure into success.
    if [ ! -f pyproject.toml ]; then
      echo "no pyproject.toml on this branch; it is in pull request #8" >&2; exit 2
    fi
    if command -v uv >/dev/null 2>&1; then uv sync
    else echo "uv not installed; using the ambient python3 (issue #15)"; fi

# Reads the roots from people.json rather than a hardcoded path, because
# build_manifest.py loads all of them and a partial scan reports clean.

# Scan every transcript a load would touch, across all find_roots
scan:
    #!/usr/bin/env bash
    set -euo pipefail
    # No mapfile: macOS ships bash 3.2, where it does not exist, and this has to
    # run both here and on the pod.
    roots=()
    while IFS= read -r line; do roots+=("$line"); done < <({{PYBIN}} -c "import json,pathlib;[print(pathlib.Path(s['find_root']).expanduser()) for p in json.load(open('people.json')) for s in p['sources']]")
    files=()
    # Abort on a missing root rather than skipping it. Scanning whichever roots
    # happen to exist and exiting 0 is the partial scan this recipe exists to stop.
    missing=0
    for r in "${roots[@]}"; do
      if [ ! -d "$r" ]; then echo "missing root: $r" >&2; missing=1; continue; fi
      # find's exit status is lost inside process substitution, so an unreadable
      # subtree yields a partial list and the recipe still exits 0. Capture first.
      tmp=$(mktemp); if ! find "$r" -maxdepth 2 -type f -name '*.jsonl' -print0 > "$tmp"; then
        rm -f "$tmp"; echo "find failed under $r; the scan would be partial" >&2; exit 2
      fi
      while IFS= read -r -d '' f; do files+=("$f"); done < "$tmp"; rm -f "$tmp"
    done
    [ "$missing" -eq 0 ] || { echo "refusing: at least one find_root in people.json is not present here, so this scan would be partial" >&2; exit 2; }
    [ ${#files[@]} -gt 0 ] || { echo "no transcripts found under any find_root" >&2; exit 2; }
    [ -f scan_transcript.py ] || { echo "scan_transcript.py is not on this branch; it is in pull request #6" >&2; exit 2; }
    echo "scanning ${#files[@]} transcripts"
    {{PY}} scan_transcript.py --quiet "${files[@]}"

# The detail file holds exactly what the scan exists to find. Never commit it.

# Scan one file and write matched context for review
scan-detail FILE OUT="scan-detail.txt":
    @test -f scan_transcript.py || (echo "scan_transcript.py is not on this branch; it is in pull request #6" >&2; exit 2)
    @{{PY}} scan_transcript.py --detail {{quote(OUT)}} {{quote(FILE)}}

# Overwrites the committed manifest.json from the find_roots on THIS machine.
# Off the pod that means your own ~/.claude, which is not the corpus, so this
# refuses unless the frozen-corpus root is present.

# Rebuild manifest.json from people.json (pod only)
manifest:
    #!/usr/bin/env bash
    set -euo pipefail
    # Every root of every type, not just the frozen-corpus ones. build_manifest.py
    # processes all sources, so an absent pod-live root produces a manifest missing
    # those sessions while both frozen roots are present and this check passes.
    missing=$({{PYBIN}} -c "import json,pathlib;print(sum(1 for p in json.load(open('people.json')) for s in p['sources'] if not pathlib.Path(s['find_root']).expanduser().is_dir()))")
    if [ "$missing" != "0" ]; then
      echo "refusing: $missing find_root(s) in people.json are not present here, so this would rebuild" >&2
      echo "manifest.json from a partial set and commit the wrong thing. Run it on the pod." >&2
      exit 2
    fi
    {{PY}} build_manifest.py

# Show what a load would send. Always run this first.
load-dry:
    {{PY}} run_manifest.py --dry-run

# Markers in ~/.retro_load_markers/ make this resumable, and also make it
# silently skip anything already marked, including entries that went to a
# different project. Pass FORCE=--force after a purge.

# Backgrounded with nohup, as README.md has always said: a terminal or browser
# hiccup should not kill a load partway through. Watch full_load_run.txt.

# Load for real, in the background
load FORCE="" TAG="":
    nohup {{PY}} run_manifest.py {{FORCE}} {{ if TAG != "" { "--batch-tag " + quote(TAG) } else { "" } }} > full_load_run.txt 2>&1 &
    @echo "started; follow with: tail -f full_load_run.txt"

# Needs --session on run_manifest.py, which is in pull request #6.

# Load only named sessions. Unknown ids are a hard error
load-sessions FORCE="" TAG="" +IDS="":
    #!/usr/bin/env bash
    set -euo pipefail
    # IDS has an empty default so FORCE and TAG can be optional, and run_manifest.py
    # reads an absent --session as "the whole manifest". Without this check,
    # `just load-sessions` is a full production load wearing the name of a narrow one.
    # No backticks in these strings. An earlier version wrote "Use `just load`" here
    # and bash executed it as a command substitution, so the refusal message started
    # a full background load. Off-pod it failed on missing roots; on the pod it would
    # have run the entire manifest from the recipe written to prevent exactly that.
    [ -n "{{IDS}}" ] || { echo "refusing: no session ids given. This recipe loads named sessions, and run_manifest.py with no --session loads everything. Run 'just load' if a full load is what you want." >&2; exit 2; }
    grep -q '"--session"' run_manifest.py || { echo "run_manifest.py has no --session on this branch; it is in pull request #6" >&2; exit 2; }
    # Without --force this silently does nothing for exactly the sessions you would
    # want it for: --session filters the manifest, it does not override a marker.
    [ -n "{{FORCE}}" ] || echo "note: no FORCE given, so any session with a marker will be skipped" >&2
    {{PY}} run_manifest.py {{FORCE}} {{ if TAG != "" { "--batch-tag " + quote(TAG) } else { "" } }} {{ prepend("--session ", IDS) }}

# Needs langfuse_admin.py, which is not on main yet: see pull request #9.
# The web interface defaults to a short time window and this corpus is
# backdated, so what it shows are not totals.

# Real totals for every object type in a project
count PROJECT:
    @test -f langfuse_admin.py || (echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2)
    {{PY}} langfuse_admin.py count --project {{quote(PROJECT)}}

# A project key cannot see its siblings, so this needs an organization key.

# List an organization's projects
projects ORG:
    @test -f langfuse_admin.py || (echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2)
    {{PY}} langfuse_admin.py projects --org {{quote(ORG)}}

# Show what a deletion would remove.
delete-dry PROJECT TYPE="trace" NAME="":
    @test -f langfuse_admin.py || (echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2)
    {{PY}} langfuse_admin.py delete --project {{quote(PROJECT)}} --type {{quote(TYPE)}} {{ if NAME != "" { "--name " + quote(NAME) } else { "--all" } }} --dry-run

# NAME is required. An earlier version defaulted it to empty and therefore passed
# --all --yes, so `just delete <project>` deleted every trace with no confirmation,
# undoing the explicit selector langfuse_admin.py requires. Whole-project deletion
# has its own recipe below.

# Delete traces with one exact name
delete PROJECT NAME TYPE="trace" RECORD="":
    #!/usr/bin/env bash
    set -euo pipefail
    # The shebang must be the recipe's first line. With a guard line above it, Just
    # runs every line in its own shell, so `set -euo pipefail` governs nothing and
    # `rec` below never reaches the command that uses it: --record would be empty and
    # no audit manifest would be written at all.
    test -f langfuse_admin.py || { echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2; }
    # A fixed default record path meant each deletion overwrote the previous one's
    # pre-delete manifest, which is the only audit artifact these commands produce.
    rec="{{RECORD}}"; [ -n "$rec" ] || rec="deletion-record-$(date -u +%Y%m%dT%H%M%SZ).json"
    {{PY}} langfuse_admin.py delete --project {{quote(PROJECT)}} --type {{quote(TYPE)}} --name {{quote(NAME)}} --record "$rec" --yes

# CONFIRM must repeat the project id. Nothing here should be reachable by
# autocomplete or by leaving an argument off.

# Delete every trace in a project
delete-all PROJECT CONFIRM TYPE="trace" RECORD="":
    #!/usr/bin/env bash
    set -euo pipefail
    test -f langfuse_admin.py || { echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2; }
    [ "{{CONFIRM}}" = "{{PROJECT}}" ] || { echo "refusing: pass the project id twice to confirm deleting everything" >&2; exit 2; }
    rec="{{RECORD}}"; [ -n "$rec" ] || rec="deletion-record-all-$(date -u +%Y%m%dT%H%M%SZ).json"
    {{PY}} langfuse_admin.py delete --project {{quote(PROJECT)}} --type {{quote(TYPE)}} --all --record "$rec" --yes
