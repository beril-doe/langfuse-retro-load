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
    @command -v uv >/dev/null 2>&1 && uv sync || echo "uv not installed; using the ambient python3 (issue #15)"

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
    for r in "${roots[@]}"; do
      [ -d "$r" ] || { echo "missing root, skipping: $r" >&2; continue; }
      while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$r" -maxdepth 2 -type f -name '*.jsonl' -print0)
    done
    [ ${#files[@]} -gt 0 ] || { echo "no transcripts found under any find_root" >&2; exit 2; }
    [ -f scan_transcript.py ] || { echo "scan_transcript.py is not on this branch; it is in pull request #6" >&2; exit 2; }
    echo "scanning ${#files[@]} transcripts"
    {{PY}} scan_transcript.py --quiet "${files[@]}"

# The detail file holds exactly what the scan exists to find. Never commit it.

# Scan one file and write matched context for review
scan-detail FILE OUT="scan-detail.txt":
    @test -f scan_transcript.py || (echo "scan_transcript.py is not on this branch; it is in pull request #6" >&2; exit 2)
    {{PY}} scan_transcript.py --detail {{OUT}} {{FILE}}

# Overwrites the committed manifest.json from the find_roots on THIS machine.
# Off the pod that means your own ~/.claude, which is not the corpus, so this
# refuses unless the frozen-corpus root is present.

# Rebuild manifest.json from people.json (pod only)
manifest:
    #!/usr/bin/env bash
    set -euo pipefail
    frozen=$({{PYBIN}} -c "import json,pathlib;print(next((pathlib.Path(s['find_root']).expanduser() for p in json.load(open('people.json')) for s in p['sources'] if s['type']=='workshop-frozen-corpus'), ''))")
    if [ -z "$frozen" ] || [ ! -d "$frozen" ]; then
      echo "refusing: the frozen-corpus root is not present here, so this would rebuild" >&2
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

# Load for real
load FORCE="" TAG="":
    {{PY}} run_manifest.py {{FORCE}} {{ if TAG != "" { "--batch-tag " + TAG } else { "" } }}

# Load only named sessions. Unknown ids are a hard error.
load-sessions +IDS:
    {{PY}} run_manifest.py {{ prepend("--session ", IDS) }}

# Needs langfuse_admin.py, which is not on main yet: see pull request #9.
# The web interface defaults to a short time window and this corpus is
# backdated, so what it shows are not totals.

# Real totals for every object type in a project
count PROJECT:
    @test -f langfuse_admin.py || (echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2)
    {{PY}} langfuse_admin.py count --project {{PROJECT}}

# A project key cannot see its siblings, so this needs an organization key.

# List an organization's projects
projects ORG:
    @test -f langfuse_admin.py || (echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2)
    {{PY}} langfuse_admin.py projects --org {{ORG}}

# Show what a deletion would remove.
delete-dry PROJECT TYPE="trace" NAME="":
    @test -f langfuse_admin.py || (echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2)
    {{PY}} langfuse_admin.py delete --project {{PROJECT}} --type {{TYPE}} {{ if NAME != "" { "--name " + NAME } else { "--all" } }} --dry-run

# Writes a record of what is going before anything goes.

# Delete for real
delete PROJECT TYPE="trace" NAME="" RECORD="deletion-record.json":
    @test -f langfuse_admin.py || (echo "langfuse_admin.py is not on this branch; it is in pull request #9" >&2; exit 2)
    {{PY}} langfuse_admin.py delete --project {{PROJECT}} --type {{TYPE}} {{ if NAME != "" { "--name " + NAME } else { "--all" } }} --record {{RECORD}} --yes
