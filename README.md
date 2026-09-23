# BERIL Langfuse retro-load

Loads already-completed Claude Code sessions into BERIL's Langfuse org,
backdating each step to when the conversation actually happened instead of
only capturing new sessions going forward.

For how this work and Dileep's BERIL live tracing benefit each other, see the
[reuse accounting and handoff](docs/live-tracing-handoff.md) and
[implementation tracker #30](https://github.com/beril-doe/langfuse-retro-load/issues/30).

## Before anything else: this has to run on the pod, not your laptop

The source transcripts live on the BERDL pod, and some of them (the frozen
2026-05-07 hackathon corpus) are other people's data. **Never copy raw
`.jsonl` off the pod**: it can contain anything anyone pasted into a
session. Every script here reads transcripts and talks to Langfuse's API
directly from wherever it runs; it never needs to move a transcript
anywhere. Push these files to the pod (`labctl pod put`, or however you
transfer files there) and run everything from a pod terminal.

## The pieces

- **`langfuse_hook_official.py`**: Langfuse's own official Claude Code
  integration hook, vendored unmodified from
  [their integration page](https://langfuse.com/integrations/developer-tools/claude-code).
  Does the actual turn-reconstruction and timestamp-backdating. Depends on
  `langfuse>=4.0,<5` internals (`_otel_tracer`,
  `_create_observation_from_otel_span`) that aren't in the public SDK API,
  so pin the version: a future major release could rename them.
- **`retro_load.py`**: loads one transcript file, given its path directly.
  `--dry-run` prints turn count and per-turn timestamps only, never message
  content, so it's safe to run against anyone's data, including the frozen corpus.
  Real runs write an idempotency marker to `~/.retro_load_markers/` (keyed
  by a hash of the resolved source path, not a sibling file, since the frozen
  corpus isn't writable by any individual account) so re-running against an
  already-loaded file reports "already retro-loaded" instead of duplicating
  it in Langfuse.
- **`people.json`**: the only file you edit to add a new person or source.
  See below.
- **`build_manifest.py`** / **`run_manifest.py`**: `build_manifest.py`
  reads `people.json`, discovers every session under each source's
  `find_root`, and runs `retro_load.py --dry-run` on each to work out turn
  counts and tags automatically, writing `manifest.json`. `run_manifest.py`
  reads that manifest and drives the real loads. This replaces hand-typing
  `--tag` flags per file, which doesn't scale and is easy to get wrong.

- **`redaction.py`**: detection and redaction of sensitive spans, as a pure
  function. No file handling, no Langfuse, no clock. This is the reusable
  engine for this repository; adapting it to BERIL's live masking policy and
  other filtering points remains tracked in #30.
- **`plan.py`**: builds the redaction plan a load applies, and applies it. See "The
  redaction plan" below.
- **`inventory.py`**: the screening pass. Writes one row per finding, says
  where each one is, and gives `retro_load.py` the means to leave out a value
  rather than a session. See the next section.

## Screening what goes out

`retro_load.py` screens by default. Every record still goes out; the values
that carry a secret or someone's personal details are replaced in place, one
value at a time. A real load requires `--plan` unless explicitly bypassed with
`--without-plan`; `--no-redact` is incompatible with a plan.

That is the whole design decision. The scanner proposed in
[#6](https://github.com/beril-doe/langfuse-retro-load/pull/6) answers one
question per file, as an exit status, which leaves a loader with two options:
send all of it or send none of it. Langfuse observations are immutable once
ingested and the only delete removes an entire trace, so "none of it" is the
one that gets used, and a session's research is dropped because a tool result
forty turns in printed an environment variable.

```
# Screen only: no Langfuse calls, writes the inventory and a report
python3 inventory.py --out inv.jsonl --report report.md ~/.claude/projects/*/*.jsonl

# Screen a project snapshot before attaching it as Langfuse media
python3 inventory.py --out assets.jsonl --asset-root projects/ projects/p1/**/*

# Build and review a plan first (see the next section), then load it. Keep the
# load inventory separate: the loader would overwrite the preflight inventory.
python3 retro_load.py --plan plan.jsonl --inventory load-inv.jsonl session.jsonl
```

Each row is addressed by session id, record number, and an RFC 6901 JSON
pointer to the exact value, so a caller can rewrite one value, drop one
observation, or drop one record, and still emit everything around it.
`inventory.excluded_paths()` returns those pointers grouped by record.

**No row carries matched text, a value, an absolute path, or the fingerprint
key.** Standalone inventory fingerprints use HMAC-SHA256 with a random,
unstored key per run. Plan fingerprints instead use the transcript hash as
the key so clearances remain stable for the same transcript. Matching
fingerprints group findings within that key scope; they do not authenticate
a reviewer. One token in 41 records is one thing to rotate; 41 unrelated
findings is a different afternoon. It also means the inventory needs no
special file permissions, unlike the `--detail` file in
[#6](https://github.com/beril-doe/langfuse-retro-load/pull/6), whose whole
purpose is to hold the material being looked for.

Two detectors, union, per
https://github.com/beril-doe/langfuse-retro-load/issues/10. Both run at scan time, in
`inventory.py` and in `plan.py build`. `retro_load.py` never invokes gitleaks itself, but
with `--plan` it applies gitleaks' findings as the plan recorded them (see "The redaction
plan" below); without a plan it has only the local patterns. The local
patterns are keyword and shape anchored and can also use the key a value sits
under, so `{"KBASE_AUTH_TOKEN": "s3cret"}` is caught on six characters.
gitleaks knows about 150 provider shapes and gates on entropy near 3.5, so it
catches what nobody here wrote a rule for and misses the low-entropy ones: the
three real tokens in the September corpus scored 4.351, 3.531 and 3.328.
Neither substitutes for the other. gitleaks reports a file line, which the
inventory converts to a record number. A record number counts parsed records only,
the same way the loader does, so a blank or unparseable line has none.

What this does not do, stated plainly:

- **It bounds over-redaction, it does not remove it.** An unterminated
  `BEGIN ... PRIVATE KEY` still takes the rest of the value it sits in. Walking
  the parsed structure makes that one JSON value instead of everything after it
  in the file. An asset read as one string is one value, so nothing is bounded
  there.
- **It cannot help a trace that is already loaded.** The remedy there is
  deleting the whole trace, which is the thing this exists to avoid.
- **It is about secrets and personal details, not consent.** Whether a session
  should be loaded at all is a different question, answered by `people.json`
  and by [#2](https://github.com/beril-doe/langfuse-retro-load/issues/2).

## The redaction plan: scan, review, then load

A real load normally requires a **redaction plan** built before sending. The
operator reviews its masks using `reveal.py --plan`; the loader applies them
and checks for remaining local findings that were neither masked nor cleared.
On the pod:

```
# 1. Scan: both detectors, one row per value to mask, no values in the file
python3 plan.py build --out plan.jsonl [--clearances clearances.jsonl] SESSION.jsonl

# 2. Review: every planned mask in context, value hidden unless --show-values in a terminal
python3 reveal.py --transcript SESSION.jsonl --plan plan.jsonl

# 3. Load: applies the plan, then checks for uncleared local findings
python3 retro_load.py --plan plan.jsonl SESSION.jsonl
```

Three files, three jobs. The **inventory** (`inventory.py`) is everything a scan found,
report-only items included. **Clearances** are findings a reviewer decided are not secrets;
each row names any of `subject`, `record`, `pointer`, `pattern`, `fingerprint`, and a missing
field matches anything. The **redaction plan** is the actionable findings minus clearances.

What the plan guarantees:

- **gitleaks is part of it.** gitleaks reports a line and the matched text; the plan finds the
  field of that record holding the text and records its pointer and offsets. A match it can't
  place is kept as an unplaceable row, and the load refuses the plan until it is cleared.
- **It holds no values.** Each row is a record number, a JSON pointer, character offsets,
  the pattern and a fingerprint.
- **It fits only the transcript it was built from.** Each transcript's header carries its
  SHA-256, and the load refuses a plan for a transcript that has changed since.
- **Fingerprints are stable** for the same value in the same transcript, so a clearance by
  fingerprint keeps working when the plan is rebuilt.

A real load without `--plan` is refused. `--without-plan` loads with the local patterns only
and says so; it is for tests, not backfill. A plan built with `--no-gitleaks`
also needs explicit `--allow-plan-without-gitleaks` at load time.

The transcript hash and mask count check source consistency and truncation;
they do not prove that a person reviewed the plan or that its mask rows have
not been edited since review. That remaining contract is tracked in
[issue #29](https://github.com/beril-doe/langfuse-retro-load/issues/29).

## Not sending a session twice

Langfuse has no create-time dedupe, so `retro_load.py` asks the target project before sending
anything, through `presence.py`:

- **Already there.** If the project holds any observations for the session id, the session is
  skipped. This covers a second run of this loader and a session live tracing already sent. The
  local marker cannot detect a session sent by another client, even though current markers
  record their destination.
  `--allow-existing` sends anyway.
- **Still in use.** A session whose last record is newer than `--min-idle-days` (default 7) is
  skipped, because resuming it without corresponding live-hook state can re-send earlier turns.
- **Could not tell.** A failed check stops the send. A skipped session can be loaded later; a
  duplicate can only be removed by deleting whole traces.

A skip exits with status 3, and `run_manifest.py` lists skipped sessions separately.

`presence.covered_through()` returns the greatest observation start time held for a
session. It is not used by this loader or integrated into BERIL's relay. Reuse is
tracked in #30, but this value is not a completeness watermark: partial uploads,
equal timestamps and late arrivals can leave gaps before it. A live adapter needs
those cases tested before dropping earlier spans. The helper also requires read
access that the write-only relay does not expose to clients.

## Adding a person or a new source

Edit `people.json`, not the Python. One entry per person, one `sources`
entry per place their traces live:

```json
{
  "person": "someuser",
  "user_id": "someuser",
  "role": "Observe",
  "group": "SomeGroup",
  "sources": [
    {
      "type": "workshop-frozen-corpus",
      "find_root": "~/justin-trace-analysis/data/claudefiles/someuser/.claude/projects",
      "consent_bin": "opt_in",
      "force_event_day": []
    }
  ]
}
```

`consent_bin` should reflect a real, checked consent status
(`opt_in`/`opt_out`/`no_reply`/`team`): see the coverage-gaps issue below
before adding anyone whose consent hasn't actually been verified.
`force_event_day` is a list of session IDs to count as the 2026-05-07
event day even if the session started the day before (see issue #392 for
why that's a real, non-hypothetical case). `role`/`group` come from the
workshop invite-list sheet if applicable; leave them `null` for sources
where that doesn't apply (e.g. someone's own ongoing pod-home work).

`user_id` is deliberately the pod account name, never a real name. Langfuse
Sessions/Users views are a re-identification surface, and consent was
tracked pseudonymously. Don't change that without a real reason.

## This repository is public, and two of its files are about people

`people.json` and `manifest.json` are committed, and the repository is public. So
everything in them is published, including the part that is a judgment about a
person rather than a mechanism.

- **A `consent_bin` is a decision someone made about a named account.** Putting it
  here publishes it. The account name, the employer group and the consent status sit
  in one record, and the person it describes has not necessarily been asked whether
  that is fine.
- **`manifest.json` is one row per session**, and `build_manifest.py` rewrites it
  from `people.json`. Step 1 of "Running it" below regenerates it, so following the
  instructions and committing the result publishes a fresh roster of session ids per
  person. It is derived, so tracking it buys nothing that one command does not.
- **A `pod-live` source is someone's ordinary work, not workshop data.** Its
  `find_root` is `~/.claude/projects` on the pod, which is everything they have ever
  done there. One such source currently contributes 60 of the 111 manifest entries.
  Adding one publishes those session ids and sends that work to Langfuse.
- **`consent_bin: null` means nobody checked**, which is not the same as consent.
  Nothing in the code treats it as a reason not to load.
- **This scales badly on purpose.** The frozen corpus holds 82 participant
  directories. The file grows one entry per person and the manifest one row per
  session, so loading the corpus as the repo stands today would publish 82 named
  accounts with their consent decisions.

The care already taken over `user_id` is the reason to care here: it is the pod
account name rather than a real name because Langfuse's Sessions and Users views make
re-identification easy. That reasoning stops at the Langfuse boundary and needs to
reach the repository too.

## Running it

`pyproject.toml` and `uv.lock` describe the intended environment. They are not yet in
use on the pod, because `uv` is not installed there; see the setup issue in this repo.
Until that lands, the commands below run against whatever Python the pod provides,
which is the reproducibility gap the lockfile exists to close.

```bash
# 1. Regenerate the manifest from current state (content-safe, no Langfuse calls)
python3 build_manifest.py

# 2. Sanity check before spending anything for real
python3 run_manifest.py --dry-run

# 3. Credentials -- .env next to these scripts, LANGFUSE_PUBLIC_KEY /
#    LANGFUSE_SECRET_KEY / LANGFUSE_HOST, for whichever Langfuse project
#    should receive this load. Never paste real key values through a chat
#    session -- set this up directly in a pod terminal.

# 4. The real thing. Backgrounded, since a browser/terminal hiccup shouldn't
#    kill a run partway through -- it's resumable via the markers either way.
python3 plan.py build --out plan.jsonl <the manifest's transcripts>   # then review with reveal.py
nohup python3 run_manifest.py --plan plan.jsonl > full_load_run.txt 2>&1 &

# 5. Verify independently against Langfuse's own API, not just this
#    script's own "OK" output. Count the observations carrying your batch tag.
#    The metrics API is the one that filters on tags: /api/public/observations
#    ignores a ?tag= parameter and is removed from Langfuse Cloud on 2026-11-16.
#    curl does not read .env: the three variables must already be exported in
#    this shell. The host is resolved in the same order as retro_load.py
#    (LANGFUSE_HOST, then LANGFUSE_BASE_URL), so this counts the project the
#    load wrote to.
curl -s -G "${LANGFUSE_HOST:-$LANGFUSE_BASE_URL}/api/public/v2/metrics" \
  -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" \
  --data-urlencode 'query={"view":"observations","metrics":[{"measure":"count","aggregation":"count"}],"filters":[{"column":"tags","operator":"any of","value":["<your-batch-tag>"],"type":"arrayOptions"}],"fromTimestamp":"2000-01-01T00:00:00Z","toTimestamp":"2100-01-01T00:00:00Z"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data'][0]['count_count'])"
```

## Tests

```
just test      # pytest, offline
just lint      # ruff, the narrow ruleset pinned in pyproject.toml
just check     # both, in the order CI runs them
```

Nothing in `tests/` talks to Langfuse. The deletion tests replace `api`,
`auth_for_project` and `confirm_project` with functions that raise, so a refusal
that reached the network fails the run instead of passing it. That is the point of
those tests: the refusals in `langfuse_admin.py delete` have to happen before the
tool authenticates, and testing only the exit code would not show it.

The key resolver is tested separately, against a synthetic environment rather than a
replaced function, because the guarantee there is that it never falls back to whichever
key happens to be present. A test that replaced the resolver could not see that change.

Both recipes need `uv`, which is not on the pod yet
(https://github.com/beril-doe/langfuse-retro-load/issues/15). CI runs them on every
push regardless.

## Known gaps (tracked as issues, not fixed here)

- [#1](https://github.com/beril-doe/langfuse-retro-load/issues/1):
  which LLM backend (direct Anthropic / CBORG / Vertex) served a given
  trace isn't recoverable from the transcript itself.
- [#2](https://github.com/beril-doe/langfuse-retro-load/issues/2):
  loading someone's traces only covers what's in `people.json`; the other
  ~80 hackathon participants have directories in the corpus with no
  consent checked. Don't read "we loaded the corpus" as "we loaded
  everyone."
- [#4](https://github.com/beril-doe/langfuse-retro-load/issues/4):
  a live `.credentials.json` was found swept into the shared frozen corpus
  for every participant during this work. Not this tool's problem to fix,
  but tracked so it isn't lost.

A full session-by-session working log exists outside this repo (not
committed here, since it's a working log rather than documentation). Ask a
maintainer for it if you want the full story behind a decision, including
two real bugs found building this the first time (a capture-group indexing
error and an idempotency marker that didn't survive a later fix).
