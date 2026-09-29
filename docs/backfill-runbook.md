# Backfill one consenter: runbook

The sequence that loaded a consenter's workshop sessions on 2026-09-29, one step per stage.
Run every command on the BERDL pod, in a terminal, unless it says otherwise. Steps marked
**Mark** are decisions only Mark makes; the rest can be run by anyone with pod access.

Who consented, and the evidence linking each account to a person and an ORCID, are kept
outside this repository, because the repository is public. The roster the commands read
is private to the pod: `~/beril-backfill-roster.json`. Never put a consenter's name,
account name or ORCID in an issue, a pull request or a commit here.

Shorter `--review` and `--load` commands are planned in
https://github.com/beril-doe/langfuse-retro-load/issues/62; until they land, use the
commands below. `<person>` is the account name in the roster.

## 1. Decide who is next (Mark)

A consenter is loaded only under an ORCID with strong evidence: the iD appears in the
person's own transcripts, and the account is tied to the person by their registration
form and by their KBase display name.

## 2. Add them to the private roster

Add one entry to `~/beril-backfill-roster.json`, copying the shape of an existing one: the
account name as `person` and `user_id`, the ORCID as `orcid` in `https://orcid.org/...`
form, and one `workshop-frozen-corpus` source. Keep a copy of the file before editing it.

## 3. Update the checkout

```bash
cd ~/langfuse-retro-load && git pull --ff-only
```

`backfill.py` refuses to run on an out-of-date checkout, a `langfuse` other than the one
`uv.lock` pins (fix: `uv sync --locked`), or a gitleaks older than 8.20.0. Each refusal
prints its fix.

## 4. Preview (sends nothing)

```bash
cd ~/langfuse-retro-load && .venv/bin/python backfill.py <person> --people ~/beril-backfill-roster.json | tee ~/backfill-<person>-preview.log
```

It prints the sessions and turns it would send, the redaction plan it wrote under `plans/`,
the masks by category and pattern, and the exact load command. Only the sessions listed
there are loaded, with only the masks in that plan.

## 5. Review the masks (Mark)

For each session that has masks, show them with their values. This reads the plan written
in step 4; replace `<plan>` with its file name under `plans/`.

```bash
cd ~/langfuse-retro-load && for t in $(grep -o -- '--transcript [^ ]*' ~/backfill-<person>-preview.log | cut -d' ' -f2); do clear; .venv/bin/python reveal.py --plan plans/<plan> --transcript "$t" --show-values; read -r -p "--- Enter for the next session ---"; done
```

`--show-values` only runs in a terminal, so don't pipe it into `less`. Things worth checking:
gitleaks findings, which can be false positives (public identifiers are allowlisted in
`.gitleaks.toml`), and anything the session is about that a mask would hide. If a mask is
wrong, fix the rule and rebuild the preview. Don't edit the plan: a plan whose rows changed
after it was built is refused.

## 6. Load (Mark)

Copy the load command the preview printed, and run it in the background so a closed tab
can't stop it:

```bash
cd ~/langfuse-retro-load && PYTHONUNBUFFERED=1 nohup .venv/bin/python backfill.py <person> --people ~/beril-backfill-roster.json --batch-tag <tag from the preview> --load --plan plans/<plan> > ~/backfill-<person>-load.log 2>&1 &
```

`PYTHONUNBUFFERED=1` makes the log show progress as it happens. Unlike `python -u`, it also
reaches the processes the load starts, which print the per-session lines. The load is finished when
`pgrep -af 'backfill.py|run_manifest.py|retro_load.py'` prints nothing; the log then ends
with a summary of sessions emitted and skipped. A session with no timestamps is skipped on
purpose.

## 7. Verify the traces

From any machine with the project key in `.env` (read-only):

```bash
python3 langfuse_admin.py delete --project beril --type trace --tag <tag from the preview> --dry-run
```

Despite the name, `--dry-run` sends nothing. It lists the traces carrying that tag, the
sessions touched and the user id. The trace count should equal the preview's turn count.

## 8. Artifacts

```bash
cd ~/langfuse-retro-load && .venv/bin/python artifacts.py <person> --people ~/beril-backfill-roster.json          # preview
cd ~/langfuse-retro-load && .venv/bin/python artifacts.py <person> --people ~/beril-backfill-roster.json --load   # upload
```

This uploads one "BERIL artifacts — <project>" span for each session that changed a BERIL
project's REPORT, RESEARCH_PLAN or WORKLOG, as the live hook does.

## If something went wrong

The turn traces from one load carry its batch tag. To remove them, run the step 7 command
without `--dry-run`, with `--yes`, and `--record <file>` to keep a manifest of what was
deleted.

The artifact spans from step 8 don't carry the batch tag, so that doesn't remove them. They
also carry the session ids, and a reload skips any session that Langfuse already holds
observations for, even with `--force`. So after uploading artifacts, a full redo needs
their spans removed too. Select them by tags, never by name alone: the live hook uploads
spans with the same name, but only retro-loaded ones carry `retro-load`.

```bash
python3 langfuse_admin.py delete --project beril --type trace --tag retro-load --tag artifacts --tag <project> --dry-run
```

`--tag` repeats and every tag must match, so this lists only retro-loaded artifact spans for
that BERIL project. Check that the users line shows only this person's ORCID before running
it with `--yes` and `--record <file>`. Then reload the turns with `backfill.py ... --load
--force` and the artifacts with `artifacts.py ... --load --force`. Each script keeps its
own "already sent" markers, so each needs `--force`.
A simpler, tag-scoped undo is part of
https://github.com/beril-doe/langfuse-retro-load/issues/62.
