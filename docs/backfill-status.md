# Backfill status and deletion log

What exists in the BERIL workshop corpus, what has been loaded into the Langfuse project
beril-usage, and every deletion made from the BERIL Langfuse organization. Measured on
2026-09-29.

This repository is public, so this page gives counts only. It doesn't name who consented,
their account names or their ORCIDs; that per-person table is kept privately by Mark. The
procedure for loading someone is in [backfill-runbook.md](backfill-runbook.md).

## Rules in force

- A consenter is loaded only under an ORCID with strong evidence: the iD appears in the
  person's own transcripts, and the account is tied to the person by their registration form
  and their KBase display name.
- Consenters are loaded for the workshop day only, 2026-05-07 in UTC. That means
  `backfill.py --workshop-day-only` and `artifacts.py --only-day 2026-05-07` (Mark,
  2026-09-29). All of the BERIL developer's own traces stay, whatever their day.
- Personal details and secrets are masked, as the runbook describes.

## How the numbers are measured

- **Consent** comes from the workshop invite list: 33 people consented.
- **Corpus counts** come from a read-only scan on the BERDL pod of each consenter's workshop
  transcripts, using the loader's own parsing.
  - A **turn** is what the loader sends as one Langfuse trace.
  - A **snapshot** is what `artifacts.py` would upload as one "BERIL artifacts — <project>"
    span.
  - A turn is dated by its user message, and a snapshot by its session's end, both in UTC. No
    turn lacked a timestamp.
- **Loaded counts** are the traces in beril-usage tagged `retro-load`. For every person
  loaded, they agree with the corpus scan.

## Corpus, across the 33 who consented

| | before 2026-05-07 | on 2026-05-07 | after 2026-05-07 |
|---|---|---|---|
| turns | 175 | 1,093 | 37 |
| artifact snapshots | 1 | 38 | 3 |

252 sessions in all. One person who consented has no account in the corpus.

| status | people | turns on the workshop day | snapshots on the workshop day |
|---|---|---|---|
| loaded | 6 (the BERIL developer, who also consented, and 5 others) | 264 | 12 |
| strong evidence, not yet loaded | 11, one of them on hold at Mark's request | 410 | 12 |
| good evidence: one matching registry record, but the iD isn't in the transcripts | 11 | 363 | 14 |
| unresolved: no single matching registry record | 4 | 56 | 0 |
| no account in the corpus | 1 | 0 | 0 |

The rows add up to the corpus totals: 1,093 workshop-day turns and 38 snapshots. The strong
row includes the person on hold (40 workshop-day turns and one snapshot).

## Loaded now (beril-usage, tag `retro-load`)

| | on 2026-05-07 | other days |
|---|---|---|
| turn traces | 264 | 60, all the BERIL developer's, kept by decision |
| artifact spans | 12 | 0 |

That's 336 traces. The project also holds the developer's live-hook and smoke-test traces,
which carry no `retro-load` tag.

## Deletion log

Deleting a Langfuse trace also deletes its observations, scores and media. Sessions can't be
deleted: a session is only a label that traces carry, so empty sessions stay listed. The pod's
"already sent" markers survive every deletion, so a reload needs `--force`. Each deletion
since 2026-09-24 was made with `langfuse_admin.py delete` after a matching dry run, and it
saved a `--record` manifest, which Mark keeps privately.

| date (UTC) | what | how many | why |
|---|---|---|---|
| 2026-09-11 | everything in beril-usage: the first retro-load, including 67 `beril.artifact_snapshot` traces | 483 traces, 6,974 observations, 123 media objects | start over in the live hook's format |
| 2026-09-11 | a sandbox project, deleted in the web UI | the project | cleanup |
| 2026-09-24 | the 2026-09-18 pilot load (`--tag retro-load`) | 135 traces, 60 scores | replaced by the ORCID-keyed format |
| 2026-09-24 | Mark's own backfill batch (`--tag backfill-mamillerpa-2026-09-24`) | 376 traces | his workshop sessions produced no BERIL artifacts |
| 2026-09-29 | three consenters' turns from days other than the workshop, one command per person (`--tag retro-load --user-id <orcid> --outside-day 2026-05-07`) | 51 traces: 45, 3 and 2 turns, plus 1 artifact span | workshop day only |
