# Reuse with BERIL live tracing

Checked **2026-09-23** against this repository's main `2eb1724` and BERIL main
`00537fc`. [Issue #30](https://github.com/beril-doe/langfuse-retro-load/issues/30)
tracks actions in both directions. The detailed, versioned component inventory
is maintained in [langfuse-notes](https://github.com/turbomam/langfuse-notes/blob/dd93a327322b96a9ce6463eed42af06b5b925a5b/docs/beril-live-and-retro-reuse.md)
(the reviewed accounting snapshot; its documentation PR remains open).

## What already exists

Dileep Kishore's [merged BERIL PR #420](https://github.com/beril-doe/BERIL-research-observatory/pull/420)
adds opt-in live hooks, a personal-token-authenticated write-only relay,
server-held Langfuse project keys, session artifact uploads, identity mapping,
background launch and SDK error logging. The turn-reconstruction core is
vendored from Langfuse; the BERIL adaptations are Dileep's work.

This repository's merged #25 supplies parsed-value screening, secret/person
categories, findings without matched text, inventory-time gitleaks, and
presence/idle-session checks. #25 adopted the live hook's Basic/Token header
handling and fixed variable-reference/name preservation (#23). BERIL #420 in
turn adopted the synthetic transcript-path lesson from this repository's #3.
These are concrete examples of reuse already completed in both directions.

## Lessons to apply here

- Resolve a destination once for presence queries, SDK export and markers.
  Dileep passes explicit `base_url`; this loader still passes `host`, allowing
  environment precedence to split those destinations. [#31](https://github.com/beril-doe/langfuse-retro-load/issues/31)
  defines the offline regression and fix.
- Preserve the relay's write-only boundary. This loader needs read APIs for
  presence and verification; changing its URL to `/lf` alone will not work.
  Design the read authorization separately if relay-backed backfills are added.
- Consider caller-known credential values as an additional detector input.
  Historical backfills cannot rely on knowing other people's credential values.
- Reuse the existing BERIL artifact uploader where its behavior fits, and
  account separately for historical snapshots and verification receipts.
  Screen actual attachment bytes before upload, not just their media references.
- Keep historical identity and consent decisions explicit. BERIL defaults to
  ORCiD; this loader uses the approved pod account name. Live opt-in does not
  authorize every archived transcript.

## What the live path can reuse from here

- The pure detector and synthetic regression cases, through the existing SDK
  mask boundary where practical. Preserve the live known-value/header rules,
  choose personal-data policy explicitly, and protect trace-linkage fields.
  #28 remains a blocker to claiming arbitrary category combinations work.
- Findings that omit matched values for diagnostic counts and review. Do not
  treat short fingerprints as unique identifiers or approval signatures.
- Presence helpers for overlap analysis. `covered_through()` is only the
  greatest observation start time: it cannot prove every earlier observation
  arrived. An incremental adapter needs partial-session, equal-timestamp,
  retry and late-arrival tests before dropping spans; see #7 and #30.
- Batch screening experience and detector comparison. Keep subprocess scans
  and human plan review out of the live hook's critical path unless separately
  designed and measured. Nonblocking research must not become an unredacted
  telemetry fallback on masking errors.

## Current task state

| Work | State on 2026-09-23 |
| --- | --- |
| Pure detector (#13), tests and CI (#14) | Implementations merged via #19/#25; acceptance evidence is linked in those issues |
| Variable-reference and key-name corruption (#23) | Fixed; issue closed |
| Detector union (#10) and reviewed redaction (#11) | Inventory union exists; main loader uses local rules only. Reviewed application is pending in #27 |
| Plan/apply/reveal workflow (#27) | Open PR, not this main revision; #29 separately tracks binding the reviewed rows to what is applied |
| Post-load scoring/reveal (#26), custom categories (#28) | Open follow-ups; not blanket capabilities of main |
| Destination agreement (#31) | Open, concrete lesson from BERIL |
| Live adapter, relay-backed backfill, artifact and identity reconciliation (#30) | Tracked proposals; not deployed integrations |

External references are [BERIL #431](https://github.com/beril-doe/BERIL-research-observatory/issues/431)
(live integration), [#438](https://github.com/beril-doe/BERIL-research-observatory/issues/438)
(missing known credential names), [#424](https://github.com/beril-doe/BERIL-research-observatory/issues/424)
(historical artifacts), and [#428](https://github.com/beril-doe/BERIL-research-observatory/issues/428)
(pre-provider exposure). This accounting updates only this repository and
`langfuse-notes`; it does not alter those issues, deploy hooks, or assign work
to Dileep.

## Evidence required to mark adoption complete

Link the consumer commit and relevant offline tests, then separately record
any synthetic deployment test. Verify trace and attachment bytes, target
agreement, failure behavior and duplicate handling. Do not use a merged PR,
an available helper, or a local source-code comparison as proof of production
coverage. Refresh #30 and the notes inventory when relevant PRs merge.
