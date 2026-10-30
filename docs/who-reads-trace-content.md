# Who reads trace content

Text from Langfuse traces, and from the transcripts they are built from (the pod's `~/.claude` and the frozen corpus), goes to three places only:

- **gitleaks**, run locally, as `inventory.py` and `plan.py build` run it.
- **A local Ollama model**, if a semantic pass is ever wanted. The model runs on my M5 or on another contributor's computer with enough capacity, never on a hosted service. This repository has no such pass today.
- **A person**, reading it in a pod terminal or in the Langfuse web UI.

It never goes to a hosted model, whether Claude, Codex, Copilot, CBORG or any other, and never through an agent session that runs on one.

## Why

Anything an agent session reads is sent to the model provider, and deleting the trace afterwards cannot undo that. This is the exposure https://github.com/beril-doe/BERIL-research-observatory/issues/428 is about, and a colleague has raised the concern that reading traces through hosted models may have added to it.

## What an agent session can do here

- **Write and test this repository's tools** against made-up placeholder fixtures, as `tests/` does.
- **Run the tools that print counts, lengths and shapes, and read their output:**
  - `backfill.py <person>` without `--review` (the preview): the account name and user id, session and turn counts, mask counts by category and pattern, the plan path and the load command.
  - `plan.py build`: mask counts per transcript.
  - `inventory.py`: counts, record numbers, JSON pointers, patterns and fingerprints, never a value.
  - `retro_load.py --dry-run`: the turn count and each turn's timestamp.
  - `langfuse_admin.py count`: totals per object type.

## What a person does, not an agent

- **`reveal.py`.** It prints the text around each finding even without `--show-values` (`context_for`). An agent session does not run it, and its output is not pasted into one.
- **`backfill.py <person> --review`.** It shows values. It refuses to run unless stdin and stdout are terminals, but an agent driving a terminal, for example through a browser tab, still reads what the terminal shows. A person runs `--review`.
- **Reading a trace in the Langfuse web UI**, for the same reason.
- **Langfuse API keys.** A person creates them in the Langfuse web UI and sets them up in a pod terminal. An agent does not create them, and they are never pasted into a chat session (README, "Running it", step 3).
