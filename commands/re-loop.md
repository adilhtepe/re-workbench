---
description: Deep, iterative autonomous RE of a large target — runs level-by-level across fresh iterations via the ralph-loop skill until a full report is written
argument-hint: <path-to-binary-or-firmware> [--max-iterations N]
---

Run a self-driving, multi-iteration reverse-engineering loop over `$ARGUMENTS`.
Use this instead of `/re` for large binaries or firmware where one pass can't
cover every function within context — each iteration advances one level / a few
targets, persists findings, and a fresh iteration continues.

Set it up, then hand off to the installed `ralph-loop` skill (don't build a
loop):

1. Create `re-findings/<basename>.md` (if absent) and a state file
   `re-findings/<basename>.state.json` with the phases and per-phase status:
   `{"target":"$ARGUMENTS","phase":"classify","done":[],"targets_pending":[],"targets_done":[]}`
   Phases in order: `classify, surface, strings, structure, decompile, report`.

2. Invoke the `ralph-loop` skill with a phase-aware prompt (the loop re-feeds it
   each iteration). The prompt must tell each iteration to:
   - Read `re-findings/<basename>.state.json`.
   - Do the **next** incomplete phase only (or decompile the next few pending
     targets), using the re-workbench MCP tools and the token-budget discipline
     from the `ghidra-triage` skill.
   - Append results to `re-findings/<basename>.md` and update the state file
     (advance `phase`, move targets between pending/done). Gate advancement on
     the artifact actually existing (decompiled output written, report section
     present) — not on a self-report of "done."
   - When the `report` phase is complete, emit the completion promise
     `<promise>RE_COMPLETE</promise>` so the loop stops.

   Pass `--completion-promise "RE_COMPLETE"` and the user's `--max-iterations`
   (default 12) to `ralph-loop`.

State lives in the two files on disk, never only in context — that is what lets a
fresh iteration pick up where the last stopped. If `$ARGUMENTS` is empty, ask
which file first.
