---
description: Autonomously reverse engineer a binary or firmware image end to end (dispatches the re-analyst agent — no per-step input needed)
argument-hint: <path-to-binary-or-firmware>
---

Dispatch the `re-analyst` agent to analyze `$ARGUMENTS` autonomously.

Give the agent this task: reverse engineer the target at `$ARGUMENTS` level by
level (classify → surface → strings → structure → targeted decompilation →
report) using the re-workbench MCP tools, writing progressive findings to
`re-findings/<basename>.md`, and return the final report. It should not ask for
input between levels; only stop to ask if the path is missing/ambiguous or the
work would be unauthorized.

If `$ARGUMENTS` is empty, ask which file to analyze before dispatching.
