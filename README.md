# re-workbench

Ghidra-powered reverse engineering & firmware/IoT analysis for Claude Code — as
an MCP server, skills, an autonomous agent, and slash commands.

## What's in it

- **MCP server** (`mcp/`) — Ghidra headless (via PyGhidra) + lief triage, exposed
  as tools: `triage`, `list_strings`, `scan_firmware`, `analyze`,
  `list_functions`, `decompile` (with callers + referenced strings),
  `disassemble`, `xrefs`, `session_status`. One JVM boots once and analyzed
  programs are cached for the session.
- **Skills** — `ghidra-triage` (drive the tools to understand a binary),
  `firmware-recon` (unpack/triage firmware without binwalk). Both point to the
  ~49 RE skills already installed on this machine rather than duplicating them
  (see `skills/ghidra-triage/references/related-skills.md`).
- **Agent** — `re-analyst`: dispatch with a file path and it self-drives the full
  analysis level by level, minimizing tokens (cheap tools first, decompile only
  targeted functions), and writes a report to `re-findings/`.
- **Commands** — `/re <path>` (one-shot autonomous) and `/re-loop <path>`
  (deep iterative via the installed `ralph-loop` skill for large targets).

## Configuration

The MCP server needs Ghidra and a JDK 17+ (Ghidra 12 wants 21). Paths are set in
`.mcp.json` under `mcpServers.re-workbench.env`. Current values:

```json
"GHIDRA_INSTALL_DIR": "C:\\Users\\adil.tepe\\xcover5nethunter\\ghidra_12.1.3_PUBLIC",
"JAVA_HOME": "C:\\Program Files\\Microsoft\\jdk-21.0.12.101-hotspot"
```

Change these if Ghidra/JDK move. Ghidra projects are written to
`%TEMP%\re-workbench-ghidra` (override with `RE_WORKBENCH_PROJECTS`) so read-only
source dirs like System32 don't block analysis.

Python deps are managed by `uv` from `mcp/pyproject.toml` (pinned to Python 3.12
via `mcp/.python-version` — jpype1 has no prebuilt wheel for 3.14 yet). The
server command is `uv run --directory ${CLAUDE_PLUGIN_ROOT}/mcp
re-workbench-server`, so `uv sync` runs on first launch.

## Install

Local, for development:

```
/plugin marketplace add C:\Users\adil.tepe\RE
/plugin install re-workbench@re-workbench
```

Then restart Claude Code so the MCP server registers.

## Scope

Authorized reverse engineering only — your own binaries, CTFs, defensively
analyzed malware, and targets you may inspect. The tools read and describe; they
don't modify or deploy. Weaponization against third-party systems is out of
scope.
