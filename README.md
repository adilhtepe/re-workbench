# re-workbench

Ghidra-powered reverse engineering & firmware/IoT analysis — headless
decompilation, binary triage, firmware unpacking, and autonomous analysis as
an MCP server, skills, an autonomous agent, and slash commands.

## What's in it

- **MCP server** (`mcp/`) — Ghidra headless (via PyGhidra) + lief triage, exposed
  as tools: `triage`, `list_strings`, `scan_firmware`, `analyze`,
  `list_functions`, `decompile` (with callers + referenced strings),
  `disassemble`, `xrefs`, `session_status`. One JVM boots once; analyzed
  programs are cached for the session.
- **Skills** — `ghidra-triage` (drive the tools to understand a binary),
  `firmware-recon` (unpack/triage firmware without binwalk).
- **Agent** — `re-analyst`: dispatch with a file path and it self-drives the full
  analysis level by level, minimizing tokens (cheap tools first, decompile only
  targeted functions), and writes a report to `re-findings/`.
- **Commands** — `/re <path>` (one-shot autonomous) and `/re-loop <path>`
  (deep iterative loop for large targets).

## Requirements

- [uv](https://docs.astral.sh/uv/) — manages the Python venv automatically
- Ghidra 10.4+ (12.x recommended)
- JDK 17+ (JDK 21 required for Ghidra 12)

## Configuration

Copy `.mcp.json.example` to `.mcp.json` and fill in your paths:

```json
{
  "mcpServers": {
    "re-workbench": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/re-workbench/mcp", "re-workbench-server"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.1.3_PUBLIC",
        "JAVA_HOME": "/path/to/jdk-21"
      }
    }
  }
}
```

Ghidra projects land in `$TMPDIR/re-workbench-ghidra` so read-only source dirs
(like System32) never block analysis. Override with `RE_WORKBENCH_PROJECTS`.

Python deps are managed by `uv` from `mcp/pyproject.toml` (pinned to Python 3.12
via `mcp/.python-version` — jpype1 has no prebuilt wheel for 3.14 yet). `uv sync`
runs automatically on first launch.

## Install

### Claude Code (plugin)

```
/plugin install re-workbench@https://github.com/adilhtepe/re-workbench
```

Restart the app after install so the MCP server registers.

### OpenClaw

Clone the repo, then add to OpenClaw's MCP server config (`~/.openclaw/mcp.json`
or equivalent):

```json
{
  "servers": {
    "re-workbench": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/re-workbench/mcp", "re-workbench-server"],
      "transport": "stdio",
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra",
        "JAVA_HOME": "/path/to/jdk-21"
      }
    }
  }
}
```

Restart OpenClaw after adding the server.

### Any MCP-stdio client

The server speaks MCP over stdio. Point your client at:

```
command: uv
args:    run --directory /path/to/re-workbench/mcp re-workbench-server
env:     GHIDRA_INSTALL_DIR=/path/to/ghidra  JAVA_HOME=/path/to/jdk-21
```

## Scope

Authorized reverse engineering only — your own binaries, CTFs, defensively
analyzed malware, and targets you may inspect. The tools read and describe; they
don't modify or deploy. Weaponization against third-party systems is out of
scope.
