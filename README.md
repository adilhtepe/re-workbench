# re-workbench

Ghidra-powered reverse engineering & firmware/IoT analysis — headless
decompilation, binary triage, firmware unpacking, and autonomous analysis as
an MCP server, skills, an autonomous agent, and slash commands.

## What's in it

- **MCP server** (`mcp/`) — Ghidra headless (via PyGhidra) + lief triage, exposed
  as tools: `triage`, `list_strings`, `scan_firmware`, `analyze`,
  `list_functions`, `decompile` (with callers + referenced strings),
  `disassemble`, `xrefs`, `session_status`. One JVM boots once; analyzed
  programs are cached for the session. Optionally `rank_functions`,
  `rank_strings` and `decision_status` — ordering help from a local decision
  model, off by default (see below).
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

## Optional decision-model ranking

Two extra tools, `rank_functions` and `rank_strings`, will **order** a
candidate list by one question using a local decision model (a small encoder
answering one yes/no-shaped question per forward pass, not a language model).
This is entirely optional: with nothing configured both tools return the same
full candidate list in deterministic order, and every other tool is unaffected.
The repository has no new dependency for it — the client is `urllib` from the
standard library.

### Setup

Point the server at a decision endpoint **on loopback**:

```json
"env": {
  "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.1.3_PUBLIC",
  "JAVA_HOME": "/path/to/jdk-21",

  "RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:8009",
  "RE_WORKBENCH_DECISION_MODEL": "von-1.3",
  "RE_WORKBENCH_DECISION_TIMEOUT": "60",
  "RE_WORKBENCH_DECISION_MAX_ITEMS": "150"
}
```

| variable | default | meaning |
| --- | --- | --- |
| `RE_WORKBENCH_DECISION_URL` | empty (off) | endpoint; `/v1/systemone` is appended when the URL has no path |
| `RE_WORKBENCH_DECISION_MODEL` | `von-1.3` | model name sent with each request |
| `RE_WORKBENCH_DECISION_TIMEOUT` | `60` | per-request timeout in seconds |
| `RE_WORKBENCH_DECISION_MAX_ITEMS` | `150` | hard cap on requests per call |

Only `127.0.0.1`, `localhost` and `::1` are accepted. Anything else is refused
before a request is made, so evidence assembled from your binaries does not
leave the machine. Requests bypass any configured HTTP proxy. `decision_status()`
reports whether the layer is configured, reachable, which model answers, and
what a batch will cost in wall-clock seconds.

### Portability

Nothing requires the decision server. Unset, misconfigured or down, the ranking
tools return `{"status": "unavailable", "reason": ...}` together with the
complete candidate list in deterministic order (inbound reference count for
functions, matched pattern-class count for strings). Code that reads the
ordering keeps working; it just stops being model-ordered.

### Measured limits

These numbers come from measurements on a local setup, and they are the reason
the tools are shaped the way they are.

- **Cost.** Latency is super-linear in the length of the state: 76 tokens
  0.57 s, 241 tokens 1.61 s, 961 tokens 7.08 s, 3061 tokens 30.6 s. So evidence
  is capped at ~150 tokens per item, there is one request per item, and the
  expected wall-clock cost is reported before a batch runs. Observed in practice:
  ~0.9 s per item, so ~50 s for 50 functions.
- **No thresholds exist.** Scores are banded: 41 measurements all landed inside
  [0.1774, 0.8384]. A rule like ">= 0.85 means yes" structurally cannot fire,
  and an absolute flag rule (">= 0.80 is suspicious") flagged 7 of 7 files in a
  real set. The tools therefore return no judgement of any kind — no
  suspicious/clean, no important/unimportant, just an order and a score.
- **A low score is not a negative answer.** The classic true positive of an
  embedded binary (96 bytes, 14 inbound refs, only `memcpy`) scored 0.1790 and
  ranked last of nine. Nothing is dropped, filtered or hidden on the strength of
  a score, and neither should you drop it.
- **Evidence is generated by code.** The class margin measured smaller than
  paraphrase noise (0.0015 against 0.0041), so evidence comes from one fixed,
  versioned template (`EVIDENCE_TEMPLATE_VERSION`, reported in every result) and
  every item of a batch is rendered the same way. A summary written by a
  language model is not comparable between items.
- **One question per item.** Ranking several candidates inside a single call
  inverted the order (glue functions came out top three), hence one
  single-condition request per item. Compound questions also fail quietly: on an
  8-function set a multi-clause question collapsed the spread to 0.0047 — inside
  paraphrase noise — while one concrete condition spread it over 0.63.
- **No persistent write is derived from a score.** Role labelling did not
  generalise (2 of 5 correct on fresh samples; five unrelated functions all
  passed the gate with the same label), so `rename_function` and `set_comment`
  are never driven by the decision layer.

### Calibrate before trusting the order

Do not take the ranking seriously until you have measured it on your own
labelled data. Label a few dozen items, render the evidence with the same
template the server uses, and run:

```
RE_WORKBENCH_DECISION_URL=http://127.0.0.1:8009 \
python3 eval/calibrate.py eval/example-functions.jsonl \
    --question "Does this function read data from the network?"
```

It reports ROC AUC, top-k recall, the score range of each class and an explicit
verdict on whether the question discriminates on that data.
`eval/example-functions.jsonl` is a ten-line example fixture for smoke-testing
the runner only — it is hand-written, not a corpus, and proves nothing about
your binaries.

### Tests

```
python3 -m unittest discover -s mcp/tests -v
```

Stdlib `unittest`, no extra dependency. Tests that need a decision server are
skipped unless `RE_WORKBENCH_DECISION_URL` is set.

## Scope

Authorized reverse engineering only — your own binaries, CTFs, defensively
analyzed malware, and targets you may inspect. The tools read and describe; they
don't modify or deploy. Weaponization against third-party systems is out of
scope.
