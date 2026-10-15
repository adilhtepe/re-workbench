---
name: ghidra-triage
description: End-to-end reverse engineering of an unknown binary using the re-workbench MCP (Ghidra headless + lief). Use whenever the user hands over an executable, DLL, .so, object, or any compiled artifact and asks what it does, how it works, whether it is malicious, or to find a specific routine. Drives triage -> analyze -> targeted decompilation with surrounding context. Triggers on "reverse engineer this", "what does this binary do", "decompile", "analyze this exe/elf/dll/.so", "is this malware".
---

# Ghidra Triage

Turn an unknown binary into an understood one, efficiently. The re-workbench MCP
server exposes Ghidra's decompiler plus fast lief-based triage. Your job is to
drive those tools in the right order and, crucially, to **assemble context
around a function before interpreting it** — decompiled pseudo-C read in
isolation is a weak signal, and naming/understanding a function from its body
alone leads to confident-but-wrong conclusions.

## The workflow

Work top-down: cheap and broad first, expensive and narrow last.

1. **`triage(path)`** — instant, no JVM. Learn the format, architecture,
   bitness, sections (watch section entropy — a `.text` at ~7.9 bits/byte is
   packed), and the import table. The imports alone often reveal intent:
   `WinHttpConnect` + `CryptEncrypt` + `RegSetValueEx` tells a story before you
   decompile anything.

2. **`list_strings(path)`** — cheap. URLs, IPs, file paths, registry keys,
   format strings, error messages, version banners. Strings are the single
   highest-value-per-token artifact. Note offsets of anything interesting.

3. **`analyze(path)`** — boots Ghidra (~5-10s the first time, then cached).
   Confirms Ghidra's language/compiler guess and the function count.

4. **`list_functions(path, min_size=20)`** — skip tiny thunks with `min_size` so
   you see functions with real logic. Use `name_filter` to jump to `main`,
   `WinMain`, entry, or anything named after a string you found.

5. **`decompile(path, function)`** — the payoff. Leave `include_callers` and
   `include_strings` on: they attach *who calls this* and *what string literals
   it touches*, which is the context that makes pseudo-C interpretable. Decompile
   **targeted** functions, not everything — pick from steps 2 and 4.

Use **`xrefs(path, target)`** to pivot: found a suspicious string or a
`system`/`exec` import? See who reaches it. Use **`disassemble(path, address)`**
when pseudo-C hides the truth (jump tables, anti-debug timing checks,
self-modifying code, tight crypto loops).

## How to interpret, without overreaching

- **Follow the evidence chain, don't guess from shape.** "This function has a
  loop and some XORs" is not "this is the decryptor." Confirm with the strings it
  references, its callers, and the imports it ultimately reaches.
- **Name functions from behavior + context.** A function that calls
  `InternetOpenUrl` and references `"POST"` and a `.php` path is a C2 beacon,
  regardless of how its locals look.
- **State confidence.** Separate what the code *provably* does (this call, this
  compare, this write) from what you *infer* it's for. Say which is which.
- **Stay in budget.** Don't dump 40 decompilations into context hoping something
  sticks. Triage narrows the target set; decompile the few that matter.

## Optional: ranking tools (`rank_functions`, `rank_strings`)

**It is a two-way split, not a fine ranking.** Measured on a six-function batch with one
question: three items scored 0.8184-0.8198 and three scored 0.1845-0.1847 — a gap of 0.63
between the groups and 0.0014 inside the top group, which is below the 0.0041 spread the same
facts produce when the wording changes. Read which group an item landed in. The order inside a
group carries no measured signal: in that batch the highest score went to a logging helper,
above the HTTP header parser.

If a local decision model is configured (`RE_WORKBENCH_DECISION_URL`), two
extra tools will **order** a candidate list by one question. If it is not
configured they return the same full list in deterministic order. Check with
`decision_status()`.

**What they are for.** Deciding which of 40 candidates to decompile first, when
reference counts and string classes alone leave you with a flat list. One
request per item, roughly a second each, so a 50-function batch costs about a
minute.

**Check the cost before you pay it.** `decision_status()` gives the per-batch
estimate, and `rank_functions(..., dry_run=True)` / `rank_strings(...,
dry_run=True)` return this batch's estimate together with the deterministic
list, without sending a single request. The `elapsed_s` in a normal result is a
measurement after the fact, not a warning. A whole batch also runs under one
wall-clock deadline (300 s by default, `RE_WORKBENCH_DECISION_MAX_SECONDS`), and
says so in `aborted` when it stops early.

**What they are NOT.** They are not a verdict and not a filter:

- Nothing is dropped, hidden or filtered **by score**. The output always
  contains every candidate that reached the scoring step.
- Candidate **selection** is a filter, and it runs first: `limit` defaults to 50
  for functions and 150 for strings. Read `functions_total` /
  `strings_extracted` against `candidates_selected` to see how many never
  reached the list. Absent from the output means "not selected", never
  "unimportant".
- An item with `rank: null` was never asked about (deadline, `max_items`, a
  failed request). That is not a low rank.
- **A low score is not a "no".** Measured: the textbook true positive of an
  embedded binary (96 bytes, 14 inbound refs, only `memcpy`) scored 0.1790 and
  came last of nine candidates. Never skip a function because it ranked low.
- No threshold exists. Scores are banded — 41 measurements all landed inside
  [0.1774, 0.8384] — so a rule like ">= 0.85 means yes" can never fire, and an
  absolute flag rule (">= 0.80 is suspicious") flagged 7 of 7 files in a real
  set. Do not invent one.
- **Never rename or comment on the strength of a score.** Role labelling with
  this model did not generalise (2 of 5 correct on fresh samples; five
  unrelated functions all passed the gate with the same label), so
  `rename_function` / `set_comment` stay driven by evidence you read yourself.
- Scores from different calls are not comparable. They are a sort key inside
  one batch, produced from one evidence template.

**How to ask.** One concrete condition per call: "Does this function read data
from the network?", not "Does this function handle external input and pass it to
a memory operation without a bound check?". Measured on an 8-function set: the
single condition spread scores over 0.63 and put all 4 real targets in the top
5; the compound sentence collapsed the spread to 0.0047, which is inside the
0.0041 paraphrase noise — in other words, pure noise that still looks like a
ranking. You cannot tell those two cases apart by reading the output.

**Measure before you trust it.** The evidence is generated by code from a fixed
template precisely because the class margin (0.0015) measured smaller than the
spread from rewording the same facts (0.0041). Whether *your* question
separates *your* binaries is an open question until you label a few dozen items
and run `eval/calibrate.py`, which reports AUC, top-k recall, the per-class
score ranges and an explicit verdict on whether the question discriminates.
Below 30 labelled items it refuses to give a verdict at all and says
"unknown" — ten hand-written rows cannot tell you anything, however clean the
AUC looks. Do that first; until then treat the order as a hint and your own
reading of the code as the evidence.

## Going deeper by artifact type

For technique depth on a specific artifact (Go/Rust/.NET malware, ransomware
crypto, packed/obfuscated samples, mobile apps, memory dumps, firmware), see
`references/related-skills.md` — a map of the reverse-engineering skills already
installed on this machine. Invoke the matching one by name rather than
reinventing its workflow here.

## Reporting

Give the user a short brief, then detail:

```
# <filename> — <one-line verdict>
Format / arch: ...
Notable imports: ... (what they imply)
Notable strings: ... (offsets)
Key functions:
  - <name/addr>: what it does (confidence: high/med/low), evidence
Behavior summary: <what the binary does, end to end>
Open questions / next steps: ...
```

## Safety and scope

This is for authorized work: your own binaries, CTFs, malware you are analyzing
defensively, software you have the right to inspect. Analysis (reading,
decompiling, describing) is the whole job here — you are not modifying or
deploying anything. If asked to weaponize findings (build a working exploit for
a third-party system, defeat licensing on software the user doesn't own), decline
the weaponization while still helping with the analysis/defense.

## Setup note

The MCP needs `GHIDRA_INSTALL_DIR` and `JAVA_HOME` set in the plugin's
`.mcp.json`. If `analyze` returns a GHIDRA_INSTALL_DIR error, those paths are
wrong for this machine — see the plugin README's "Configuration" section.
