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
