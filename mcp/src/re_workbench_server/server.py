"""re-workbench MCP server.

Three tiers of tools:
  * Fast triage (lief + pure Python) — no JVM, instant. Format/arch, sections,
    imports/exports, strings, firmware signature + entropy scan.
  * Deep analysis (Ghidra via PyGhidra) — boots one JVM, caches analyzed
    programs. Function listing, decompilation with context, disassembly, xrefs.
  * Optional ranking (local decision model) — orders a candidate list by one
    question. Off by default, works without it, and ordering only: it drops
    nothing and returns no verdict. See decisions.py.

The deep tools deliberately expose strings/imports/xrefs SEPARATELY from
decompilation so the caller can assemble rich context around a function — raw
pseudo-C alone is a weak signal for naming/understanding.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import decisions, firmware, ghidra_session

mcp = FastMCP("re-workbench")

#: What replaces a non-finite float on its way out. The decision client already
#: refuses NaN/Infinity as a score, but one is cheap to produce elsewhere (a
#: ratio over zero, a value read straight from a reply) and a single one makes
#: the whole tool result unparseable for a strict JSON client.
_NOT_A_NUMBER = None


def _strict(obj: Any) -> Any:
    """Replace every non-finite float so the result is valid JSON.

    `json.dumps` defaults to allow_nan=True and emits the bare literals `NaN`,
    `Infinity` and `-Infinity`, which are not JSON: measured, one NaN in a batch
    made the whole tool output fail a strict reparse with "bare NaN".
    """
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else _NOT_A_NUMBER
    if isinstance(obj, dict):
        return {key: _strict(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_strict(value) for value in obj]
    return obj


def _j(obj: Any) -> str:
    # allow_nan=False turns a missed non-finite value into a loud error here
    # rather than into a quietly unparseable tool result at the client.
    return json.dumps(_strict(obj), indent=2, default=str, allow_nan=False)


def _score_sort_key(candidate: dict[str, Any]) -> tuple[bool, float, int]:
    """Sort key that is safe against a score that is not a number.

    A NaN comparator is not transitive, so sorting on a raw score moves the
    CORRECTLY scored items of the batch out of order too: measured ranks from
    one such batch were 0.28, nan, 0.30, nan, 0.21, 0.32. Anything that is not
    a finite number sorts after everything that is, and ties fall back to the
    deterministic rank.
    """
    score = candidate.get("score")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(float(score))
    ):
        return (True, 0.0, candidate["deterministic_rank"])
    return (False, -float(score), candidate["deterministic_rank"])


def _apply_ranks(
    selected: list[dict[str, Any]], ranked_by_score: bool
) -> tuple[int, int]:
    """Number the ranked items 1..N and leave the unscored ones rank null.

    An item that was never asked about must not get a rank number at the bottom
    of a score-ordered list: to a reader that is indistinguishable from "the
    model ranked it last". Returns (ranked, unscored).
    """
    position = 0
    unscored = 0
    for candidate in selected:
        if ranked_by_score and candidate.get("score") is None:
            candidate["rank"] = None
            candidate["rank_note"] = (
                "not scored, so not ranked: this item was never asked about, "
                "which is not the same as scoring low"
            )
            unscored += 1
            continue
        position += 1
        candidate["rank"] = position
    return position, unscored


# --------------------------------------------------------------------------
# Tier 1 — fast triage (no JVM)
# --------------------------------------------------------------------------


@mcp.tool()
def triage(path: str) -> str:
    """Fast static triage of a binary WITHOUT booting Ghidra. Returns file
    format (PE/ELF/Mach-O), architecture, bitness, endianness, entry point,
    sections with sizes and entropy, and libraries/imports. Use this FIRST on
    any unknown file — it is instant and tells you what you are dealing with."""
    import lief

    p = str(Path(path).resolve())
    if not Path(p).exists():
        return _j({"error": f"file not found: {p}"})
    b = lief.parse(p)
    if b is None:
        raw = Path(p).read_bytes()
        return _j(
            {
                "path": p,
                "format": "unknown/raw",
                "size": len(raw),
                "hint": "Not a recognized executable. If this is a firmware "
                "image, use scan_firmware.",
            }
        )

    fmt = str(b.format).split(".")[-1]
    hdr = b.header
    out: dict[str, Any] = {
        "path": p,
        "format": fmt,
        "size": Path(p).stat().st_size,
    }
    try:
        out["architecture"] = str(b.abstract.header.architecture).split(".")[-1]
    except Exception:
        try:
            out["architecture"] = str(hdr.machine).split(".")[-1]
        except Exception:
            pass
    try:
        out["entrypoint"] = hex(b.entrypoint)
    except Exception:
        pass
    try:
        out["sections"] = [
            {
                "name": s.name,
                "size": s.size,
                "vaddr": hex(s.virtual_address),
                "entropy": round(getattr(s, "entropy", 0.0), 3),
            }
            for s in b.sections
        ]
    except Exception:
        pass
    try:
        out["libraries"] = list(b.libraries)
    except Exception:
        pass
    try:
        out["imported_functions"] = [
            f.name for f in b.imported_functions
        ][:400]
    except Exception:
        pass
    return _j(out)


@mcp.tool()
def list_strings(
    path: str, min_len: int = 5, encoding: str = "both", limit: int = 2000
) -> str:
    """Extract printable strings (ASCII and/or UTF-16LE) with file offsets.
    encoding is 'ascii', 'utf16le', or 'both'. Essential for firmware/IoT secret
    hunting — look for URLs, IPs, keys, passwords, config paths, version banners."""
    return _j(firmware.extract_strings(path, min_len, encoding, limit))


@mcp.tool()
def scan_firmware(path: str) -> str:
    """Scan a firmware image or raw blob for embedded filesystems and payloads
    (squashfs, jffs2, cramfs, ubifs, cpio, gzip/xz/lzma, uImage, device trees,
    PEM keys/certs) by magic signature, plus a windowed entropy map to locate
    compressed/encrypted regions. Reports offsets to carve from. Pure Python —
    no binwalk needed."""
    return _j(firmware.scan(path))


# --------------------------------------------------------------------------
# Tier 2 — deep analysis (Ghidra / PyGhidra)
# --------------------------------------------------------------------------


def _program(path: str):
    flat = ghidra_session.get_program(path)
    return flat, flat.getCurrentProgram()


@mcp.tool()
def analyze(path: str) -> str:
    """Load a binary into Ghidra and run full auto-analysis (boots the JVM on
    first call, ~5-10s; the program is then cached for instant follow-up
    queries). Returns Ghidra's view: language/compiler, image base, and function
    count. Run this before decompile/list_functions/xrefs on a given file."""
    try:
        flat, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})
    fm = prog.getFunctionManager()
    return _j(
        {
            "path": str(Path(path).resolve()),
            "language": str(prog.getLanguageID()),
            "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
            "image_base": str(prog.getImageBase()),
            "function_count": fm.getFunctionCount(),
            "status": "analyzed and cached",
        }
    )


@mcp.tool()
def list_functions(
    path: str, name_filter: str = "", min_size: int = 0, limit: int = 500
) -> str:
    """List functions Ghidra found: name, entry address, size. name_filter is a
    case-insensitive substring; min_size (in bytes) skips tiny thunks/stubs so
    you can focus on functions with real logic. Use this to pick targets before
    decompiling."""
    try:
        _, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})
    fm = prog.getFunctionManager()
    nf = name_filter.lower()
    funcs = []
    for f in fm.getFunctions(True):
        body = f.getBody()
        size = body.getNumAddresses() if body else 0
        if size < min_size:
            continue
        name = f.getName()
        if nf and nf not in name.lower():
            continue
        funcs.append(
            {
                "name": name,
                "entry": str(f.getEntryPoint()),
                "size": size,
                "is_thunk": f.isThunk(),
                "is_external": f.isExternal(),
            }
        )
        if len(funcs) >= limit:
            break
    return _j({"count": len(funcs), "functions": funcs})


def _find_function(prog, flat, target: str):
    """Resolve target by name, or by address (hex like 0x401000)."""
    fm = prog.getFunctionManager()
    t = target.strip()
    if t.lower().startswith("0x") or t.isdigit():
        try:
            addr = flat.toAddr(int(t, 16) if t.lower().startswith("0x") else int(t))
            f = fm.getFunctionContaining(addr)
            if f:
                return f
        except Exception:
            pass
    for f in fm.getFunctions(True):
        if f.getName() == t:
            return f
    tl = t.lower()
    for f in fm.getFunctions(True):
        if f.getName().lower() == tl:
            return f
    return None


@mcp.tool()
def decompile(
    path: str,
    function: str,
    include_callers: bool = True,
    include_strings: bool = True,
    timeout: int = 60,
) -> str:
    """Decompile ONE function to pseudo-C. function is a name or a hex address.
    By default also returns the function's callers and the string literals it
    references — this surrounding context is what makes the pseudo-C
    interpretable (naming a function from its body alone is unreliable). Decompile
    targeted functions, not the whole binary, to stay within context."""
    try:
        flat, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    f = _find_function(prog, flat, function)
    if f is None:
        return _j({"error": f"function not found: {function!r}"})

    ifc = DecompInterface()
    ifc.openProgram(prog)
    res = ifc.decompileFunction(f, timeout, ConsoleTaskMonitor())
    if not res or not res.decompileCompleted():
        return _j({"error": f"decompilation failed for {function!r}"})
    code = res.getDecompiledFunction().getC()

    out: dict[str, Any] = {
        "name": f.getName(),
        "entry": str(f.getEntryPoint()),
        "signature": f.getPrototypeString(True, False),
        "pseudocode": code,
    }

    if include_callers:
        callers = sorted({c.getName() for c in f.getCallingFunctions(None)})
        out["callers"] = callers

    if include_strings:
        # Instructions carry the references; walking every byte of the body
        # costs one JVM round-trip per address for the same answer.
        out["referenced_strings"] = _function_strings(prog, f, 100)

    return _j(out)


@mcp.tool()
def disassemble(path: str, address: str, count: int = 60) -> str:
    """Disassemble `count` instructions starting at a hex address (e.g.
    0x401000). Use when you need the raw machine instructions rather than
    pseudo-C — checking a specific check, a jump table, or self-modifying code."""
    try:
        flat, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})
    try:
        addr = flat.toAddr(address)
    except Exception:
        return _j({"error": f"bad address: {address!r}"})
    listing = prog.getListing()
    insns = []
    ins = listing.getInstructionAt(addr)
    while ins is not None and len(insns) < count:
        insns.append({"addr": str(ins.getAddress()), "asm": str(ins)})
        ins = ins.getNext()
    return _j({"address": address, "count": len(insns), "instructions": insns})


@mcp.tool()
def xrefs(path: str, target: str) -> str:
    """Find cross-references TO a function (by name) or an address (hex): who
    calls it / points at it, and from where. Use to trace how a suspicious
    function or a string/constant is reached."""
    try:
        flat, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})

    f = _find_function(prog, flat, target)
    if f is not None:
        addr = f.getEntryPoint()
        label = f.getName()
    else:
        try:
            addr = flat.toAddr(target)
            label = target
        except Exception:
            return _j({"error": f"target not found: {target!r}"})

    rm = prog.getReferenceManager()
    fm = prog.getFunctionManager()
    refs = []
    for r in rm.getReferencesTo(addr):
        frm = r.getFromAddress()
        containing = fm.getFunctionContaining(frm)
        refs.append(
            {
                "from": str(frm),
                "in_function": containing.getName() if containing else None,
                "type": str(r.getReferenceType()),
            }
        )
    return _j({"target": label, "address": str(addr), "xref_count": len(refs), "xrefs": refs})


@mcp.tool()
def rename_function(path: str, target: str, new_name: str) -> str:
    """Rename a function (by current name or hex address) and persist it to the
    Ghidra project. Use this to record what you've figured out — a function you
    identified as the C2 beacon becomes `c2_beacon`, so later decompilations and
    xrefs read in your names instead of `FUN_00401abc`. Understanding accumulates
    in the project across queries and iterations."""
    try:
        flat, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})
    from ghidra.program.model.symbol import SourceType

    f = _find_function(prog, flat, target)
    if f is None:
        return _j({"error": f"function not found: {target!r}"})
    old = f.getName()
    tx = prog.startTransaction("re-workbench rename")
    ok = True
    try:
        f.setName(new_name, SourceType.USER_DEFINED)
    except Exception as e:
        ok = False
        err = str(e)
    finally:
        prog.endTransaction(tx, ok)
    if not ok:
        return _j({"error": err})
    try:
        prog.save("re-workbench rename", ghidra_session.monitor())
    except Exception:
        pass  # persists on session close regardless
    return _j({"renamed": old, "to": new_name, "entry": str(f.getEntryPoint())})


@mcp.tool()
def set_comment(path: str, address: str, comment: str) -> str:
    """Attach a plate comment at a hex address in the Ghidra project — record a
    note about what a block does. Persists like rename_function."""
    try:
        flat, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})
    try:
        addr = flat.toAddr(address)
    except Exception:
        return _j({"error": f"bad address: {address!r}"})
    from ghidra.program.model.listing import CodeUnit

    listing = prog.getListing()
    cu = listing.getCodeUnitAt(addr)
    if cu is None:
        return _j({"error": f"no code unit at {address}"})
    tx = prog.startTransaction("re-workbench comment")
    try:
        cu.setComment(CodeUnit.PLATE_COMMENT, comment)
    finally:
        prog.endTransaction(tx, True)
    try:
        prog.save("re-workbench comment", ghidra_session.monitor())
    except Exception:
        pass
    return _j({"address": address, "comment": comment})


@mcp.tool()
def session_status() -> str:
    """List binaries currently loaded and cached in the Ghidra session."""
    return _j({"open_programs": ghidra_session.open_paths()})


# --------------------------------------------------------------------------
# Tier 3 — optional ranking against a local decision model
# --------------------------------------------------------------------------
#
# Ordering help only. These tools never drop, filter or hide a candidate, never
# return a verdict, and never feed a persistent write (rename_function /
# set_comment). They work with no decision server configured, in which case the
# same full list comes back in deterministic order. See decisions.py for the
# measurements that forced this shape.


def _xref_count(prog, addr) -> int:
    rm = prog.getReferenceManager()
    n = 0
    for _ in rm.getReferencesTo(addr):
        n += 1
    return n


def _imported_calls(f, limit: int = 8) -> list[str]:
    """Names of imported/thunked functions this function calls, sorted.

    Raises on an API failure instead of returning []: an empty list renders as
    "imported calls: none", which a reader cannot tell apart from a function
    that genuinely calls nothing. The caller counts the failures and says so.
    """
    names = set()
    for callee in f.getCalledFunctions(None):
        try:
            if callee.isExternal() or callee.isThunk():
                names.add(callee.getName())
        except Exception:
            continue
    return sorted(names)[:limit]


def _function_strings(prog, f, limit: int) -> list[str]:
    """String literals referenced from inside a function body, sorted.

    Iterating `body.getAddresses(True)` walks every BYTE of the function and
    issues getReferencesFrom + getDataAt per address: for 50 functions
    averaging 1 KB that is ~100k JVM round-trips in one call, dwarfing the
    decision requests it exists to feed. References hang off instructions, so
    iterate the instructions in the body instead.

    Raises on an API failure; see _imported_calls.
    """
    listing = prog.getListing()
    body = f.getBody()
    if body is None:
        return []
    found = set()
    for insn in listing.getInstructions(body, True):
        for ref in insn.getReferencesFrom():
            data = listing.getDataAt(ref.getToAddress())
            if data is not None and data.hasStringValue():
                found.add(str(data.getValue()))
    return sorted(found)[:limit]


def _section_ranges(path: str) -> list[tuple[int, int, str]]:
    """(file_offset_start, end, name) per section, for locating a string."""
    try:
        import lief

        b = lief.parse(str(Path(path).resolve()))
        if b is None:
            return []
        out: list[tuple[int, int, str]] = []
        for s in b.sections:
            try:
                start = int(s.offset)
                out.append((start, start + int(s.size), str(s.name)))
            except Exception:
                continue
        return out
    except Exception:
        return []


def _section_at(offset: int, ranges: list[tuple[int, int, str]]) -> str | None:
    for start, end, name in ranges:
        if start <= offset < end and name:
            return name
    return None


def _rank_envelope(
    scoring: dict[str, Any], question: str, question_id: str, extra: dict[str, Any]
) -> dict[str, Any]:
    """Shared head of a ranking result, decision server present or not."""
    out: dict[str, Any] = {
        "status": scoring.get("status", "unavailable"),
        "ranking": (
            "decision_score"
            if scoring.get("status") in ("ok", "partial")
            else "deterministic_fallback"
        ),
        "question": question,
        "question_id": question_id,
        "template_version": decisions.EVIDENCE_TEMPLATE_VERSION,
        "model": scoring.get("model"),
        "decision_url": scoring.get("url"),
    }
    if scoring.get("reason"):
        out["reason"] = scoring["reason"]
    out.update(extra)
    for field in (
        "scored",
        "unscored",
        "clamped_evidence",
        "evidence_shapes_sent",
        "evidence_shape_warning",
        "max_items",
        "max_seconds",
        "aborted",
        "usage",
        "elapsed_s",
        "errors",
    ):
        if field in scoring:
            out[field] = scoring[field]
    if scoring.get("usage", {}).get("requests"):
        # Only claim a cost once one has actually been paid. The estimate used
        # to be emitted with the result even when no request had been sent.
        out["estimated_seconds_for_this_batch"] = extra.get("_estimate")
    out.pop("_estimate", None)
    out["caveats"] = list(decisions.CAVEATS)
    return out


#: One sentence, shared by both ranking tools, about how to see the cost first.
_COST_NOTE = (
    "This number is a measurement AFTER the fact. To see the cost before "
    "paying it, call the same tool with dry_run=True (deterministic list plus "
    "the estimate, no request sent) or decision_status() for the per-batch "
    "estimate."
)


def _dry_run(
    question: str,
    question_id: str,
    item_count: int,
    estimate: float,
    extra: dict[str, Any],
) -> dict[str, Any]:
    """Pre-flight result: the deterministic list and the cost, nothing asked.

    This sends NO request, not even a probe: a pre-flight that costs a round
    trip to report what a round trip costs is the thing it is meant to replace.
    So it reports the configuration only; call decision_status() separately if
    reachability matters.
    """
    try:
        config = decisions.DecisionConfig.from_env()
        server_info: dict[str, Any] = {
            "configured": config is not None,
            "reachable": "not checked: a dry run sends no request",
            "model": config.model if config else None,
            "url": config.url if config else None,
            "max_items": config.max_items if config else None,
            "max_seconds": config.max_seconds if config else None,
        }
    except decisions.DecisionConfigError as exc:
        server_info = {"configured": True, "reachable": False, "reason": str(exc)}
    out: dict[str, Any] = {
        "status": "dry_run",
        "ranking": "deterministic_fallback",
        "question": question,
        "question_id": question_id,
        "template_version": decisions.EVIDENCE_TEMPLATE_VERSION,
        "decision_server": server_info,
        "requests_planned": item_count,
        "estimated_seconds": estimate,
        "note": (
            "DRY RUN: no request was sent and no item was scored. The list below "
            "is in deterministic order. Re-run with dry_run=False to spend the "
            f"estimated {estimate}s."
        ),
    }
    extra.pop("_estimate", None)
    out.update(extra)
    out["caveats"] = list(decisions.CAVEATS)
    return out


@mcp.tool()
def rank_functions(
    path: str,
    question: str,
    min_size: int = 0,
    limit: int = 50,
    dry_run: bool = False,
) -> str:
    """ORDER a function list by one question, using the optional local decision
    model. SCORING drops nothing: every candidate that reaches the scoring step
    is returned with its score, and no suspicious/clean or
    important/unimportant label is produced. Candidate SELECTION, however, is a
    filter: `limit` (default 50) and `min_size` cut the list deterministically
    before any scoring, and `functions_total` vs `candidates_total` vs
    `candidates_selected` in the result say how many functions each step left
    behind — absent from the output does NOT mean unimportant. This is a sort
    key, not a judgement. A LOW SCORE IS NOT A NEGATIVE ANSWER and is never a
    reason to skip a function — a measured true positive (96 bytes, 14 inbound
    refs, only memcpy) scored 0.1790 and came last of nine candidates.

    `question` must be ONE concrete condition ("Does this function read data
    from the network?"), not a compound sentence: measured, a multi-clause
    question collapsed the score spread of an 8-function set to 0.0047, which
    is inside paraphrase noise, while a single condition spread it over 0.63.
    Evidence is generated by code from one fixed template (name, size, inbound
    reference count, imported calls, referenced strings), so scores are
    comparable only against the other items of the same call.

    `min_size` and `limit` select candidates DETERMINISTICALLY before any
    scoring (by inbound reference count, then size, then name); the counts are
    reported. Each item also carries `fallback_rank_key` (inbound reference
    count) and its deterministic rank, so you can see where the model disagrees
    with plain reference counting. With no decision server configured the same
    full list is returned in deterministic order and status is "unavailable".

    `dry_run=True` returns that deterministic list and the wall-clock estimate
    WITHOUT sending a single request, so the cost can be read before it is
    paid. Scores must be calibrated on your own labelled data
    (eval/calibrate.py) before the order is worth anything; treat it as a hint,
    never as evidence.
    """
    try:
        _, prog = _program(path)
    except Exception as e:
        return _j({"error": str(e)})

    fm = prog.getFunctionManager()
    candidates = []
    functions_total = 0
    excluded_external = 0
    excluded_min_size = 0
    for f in fm.getFunctions(True):
        functions_total += 1
        body = f.getBody()
        size = body.getNumAddresses() if body else 0
        if size < min_size:
            excluded_min_size += 1
            continue
        try:
            if f.isExternal():
                excluded_external += 1
                continue
        except Exception:
            pass
        candidates.append(
            {
                "name": f.getName(),
                "entry": str(f.getEntryPoint()),
                "size": size,
                "xref_count": _xref_count(prog, f.getEntryPoint()),
                "_f": f,
            }
        )

    total = len(candidates)
    # Deterministic candidate selection and deterministic fallback order.
    candidates.sort(key=lambda c: (-c["xref_count"], -c["size"], c["name"]))
    selected = candidates[: max(0, limit)]

    enrichment_errors: list[dict[str, str]] = []

    def enrich(candidate, field, getter):
        """Run one enrichment step, counting a failure instead of hiding it."""
        try:
            return getter()
        except Exception as exc:  # a Ghidra API failure, not a missing value
            enrichment_errors.append(
                {"entry": candidate["entry"], "field": field,
                 "error": f"{type(exc).__name__}: {exc}"}
            )
            candidate["enrichment_error"] = (
                f"{field}: {type(exc).__name__}: {exc}"
            )
            return []

    items = []
    for position, c in enumerate(selected, start=1):
        c["deterministic_rank"] = position
        c["fallback_rank_key"] = c["xref_count"]
        c["imported_calls"] = enrich(
            c, "imported calls", lambda f=c["_f"]: _imported_calls(f)
        )
        c["referenced_strings"] = enrich(
            c, "referenced strings", lambda f=c["_f"]: _function_strings(prog, f, 4)
        )
        evidence, clamped = decisions.function_evidence(
            c["name"],
            c["size"],
            c["xref_count"],
            c["imported_calls"],
            c["referenced_strings"],
        )
        c["evidence"] = evidence
        c["evidence_clamped"] = clamped
        c.pop("_f", None)
        items.append({"key": c["entry"], "evidence": evidence})

    tokens = max(
        (decisions.estimate_tokens(i["evidence"]) for i in items), default=0
    )
    announced = decisions.estimate_batch_seconds(len(items), tokens)

    extra = {
        "path": str(Path(path).resolve()),
        "functions_total": functions_total,
        "excluded_external": excluded_external,
        "excluded_below_min_size": excluded_min_size,
        "candidates_total": total,
        "candidates_selected": len(selected),
        "not_selected": total - len(selected),
        "min_size": min_size,
        "limit": limit,
        "selection": (
            "deterministic: external stubs excluded, size >= min_size, then "
            "ordered by inbound reference count, size, name; first `limit` "
            "kept. functions_total is every function in the program, "
            "candidates_total what survived min_size and the external filter, "
            "candidates_selected what `limit` kept and the only ones scored"
        ),
        "_estimate": announced,
    }
    if enrichment_errors:
        extra["enrichment_failed"] = len(enrichment_errors)
        extra["enrichment_errors"] = enrichment_errors[:20]
        extra["enrichment_warning"] = (
            f"{len(enrichment_errors)} evidence field(s) could not be read from "
            "Ghidra and render as 'none', which is indistinguishable from "
            "genuinely having none. The order of this call is not meaningful "
            "for the affected items."
        )

    if dry_run:
        out = _dry_run(question, "rank_functions", len(items), announced, extra)
        _apply_ranks(selected, ranked_by_score=False)
        out["functions"] = selected
        return _j(out)

    scoring = decisions.score_items(
        items,
        "rank_functions",
        question,
        config=None,
    )
    scores = scoring.get("scores") or {}
    for c in selected:
        entry = scores.get(c["entry"]) or {}
        c["score"] = entry.get("score")
        c["score_raw"] = entry.get("raw")
        if entry.get("error"):
            c["score_error"] = entry["error"]

    ranked_by_score = scoring.get("status") in ("ok", "partial")
    if ranked_by_score:
        selected.sort(key=_score_sort_key)
    ranked, unranked = _apply_ranks(selected, ranked_by_score)
    extra["ranked"] = ranked
    extra["unranked"] = unranked
    if unranked:
        extra["unranked_note"] = (
            f"{unranked} item(s) carry rank null: they were never asked about "
            "(see each one's score_error), which is not the same as ranking low"
        )

    out = _rank_envelope(scoring, question, "rank_functions", extra)
    if "estimated_seconds_for_this_batch" in out:
        out["cost_note"] = _COST_NOTE
    out["functions"] = selected
    return _j(out)


@mcp.tool()
def rank_strings(
    path: str,
    question: str,
    pattern: str = "",
    limit: int = 150,
    dry_run: bool = False,
) -> str:
    """ORDER interesting strings by one question. Same contract as
    rank_functions: a sort key, not a judgement; every candidate that passed
    the pre-filter is returned; nothing is filtered out by score and a low
    score is not a negative answer.

    Candidate selection is DETERMINISTIC and happens before any scoring: the
    `pattern` regex (case-sensitive, Python syntax) applied to the extracted
    strings, or, when `pattern` is empty, a named default pattern set for the
    classic classes of an embedded image (urls, IPv4, hostnames, credential
    words, key material, unix/windows paths, shell commands, config keys,
    format strings). The number of strings extracted, the number that passed
    the pre-filter and the number actually scored are all reported, as is the
    per-item evidence. Runs without Ghidra (lief + pure Python), so inbound
    reference counts are reported as unknown here; use xrefs(path, string) to
    resolve one.

    `matched_classes` and `fallback_rank_key` mean the same thing whether or
    not a custom `pattern` is given: the named classes are always computed as a
    description of the string, and the fallback key is always the number of
    matched classes, then length. `pattern` only decides which strings are
    candidates.

    Keep `question` to ONE concrete condition. With no decision server
    configured the same full list comes back ordered by the deterministic
    fallback key and status is "unavailable". `dry_run=True` returns that list
    and the wall-clock estimate without sending a request, so the cost can be
    read before it is paid. Calibrate with eval/calibrate.py before trusting
    the order.
    """
    p = Path(path)
    if not p.exists():
        return _j({"error": f"file not found: {p}"})

    try:
        matcher = re.compile(pattern) if pattern else re.compile(
            decisions.default_string_pattern()
        )
    except re.error as e:
        return _j({"error": f"bad pattern {pattern!r}: {e}"})

    min_len = 5
    extract_limit = 200000
    extracted = firmware.extract_strings(
        str(p), min_len=min_len, encoding="both", limit=extract_limit
    )
    ranges = _section_ranges(str(p))

    # `count` is the untruncated total; `strings` is cut to extract_limit. The
    # pre-filter only ever sees the truncated list, so reporting `count` as the
    # number examined would claim the tail of a large image was looked at.
    examined = extracted.get("strings", [])
    truncated = bool(extracted.get("truncated"))

    candidates = []
    for s in examined:
        text = s["s"]
        if not matcher.search(text):
            continue
        # Always computed: the classes describe the string, they do not select
        # it. Forcing them to [] under a custom pattern silently turned
        # fallback_rank_key into plain string length and collapsed the first two
        # keys of the deterministic sort into the same value.
        classes = decisions.classify_string(text)
        candidates.append(
            {
                "string": text,
                "offset": s["offset"],
                "hex_offset": hex(s["offset"]),
                "encoding": s["enc"],
                "section": _section_at(s["offset"], ranges),
                "matched_classes": classes,
                "fallback_rank_key": len(classes),
            }
        )

    matched = len(candidates)
    candidates.sort(
        key=lambda c: (-c["fallback_rank_key"], -len(c["string"]), c["offset"])
    )
    selected = candidates[: max(0, limit)]

    items = []
    for position, c in enumerate(selected, start=1):
        c["deterministic_rank"] = position
        evidence, clamped = decisions.string_evidence(
            c["string"],
            section=c["section"],
            xref_count=None,
            offset=c["offset"],
            encoding=c["encoding"],
        )
        c["evidence"] = evidence
        c["evidence_clamped"] = clamped
        items.append({"key": f"{c['offset']}:{c['encoding']}", "evidence": evidence})

    tokens = max(
        (decisions.estimate_tokens(i["evidence"]) for i in items), default=0
    )
    announced = decisions.estimate_batch_seconds(len(items), tokens)

    extra = {
        "path": str(p.resolve()),
        "strings_extracted": extracted.get("count", 0),
        "strings_examined": len(examined),
        "strings_truncated": truncated,
        "extract_limit": extract_limit,
        "min_len": min_len,
        "prefilter_matched": matched,
        "candidates_selected": len(selected),
        "not_selected": matched - len(selected),
        "limit": limit,
        "pattern": pattern or "<default pattern set>",
        "pattern_classes": [name for name, _ in decisions.DEFAULT_STRING_PATTERNS],
        "selection": (
            "deterministic regex pre-filter over the extracted strings, then by "
            "matched class count, length, offset; first `limit` kept"
        ),
        "_estimate": announced,
    }
    if truncated:
        extra["truncation_warning"] = (
            f"string extraction stopped at extract_limit={extract_limit}: "
            f"{extracted.get('count', 0)} strings were found but only the first "
            f"{len(examined)} (by file offset) reached the pre-filter, so the "
            "tail of the file was not examined at all"
        )

    if dry_run:
        out = _dry_run(question, "rank_strings", len(items), announced, extra)
        _apply_ranks(selected, ranked_by_score=False)
        out["strings"] = selected
        return _j(out)

    scoring = decisions.score_items(items, "rank_strings", question, config=None)
    scores = scoring.get("scores") or {}
    for c in selected:
        entry = scores.get(f"{c['offset']}:{c['encoding']}") or {}
        c["score"] = entry.get("score")
        c["score_raw"] = entry.get("raw")
        if entry.get("error"):
            c["score_error"] = entry["error"]

    ranked_by_score = scoring.get("status") in ("ok", "partial")
    if ranked_by_score:
        selected.sort(key=_score_sort_key)
    ranked, unranked = _apply_ranks(selected, ranked_by_score)
    extra["ranked"] = ranked
    extra["unranked"] = unranked
    if unranked:
        extra["unranked_note"] = (
            f"{unranked} item(s) carry rank null: they were never asked about "
            "(see each one's score_error), which is not the same as ranking low"
        )

    out = _rank_envelope(scoring, question, "rank_strings", extra)
    if "estimated_seconds_for_this_batch" in out:
        out["cost_note"] = _COST_NOTE
    out["strings"] = selected
    return _j(out)


@mcp.tool()
def decision_status() -> str:
    """Report whether the optional decision-ranking layer is configured and
    reachable, which model answers, and the measured limits that constrain how
    its output may be used. Call this before rank_functions / rank_strings to
    know whether you will get scores or the deterministic fallback order, and
    what a batch will cost in wall-clock seconds. The repository works fully
    without a decision server."""
    status = decisions.probe()
    status["env"] = {
        "RE_WORKBENCH_DECISION_URL": "loopback only (127.0.0.1 / localhost / ::1)",
        "RE_WORKBENCH_DECISION_MODEL": decisions.DEFAULT_MODEL,
        "RE_WORKBENCH_DECISION_TIMEOUT": decisions.DEFAULT_TIMEOUT,
        "RE_WORKBENCH_DECISION_MAX_ITEMS": decisions.DEFAULT_MAX_ITEMS,
        "RE_WORKBENCH_DECISION_MAX_SECONDS": decisions.DEFAULT_MAX_SECONDS,
        "RE_WORKBENCH_DECISION_MAX_CONSECUTIVE_ERRORS": (
            decisions.DEFAULT_MAX_CONSECUTIVE_ERRORS
        ),
    }
    status["evidence"] = {
        "template_version": decisions.EVIDENCE_TEMPLATE_VERSION,
        "max_tokens_per_item": decisions.MAX_EVIDENCE_TOKENS,
        "generated_by": "code, from one fixed template per item type",
    }
    status["cost"] = {
        "measured_latency_tokens_to_seconds": [
            list(pair) for pair in decisions.MEASURED_LATENCY
        ],
        "one_request_per_item": True,
        "estimated_seconds_for_50_items": decisions.estimate_batch_seconds(50),
        "estimated_seconds_for_150_items": decisions.estimate_batch_seconds(150),
        "batch_deadline_seconds": decisions.DEFAULT_MAX_SECONDS,
        "per_batch_estimate_before_running": (
            "call rank_functions / rank_strings with dry_run=True: it returns "
            "the deterministic list and this batch's estimate without sending "
            "a single request"
        ),
    }
    status["measured_limits"] = [
        "Latency is super-linear in state length: 76 tokens 0.57 s, 241 tokens "
        "1.61 s, 961 tokens 7.08 s, 3061 tokens 30.6 s.",
        "Scores are banded: all 41 measurements fell inside [0.1774, 0.8384], "
        "so absolute thresholds cannot fire.",
        "A low score is not a negative answer; a measured true positive scored "
        "0.1790 and ranked last of nine.",
        "An absolute flag rule (>= 0.80) flagged 7 of 7 files in a real set.",
        "Class margin (0.0015) measured smaller than paraphrase noise (0.0041), "
        "hence code-generated evidence and single-condition questions.",
        "Ranking several candidates in one call inverted the order, hence one "
        "request per item.",
        "Role labelling did not generalise, hence no persistent write "
        "(rename_function / set_comment) is ever derived from a score.",
        "Per-request timeouts are additive: 5 items against a sleeping server "
        "with a 1 s per-request timeout took 5.03 s, so every batch runs under "
        f"one wall-clock deadline ({decisions.DEFAULT_MAX_SECONDS}s by default).",
    ]
    status["caveats"] = list(decisions.CAVEATS)
    return _j(status)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
