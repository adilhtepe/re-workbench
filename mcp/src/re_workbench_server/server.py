"""re-workbench MCP server.

Two tiers of tools:
  * Fast triage (lief + pure Python) — no JVM, instant. Format/arch, sections,
    imports/exports, strings, firmware signature + entropy scan.
  * Deep analysis (Ghidra via PyGhidra) — boots one JVM, caches analyzed
    programs. Function listing, decompilation with context, disassembly, xrefs.

The deep tools deliberately expose strings/imports/xrefs SEPARATELY from
decompilation so the caller can assemble rich context around a function — raw
pseudo-C alone is a weak signal for naming/understanding.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import firmware, ghidra_session

mcp = FastMCP("re-workbench")


def _j(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)


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
        strings = []
        listing = prog.getListing()
        body = f.getBody()
        data_iter = prog.getReferenceManager()
        for addr in body.getAddresses(True):
            for ref in data_iter.getReferencesFrom(addr):
                to = ref.getToAddress()
                d = listing.getDataAt(to)
                if d is not None and d.hasStringValue():
                    strings.append(str(d.getValue()))
        out["referenced_strings"] = sorted(set(strings))[:100]

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
