"""One JVM, many queries. PyGhidra boots slowly (~5-10s) and re-analysis is
expensive, so we start the JVM once and keep each analyzed program open for the
process lifetime, keyed by absolute path."""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

# Ghidra writes a project sidecar; the binary's own directory may be read-only
# (e.g. System32), so route all projects to one writable cache dir.
_PROJECT_ROOT = Path(
    os.environ.get("RE_WORKBENCH_PROJECTS")
    or (Path(tempfile.gettempdir()) / "re-workbench-ghidra")
)

_lock = threading.Lock()
_started = False
# path -> {"flat": flat_api, "ctx": open_program context manager}
_programs: dict[str, dict[str, Any]] = {}


def start() -> None:
    global _started
    with _lock:
        if _started:
            return
        install = os.environ.get("GHIDRA_INSTALL_DIR")
        if not install or not Path(install).exists():
            raise RuntimeError(
                "GHIDRA_INSTALL_DIR is not set or does not exist: "
                f"{install!r}. Set it in the plugin's .mcp.json env block."
            )
        import pyghidra

        pyghidra.start(verbose=False)
        _started = True


def get_program(path: str, analyze: bool = True):
    """Return a Ghidra FlatProgramAPI for `path`, opening + auto-analyzing on
    first request and reusing the open program thereafter."""
    start()
    p = str(Path(path).resolve())
    if not Path(p).exists():
        raise FileNotFoundError(p)
    with _lock:
        if p in _programs:
            return _programs[p]["flat"]
        import pyghidra

        _PROJECT_ROOT.mkdir(parents=True, exist_ok=True)
        # Distinct, writable project per binary so read-only source dirs (e.g.
        # System32) don't block the sidecar, and different files don't collide.
        proj_name = (
            Path(p).stem + "_" + hashlib.sha1(p.encode()).hexdigest()[:8]
        )
        # Enter the context manager manually and hold it open. open_program runs
        # auto-analysis on first import into the project.
        ctx = pyghidra.open_program(
            p,
            analyze=analyze,
            project_location=str(_PROJECT_ROOT),
            project_name=proj_name,
        )
        flat = ctx.__enter__()
        _programs[p] = {"flat": flat, "ctx": ctx}
        return flat


def close(path: str) -> bool:
    p = str(Path(path).resolve())
    with _lock:
        entry = _programs.pop(p, None)
    if entry is None:
        return False
    try:
        entry["ctx"].__exit__(None, None, None)
    except Exception:
        pass
    return True


def open_paths() -> list[str]:
    with _lock:
        return list(_programs)


def monitor():
    """A TaskMonitor for save/analysis calls. Import lazily — Ghidra classes
    only exist after start()."""
    from ghidra.util.task import ConsoleTaskMonitor

    return ConsoleTaskMonitor()
