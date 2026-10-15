"""Tests for the ranking MCP tools themselves.

These import the server module, so they are skipped where the `mcp` package is
not installed (e.g. a bare stdlib interpreter). rank_strings needs no Ghidra
and no decision server, which is exactly the portability property under test:
with nothing configured the tool must still return the complete candidate list
in deterministic order.

Run from the repository root:

    python3 -m unittest discover -s mcp/tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    from re_workbench_server import decisions, server
except ImportError as exc:  # pragma: no cover - depends on the interpreter
    server = None
    _IMPORT_ERROR = str(exc)

requires_server_module = unittest.skipIf(
    server is None, "re_workbench_server.server could not be imported"
)

SAMPLE = b"""\
MAGIC HEADER v1.2.3
http://update.example.com/fw/latest.bin
admin:Sup3rSecret!
/etc/init.d/rcS
/bin/sh -c "iptables -F"
192.168.1.1
-----BEGIN RSA PRIVATE KEY-----
ssid=HomeNet wpa_psk=0123456789abcdef
GET %s HTTP/1.1
this is just some filler prose with no interesting pattern at all
another harmless sentence about nothing in particular here
bootcmd=bootm 0x82000000
"""


@requires_server_module
class TestRankStringsWithoutDecisionServer(unittest.TestCase):
    """No URL configured: deterministic order, complete list, no verdict."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls._tmp.name) / "sample.bin"
        cls.path.write_bytes(SAMPLE)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def rank(self, **kwargs):
        kwargs.setdefault("question", "Does this string contain a credential?")
        # env={} is not reachable through the tool, so clear the variable.
        import os

        previous = os.environ.pop("RE_WORKBENCH_DECISION_URL", None)
        try:
            return json.loads(server.rank_strings(str(self.path), **kwargs))
        finally:
            if previous is not None:
                os.environ["RE_WORKBENCH_DECISION_URL"] = previous

    def test_status_is_unavailable_and_ranking_is_deterministic(self):
        out = self.rank()
        self.assertEqual(out["status"], "unavailable")
        self.assertEqual(out["ranking"], "deterministic_fallback")
        self.assertIn("RE_WORKBENCH_DECISION_URL", out["reason"])

    def test_nothing_is_dropped(self):
        out = self.rank()
        self.assertGreater(out["prefilter_matched"], 0)
        self.assertEqual(out["candidates_selected"], out["prefilter_matched"])
        self.assertEqual(len(out["strings"]), out["candidates_selected"])
        self.assertEqual(
            [s["rank"] for s in out["strings"]],
            list(range(1, len(out["strings"]) + 1)),
        )
        for item in out["strings"]:
            self.assertIsNone(item["score"])
            self.assertIn("fallback_rank_key", item)
            self.assertIn("evidence", item)

    def test_the_known_candidates_are_all_present(self):
        out = self.rank()
        found = [s["string"] for s in out["strings"]]
        for expected in (
            "admin:Sup3rSecret!",
            "-----BEGIN RSA PRIVATE KEY-----",
            "http://update.example.com/fw/latest.bin",
            "192.168.1.1",
            "bootcmd=bootm 0x82000000",
        ):
            self.assertIn(expected, found)

    def test_prose_is_excluded_by_the_deterministic_prefilter_only(self):
        out = self.rank()
        found = [s["string"] for s in out["strings"]]
        self.assertNotIn(
            "this is just some filler prose with no interesting pattern at all", found
        )
        self.assertLess(out["prefilter_matched"], out["strings_extracted"])

    def test_repeated_calls_give_the_same_order(self):
        first = [s["string"] for s in self.rank()["strings"]]
        second = [s["string"] for s in self.rank()["strings"]]
        self.assertEqual(first, second)

    def test_custom_pattern_is_honoured(self):
        out = self.rank(pattern=r"PRIVATE KEY")
        self.assertEqual(out["pattern"], "PRIVATE KEY")
        self.assertEqual(
            [s["string"] for s in out["strings"]], ["-----BEGIN RSA PRIVATE KEY-----"]
        )

    def test_limit_is_reported_and_never_silently_hides_the_count(self):
        out = self.rank(limit=2)
        self.assertEqual(len(out["strings"]), 2)
        self.assertGreater(out["prefilter_matched"], 2)
        self.assertEqual(out["candidates_selected"], 2)

    def test_bad_pattern_reports_an_error(self):
        out = self.rank(pattern="([unclosed")
        self.assertIn("error", out)

    def test_missing_file_reports_an_error(self):
        out = json.loads(server.rank_strings("/nonexistent/x.bin", "q"))
        self.assertIn("error", out)

    def test_output_carries_the_caveats_and_no_verdict(self):
        out = self.rank()
        joined = " ".join(out["caveats"]).lower()
        self.assertIn("low score is not a negative answer", joined)
        for forbidden in ("verdict", "suspicious", "clean", "flagged", "important"):
            self.assertNotIn(forbidden, out)
        self.assertEqual(out["template_version"], decisions.EVIDENCE_TEMPLATE_VERSION)


@requires_server_module
class TestToolContracts(unittest.TestCase):
    def test_the_ranking_tools_exist(self):
        for name in ("rank_functions", "rank_strings", "decision_status"):
            self.assertTrue(callable(getattr(server, name, None)), name)

    def test_docstrings_tell_the_caller_it_is_ordering_only(self):
        import re

        for name in ("rank_functions", "rank_strings"):
            doc = re.sub(r"\s+", " ", (getattr(server, name).__doc__ or "").lower())
            with self.subTest(tool=name):
                self.assertIn("not a judgement", doc)
                self.assertIn("low score is not a negative answer", doc)
                self.assertIn("calibrate", doc)

    def test_persistent_writes_are_not_tied_to_a_score(self):
        """rename_function / set_comment must not touch the decision layer."""
        import inspect

        for name in ("rename_function", "set_comment"):
            source = inspect.getsource(getattr(server, name))
            with self.subTest(tool=name):
                self.assertNotIn("decisions", source)
                self.assertNotIn("score", source)

    def test_decision_status_works_without_a_server(self):
        import os

        previous = os.environ.pop("RE_WORKBENCH_DECISION_URL", None)
        try:
            out = json.loads(server.decision_status())
        finally:
            if previous is not None:
                os.environ["RE_WORKBENCH_DECISION_URL"] = previous
        self.assertEqual(out["status"], "unavailable")
        self.assertFalse(out["configured"])
        self.assertTrue(out["measured_limits"])
        self.assertTrue(out["caveats"])


if __name__ == "__main__":
    unittest.main()
