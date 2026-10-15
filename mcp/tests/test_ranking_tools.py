"""Tests for the ranking MCP tools themselves.

These import the server module, which imports the `mcp` SDK, so on a bare
stdlib interpreter they are SKIPPED — and the skip is announced loudly on
stderr, because a silent skip of these particular tests is worse than useless:
they are the ones that check the portability property (rank_strings needs no
Ghidra and no decision server, so with nothing configured the tool must still
return the complete candidate list in deterministic order), and a quiet
"OK (skipped=14)" reads as if that property had been verified.

Run them with the project's dependencies:

    uv run --directory mcp python -m unittest discover -s tests -v

Set RE_WORKBENCH_REQUIRE_SERVER_TESTS=1 to turn the skip into a failure, which
is what CI should do.
"""

from __future__ import annotations

import json
import os
import re
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
    _REASON = (
        f"re_workbench_server.server could not be imported ({_IMPORT_ERROR}); "
        "the 14 tool tests below did NOT run. Install the project's "
        "dependencies and use: "
        "uv run --directory mcp python -m unittest discover -s tests"
    )
    if os.environ.get("RE_WORKBENCH_REQUIRE_SERVER_TESTS", "").strip():
        raise SystemExit("RE_WORKBENCH_REQUIRE_SERVER_TESTS is set: " + _REASON)
    print("\n" + "!" * 72, file=sys.stderr)
    print("SKIPPING THE RANKING TOOL TESTS: " + _REASON, file=sys.stderr)
    print("!" * 72 + "\n", file=sys.stderr)
else:
    _REASON = ""

requires_server_module = unittest.skipIf(server is None, _REASON or "server missing")

#: Keys and values that would amount to the tool returning a judgement. The
#: tools legitimately use some of these words in prose (the caveats say the
#: output carries "no verdict"), so the guard looks at field NAMES and at the
#: per-item values, never at the whole blob of text.
VERDICT_WORDS = (
    "verdict",
    "suspicious",
    "malicious",
    "benign",
    "clean",
    "flagged",
    "important",
    "threshold",
)


def all_keys(obj) -> list[str]:
    """Every dict key anywhere in a nested structure."""
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            found.append(str(key))
            found.extend(all_keys(value))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(all_keys(value))
    return found

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

    def test_output_carries_the_caveats(self):
        out = self.rank()
        joined = " ".join(out["caveats"]).lower()
        self.assertIn("low score is not a negative answer", joined)
        self.assertEqual(out["template_version"], decisions.EVIDENCE_TEMPLATE_VERSION)

    def test_no_field_in_the_output_is_a_verdict(self):
        """`assertNotIn(word, some_dict)` tests KEYS, which made the old
        version of this test unable to fail: the real output contains the word
        "verdict" in its caveats and passed anyway, and a field literally named
        `triage_verdict_label` would have passed too."""
        out = self.rank()
        for key in all_keys(out):
            for word in VERDICT_WORDS:
                with self.subTest(key=key, word=word):
                    self.assertNotIn(word, key.lower())

    def test_no_item_carries_a_verdict_value(self):
        out = self.rank()
        for item in out["strings"]:
            for key, value in item.items():
                if isinstance(value, str):
                    with self.subTest(key=key):
                        self.assertNotIn(value.strip().lower(), VERDICT_WORDS)

    def test_the_verdict_guard_can_actually_fail(self):
        """A guard that cannot fail is not a guard. This proves it bites."""
        poisoned = dict(self.rank())
        poisoned["triage_verdict_label"] = "suspicious"
        with self.assertRaises(AssertionError):
            for key in all_keys(poisoned):
                for word in VERDICT_WORDS:
                    self.assertNotIn(word, key.lower())


@requires_server_module
class TestRankStringsReportsWhatItLookedAt(unittest.TestCase):
    """The counts in the envelope must not overstate what was examined."""

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
        previous = os.environ.pop("RE_WORKBENCH_DECISION_URL", None)
        try:
            return json.loads(server.rank_strings(str(self.path), **kwargs))
        finally:
            if previous is not None:
                os.environ["RE_WORKBENCH_DECISION_URL"] = previous

    def test_extraction_parameters_are_reported(self):
        out = self.rank()
        self.assertEqual(out["min_len"], 5)
        self.assertIn("extract_limit", out)
        self.assertFalse(out["strings_truncated"])
        self.assertEqual(out["strings_examined"], out["strings_extracted"])

    def test_a_custom_pattern_keeps_the_class_fields_meaningful(self):
        """Forcing matched_classes to [] turned fallback_rank_key into plain
        string length, which the docstring never claimed and which collapsed
        the first two keys of the deterministic sort into one value."""
        out = self.rank(pattern="admin|BEGIN")
        self.assertEqual(len(out["strings"]), 2)
        self.assertIsNotNone(out["pattern_classes"])
        for item in out["strings"]:
            self.assertTrue(item["matched_classes"])
            self.assertEqual(item["fallback_rank_key"], len(item["matched_classes"]))
            self.assertNotEqual(item["fallback_rank_key"], len(item["string"]))

    def test_the_default_pattern_set_still_classifies(self):
        out = self.rank()
        keyed = {item["string"]: item for item in out["strings"]}
        self.assertIn("key_material", keyed["-----BEGIN RSA PRIVATE KEY-----"]["matched_classes"])


@requires_server_module
class TestDryRunAnnouncesTheCostFirst(unittest.TestCase):
    """The design rule is that the cost is known BEFORE the batch runs."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls._tmp.name) / "sample.bin"
        cls.path.write_bytes(SAMPLE)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def dry(self, **kwargs):
        previous = os.environ.pop("RE_WORKBENCH_DECISION_URL", None)
        try:
            return json.loads(
                server.rank_strings(
                    str(self.path), "Does this string contain a credential?",
                    dry_run=True, **kwargs
                )
            )
        finally:
            if previous is not None:
                os.environ["RE_WORKBENCH_DECISION_URL"] = previous

    def test_a_dry_run_reports_the_estimate_and_the_whole_list(self):
        out = self.dry()
        self.assertEqual(out["status"], "dry_run")
        self.assertGreater(out["estimated_seconds"], 0)
        self.assertEqual(out["requests_planned"], len(out["strings"]))
        self.assertEqual(out["candidates_selected"], out["prefilter_matched"])
        self.assertIn("no request was sent", out["note"])

    def test_a_dry_run_scores_nothing(self):
        out = self.dry()
        for item in out["strings"]:
            self.assertNotIn("score", item)
        self.assertNotIn("usage", out)
        self.assertNotIn("scored", out)

    def test_a_dry_run_sends_no_request_at_all(self):
        """Not even a probe: a pre-flight that costs a round trip to report
        what a round trip costs defeats its own purpose."""
        import ast
        import inspect
        import textwrap

        tree = ast.parse(textwrap.dedent(inspect.getsource(server._dry_run)))
        code = ast.unparse(tree)
        self.assertNotIn("probe", code.split('"""')[-1])
        self.assertIn("sends no request", json.dumps(self.dry()["decision_server"]))

    def test_a_dry_run_still_orders_deterministically(self):
        first = [item["string"] for item in self.dry()["strings"]]
        self.assertEqual(first, [item["string"] for item in self.dry()["strings"]])
        self.assertEqual(
            [item["rank"] for item in self.dry()["strings"]],
            list(range(1, len(first) + 1)),
        )

    def test_no_cost_is_claimed_for_a_run_that_sent_nothing(self):
        """status=unavailable with zero requests used to still print an
        `estimated_seconds_before_run`, i.e. a cost that was never paid."""
        previous = os.environ.pop("RE_WORKBENCH_DECISION_URL", None)
        try:
            out = json.loads(server.rank_strings(str(self.path), "q"))
        finally:
            if previous is not None:
                os.environ["RE_WORKBENCH_DECISION_URL"] = previous
        self.assertEqual(out["status"], "unavailable")
        self.assertNotIn("estimated_seconds_before_run", out)
        self.assertNotIn("estimated_seconds_for_this_batch", out)

    def test_both_ranking_tools_take_dry_run(self):
        import inspect

        for name in ("rank_functions", "rank_strings"):
            with self.subTest(tool=name):
                self.assertIn(
                    "dry_run", inspect.signature(getattr(server, name)).parameters
                )


@requires_server_module
class TestUnscoredItemsAreNotRankedLast(unittest.TestCase):
    """An item nobody asked about must not read as "the model ranked it last"."""

    def test_unscored_items_get_a_null_rank(self):
        selected = [
            {"deterministic_rank": 1, "score": 0.5},
            {"deterministic_rank": 2, "score": None},
            {"deterministic_rank": 3, "score": 0.4},
        ]
        ranked, unranked = server._apply_ranks(selected, ranked_by_score=True)
        self.assertEqual((ranked, unranked), (2, 1))
        self.assertEqual([item["rank"] for item in selected], [1, None, 2])
        self.assertIn("never asked about", selected[1]["rank_note"])

    def test_the_deterministic_fallback_still_numbers_every_item(self):
        selected = [{"deterministic_rank": i, "score": None} for i in (1, 2, 3)]
        ranked, unranked = server._apply_ranks(selected, ranked_by_score=False)
        self.assertEqual((ranked, unranked), (3, 0))
        self.assertEqual([item["rank"] for item in selected], [1, 2, 3])


@requires_server_module
class TestOutputIsStrictJson(unittest.TestCase):
    """One non-finite float used to make the whole tool result unparseable."""

    def test_non_finite_floats_never_reach_the_output(self):
        text = server._j({"a": float("nan"), "b": [1.0, float("inf")], "c": {"d": -float("inf")}})
        self.assertNotIn("NaN", text)
        self.assertNotIn("Infinity", text)
        reparsed = json.loads(
            text,
            parse_constant=lambda name: self.fail(f"bare {name} in the output"),
        )
        self.assertIsNone(reparsed["a"])
        self.assertEqual(reparsed["b"], [1.0, None])
        self.assertIsNone(reparsed["c"]["d"])

    def test_a_score_that_is_not_a_number_sorts_after_the_real_ones(self):
        candidates = [
            {"deterministic_rank": 1, "score": float("nan")},
            {"deterministic_rank": 2, "score": 0.2},
            {"deterministic_rank": 3, "score": True},
            {"deterministic_rank": 4, "score": 0.8},
            {"deterministic_rank": 5, "score": None},
        ]
        candidates.sort(key=server._score_sort_key)
        self.assertEqual([c["deterministic_rank"] for c in candidates[:2]], [4, 2])
        self.assertEqual(
            sorted(c["deterministic_rank"] for c in candidates[2:]), [1, 3, 5]
        )


@requires_server_module
class TestEnrichmentFailuresAreNotHidden(unittest.TestCase):
    """`except Exception: return []` renders as "imported calls: none".

    A reader cannot tell that apart from a function that genuinely calls
    nothing, so if the Ghidra call shape is wrong every item gets the same
    empty evidence and the whole ordering is meaningless with nothing in the
    output saying so. These run without a JVM by faking the two API objects.
    """

    class Exploding:
        def getCalledFunctions(self, monitor):
            raise RuntimeError("monitor is required")

        def getBody(self):
            return object()

    class ExplodingProgram:
        def getListing(self):
            raise RuntimeError("no listing")

    def test_imported_calls_raises_instead_of_returning_empty(self):
        with self.assertRaises(RuntimeError):
            server._imported_calls(self.Exploding())

    def test_function_strings_raises_instead_of_returning_empty(self):
        with self.assertRaises(RuntimeError):
            server._function_strings(self.ExplodingProgram(), self.Exploding(), 4)

    def test_a_callee_that_cannot_be_inspected_is_skipped_not_fatal(self):
        class Callee:
            def __init__(self, name, ok):
                self._name, self._ok = name, ok

            def isExternal(self):
                if not self._ok:
                    raise RuntimeError("stale handle")
                return True

            def isThunk(self):
                return False

            def getName(self):
                return self._name

        class Caller:
            def getCalledFunctions(self, monitor):
                return [Callee("memcpy", True), Callee("broken", False)]

        self.assertEqual(server._imported_calls(Caller()), ["memcpy"])

    def test_function_strings_reads_instructions_not_every_byte(self):
        """Walking body.getAddresses(True) is one JVM round-trip per BYTE."""
        import ast
        import inspect
        import textwrap

        def code_of(func):
            """The function's source with its docstring removed."""
            tree = ast.parse(textwrap.dedent(inspect.getsource(func))).body[0]
            if ast.get_docstring(tree):
                tree.body = tree.body[1:]
            return ast.unparse(tree)

        self.assertIn("getInstructions", code_of(server._function_strings))
        for func in (server._function_strings, server.decompile):
            with self.subTest(func=func.__name__):
                self.assertNotIn("getAddresses", code_of(func))

    def test_rank_functions_reports_enrichment_failures(self):
        import inspect

        source = inspect.getsource(server.rank_functions)
        self.assertIn("enrichment_failed", source)
        self.assertIn("enrichment_warning", source)


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
                self.assertIn("dry_run", doc)

    def test_rank_functions_does_not_claim_selection_keeps_everything(self):
        """`limit=50` on a 3000-function binary leaves 2950 out of the output,
        so "every candidate is returned, nothing is filtered out" as the first
        sentence produced exactly the wrong idea."""
        doc = re.sub(r"\s+", " ", server.rank_functions.__doc__ or "")
        first = doc.split(". ")[0].lower()
        self.assertNotIn("nothing is filtered out", first)
        self.assertIn("functions_total", doc)
        self.assertIn("does NOT mean unimportant", doc)

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
