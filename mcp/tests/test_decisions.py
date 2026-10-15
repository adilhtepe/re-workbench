"""Tests for the optional decision-ranking layer.

Stdlib unittest only, no new dependency. Run from the repository root:

    python3 -m unittest discover -s mcp/tests -v

Tests that need the decision server are SKIPPED unless
RE_WORKBENCH_DECISION_URL is set.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from re_workbench_server import decisions  # noqa: E402

LIVE_URL = os.environ.get("RE_WORKBENCH_DECISION_URL", "").strip()
requires_server = unittest.skipUnless(
    LIVE_URL, "RE_WORKBENCH_DECISION_URL is not set; decision server tests skipped"
)


class TestEvidenceDeterminism(unittest.TestCase):
    """The same facts must always render to the same bytes.

    Measured: the class margin (0.0015) is smaller than the spread introduced
    by rewording the same facts (0.0041), so any variation in the text makes
    two items incomparable.
    """

    FACTS = dict(
        name="FUN_00401abc",
        size=96,
        xref_count=14,
        imported_calls=["memcpy", "malloc"],
        referenced_strings=["/tmp/%s.cfg", "POST /upload"],
    )

    def test_function_evidence_is_stable_across_calls(self):
        renders = {decisions.function_evidence(**self.FACTS)[0] for _ in range(10)}
        self.assertEqual(len(renders), 1, renders)

    def test_function_evidence_is_order_independent_in_facts_only(self):
        a, _ = decisions.function_evidence(**self.FACTS)
        b, _ = decisions.function_evidence(
            name=self.FACTS["name"],
            size=self.FACTS["size"],
            xref_count=self.FACTS["xref_count"],
            imported_calls=list(self.FACTS["imported_calls"]),
            referenced_strings=list(self.FACTS["referenced_strings"]),
        )
        self.assertEqual(a, b)

    def test_every_item_has_the_same_field_shape(self):
        rich, _ = decisions.function_evidence(**self.FACTS)
        bare, _ = decisions.function_evidence("_init", 24, 0, [], [])
        self.assertEqual(
            [part.split(" ")[0] for part in rich.split("; ")],
            [part.split(" ")[0] for part in bare.split("; ")],
        )
        self.assertIn("imported calls: none", bare)
        self.assertIn("referenced strings: none", bare)

    def test_whitespace_in_facts_cannot_change_the_shape(self):
        a, _ = decisions.function_evidence("name", 1, 0, ["a\nb"], ["x  y"])
        self.assertNotIn("\n", a)
        self.assertIn("a b", a)
        self.assertIn("x y", a)

    def test_string_evidence_is_stable_and_shaped(self):
        args = dict(text="admin:hunter2", section=".rodata", xref_count=3, offset=4096)
        renders = {decisions.string_evidence(**args)[0] for _ in range(10)}
        self.assertEqual(len(renders), 1)
        text = renders.pop()
        self.assertIn('string "admin:hunter2"', text)
        self.assertIn("section .rodata", text)
        self.assertIn("offset 0x1000", text)
        self.assertIn("inbound refs 3", text)

    def test_string_evidence_marks_unknown_fields(self):
        text, _ = decisions.string_evidence("x" * 10)
        self.assertIn("section unknown", text)
        self.assertIn("inbound refs unknown", text)


class TestClamping(unittest.TestCase):
    def test_long_evidence_is_clamped_to_the_budget(self):
        budget_chars = decisions.MAX_EVIDENCE_TOKENS * 4
        text, clamped = decisions.clamp_evidence("A" * (budget_chars * 3))
        self.assertTrue(clamped)
        self.assertLessEqual(len(text), budget_chars)
        self.assertLessEqual(decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS)
        self.assertTrue(text.endswith("[clamped]"))

    def test_short_evidence_is_untouched(self):
        text, clamped = decisions.clamp_evidence("short")
        self.assertFalse(clamped)
        self.assertEqual(text, "short")

    def test_clamping_is_deterministic(self):
        src = "B" * 10_000
        self.assertEqual(
            {decisions.clamp_evidence(src) for _ in range(5)},
            {decisions.clamp_evidence(src)},
        )

    def test_absurd_facts_still_fit_the_budget(self):
        """Per-field caps are the first guard; the clamp is the backstop."""
        text, _ = decisions.function_evidence(
            "f" * 400, 10, 1, [f"api_{i}" * 20 for i in range(40)], ["s" * 500] * 10
        )
        self.assertLessEqual(
            decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS
        )
        text, _ = decisions.string_evidence("Z" * 50_000, section="." + "r" * 400)
        self.assertLessEqual(
            decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS
        )

    def test_evidence_reports_when_the_backstop_clamp_fires(self):
        text, clamped = decisions.string_evidence(
            "Z" * 50_000, section=".rodata", max_string_chars=50_000
        )
        self.assertTrue(clamped)
        self.assertTrue(text.endswith("[clamped]"))
        self.assertLessEqual(
            decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS
        )
        text, clamped = decisions.function_evidence(
            "f", 10, 1, ["api"], ["s" * 5000], max_string_chars=5000
        )
        self.assertTrue(clamped)
        self.assertLessEqual(
            decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS
        )


class TestUrlValidation(unittest.TestCase):
    """Evidence assembled from the user's binaries must not leave the host."""

    def test_loopback_forms_are_accepted(self):
        for raw in (
            "http://127.0.0.1:8009",
            "127.0.0.1:8009",
            "http://localhost:8009/",
            "http://[::1]:8009",
            "https://localhost:8443/v1/systemone",
        ):
            with self.subTest(raw=raw):
                self.assertTrue(decisions.normalize_url(raw).endswith("systemone"))

    def test_default_path_is_appended_once(self):
        self.assertEqual(
            decisions.normalize_url("http://127.0.0.1:8009"),
            "http://127.0.0.1:8009/v1/systemone",
        )
        self.assertEqual(
            decisions.normalize_url("http://127.0.0.1:8009/custom"),
            "http://127.0.0.1:8009/custom",
        )

    def test_non_loopback_is_refused(self):
        for raw in (
            "http://evil.example.com:8009",
            "http://10.0.0.5:8009",
            "https://decision.internal/v1/systemone",
            "http://0.0.0.0:8009",
            "http://127.0.0.1.evil.example.com/",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(decisions.DecisionConfigError):
                    decisions.normalize_url(raw)

    def test_non_http_scheme_is_refused(self):
        with self.assertRaises(decisions.DecisionConfigError):
            decisions.normalize_url("file:///etc/passwd")

    def test_client_revalidates_its_config(self):
        bad = decisions.DecisionConfig(url="http://evil.example.com:8009")
        with self.assertRaises(decisions.DecisionConfigError):
            decisions.SystemOneClient(bad)

    def test_score_items_refuses_non_loopback_without_sending(self):
        result = decisions.score_items(
            [{"key": "a", "evidence": "secret from a customer binary"}],
            "q",
            "Does this matter?",
            env={"RE_WORKBENCH_DECISION_URL": "http://evil.example.com:8009"},
        )
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("loopback", result["reason"])


class TestConfig(unittest.TestCase):
    def test_absent_url_means_off(self):
        self.assertIsNone(decisions.DecisionConfig.from_env({}))
        self.assertIsNone(
            decisions.DecisionConfig.from_env({"RE_WORKBENCH_DECISION_URL": "  "})
        )

    def test_defaults(self):
        cfg = decisions.DecisionConfig.from_env(
            {"RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:8009"}
        )
        self.assertEqual(cfg.model, decisions.DEFAULT_MODEL)
        self.assertEqual(cfg.timeout, decisions.DEFAULT_TIMEOUT)
        self.assertEqual(cfg.max_items, decisions.DEFAULT_MAX_ITEMS)

    def test_overrides(self):
        cfg = decisions.DecisionConfig.from_env(
            {
                "RE_WORKBENCH_DECISION_URL": "http://localhost:9000",
                "RE_WORKBENCH_DECISION_MODEL": "von-9.9",
                "RE_WORKBENCH_DECISION_TIMEOUT": "12.5",
                "RE_WORKBENCH_DECISION_MAX_ITEMS": "7",
            }
        )
        self.assertEqual(cfg.model, "von-9.9")
        self.assertEqual(cfg.timeout, 12.5)
        self.assertEqual(cfg.max_items, 7)

    def test_bad_numbers_are_rejected(self):
        for key, value in (
            ("RE_WORKBENCH_DECISION_TIMEOUT", "soon"),
            ("RE_WORKBENCH_DECISION_TIMEOUT", "-1"),
            ("RE_WORKBENCH_DECISION_MAX_ITEMS", "0"),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaises(decisions.DecisionConfigError):
                    decisions.DecisionConfig.from_env(
                        {"RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:8009", key: value}
                    )


class TestUnavailableKeepsEverything(unittest.TestCase):
    ITEMS = [
        {"key": f"item{i}", "evidence": f"function f{i}; size {i}; inbound refs {i}"}
        for i in range(6)
    ]

    def test_unconfigured_returns_unavailable_not_an_error(self):
        result = decisions.score_items(self.ITEMS, "q", "Does this matter?", env={})
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("RE_WORKBENCH_DECISION_URL", result["reason"])
        self.assertEqual(result["template_version"], decisions.EVIDENCE_TEMPLATE_VERSION)
        self.assertTrue(result["caveats"])

    def test_unreachable_server_keeps_an_entry_for_every_item(self):
        # Port 1 on loopback: nothing listens, so every request fails.
        result = decisions.score_items(
            self.ITEMS,
            "q",
            "Does this matter?",
            env={"RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:1"},
        )
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["scored"], 0)
        self.assertEqual(set(result["scores"]), {i["key"] for i in self.ITEMS})
        for entry in result["scores"].values():
            self.assertIsNone(entry["score"])
            self.assertTrue(entry["error"])

    def test_caveats_state_that_a_low_score_is_not_a_no(self):
        joined = " ".join(decisions.CAVEATS).lower()
        self.assertIn("low score is not a negative answer", joined)
        self.assertIn("no item is dropped", joined)

    def test_unavailable_envelope_has_no_threshold_or_verdict_field(self):
        result = decisions.unavailable("off")
        for forbidden in ("verdict", "threshold", "flagged", "suspicious", "decision"):
            self.assertNotIn(forbidden, result)


class TestPrefilter(unittest.TestCase):
    def test_default_pattern_compiles(self):
        import re

        re.compile(decisions.default_string_pattern())

    def test_default_classes_match_the_obvious_cases(self):
        cases = {
            "http://update.example.com/fw.bin": "url",
            "192.168.1.1": "ipv4",
            "admin:Sup3rSecret": "config_key",
            "wpa_psk=0123456789": "credential",  # \bpsk\b would miss this
            "API-KEY: deadbeef": "credential",
            "-----BEGIN RSA PRIVATE KEY-----": "key_material",
            "/etc/init.d/rcS": "unix_path",
            "/bin/sh -c %s": "command",
            "GET %s HTTP/1.1": "format_string",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertIn(expected, decisions.classify_string(text))

    def test_plain_prose_matches_nothing(self):
        self.assertEqual(
            decisions.classify_string("another harmless sentence about nothing"), []
        )

    def test_classification_is_deterministic(self):
        text = "admin http://x.local/etc/passwd %s"
        first = decisions.classify_string(text)
        for _ in range(5):
            self.assertEqual(decisions.classify_string(text), first)


class TestCostEstimates(unittest.TestCase):
    def test_estimates_are_floored_at_the_measured_per_request_cost(self):
        self.assertGreaterEqual(
            decisions.estimate_latency_seconds(10), decisions.MIN_REQUEST_SECONDS
        )

    def test_estimates_grow_with_state_length(self):
        values = [
            decisions.estimate_latency_seconds(t) for t in (76, 241, 961, 3061, 6000)
        ]
        self.assertEqual(values, sorted(values))

    def test_batch_cost_scales_with_item_count(self):
        per_item = decisions.estimate_latency_seconds(decisions.MAX_EVIDENCE_TOKENS)
        self.assertAlmostEqual(
            decisions.estimate_batch_seconds(50), per_item * 50, places=2
        )
        self.assertEqual(decisions.estimate_batch_seconds(0), 0)


@requires_server
class TestAgainstLiveServer(unittest.TestCase):
    """Runs only when RE_WORKBENCH_DECISION_URL points at a decision server."""

    def test_probe_reports_reachable(self):
        status = decisions.probe()
        self.assertEqual(status["status"], "ok", status)
        self.assertTrue(status["reachable"])

    def test_scores_are_in_range_and_every_item_comes_back(self):
        items = [
            {"key": "a", "evidence": decisions.function_evidence(
                "recv_loop", 412, 3, ["recv", "memcpy"], ["POST /upload"])[0]},
            {"key": "b", "evidence": decisions.function_evidence("_init", 24, 0, [], [])[0]},
        ]
        result = decisions.score_items(
            items, "net", "Does this function read data from the network?"
        )
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(set(result["scores"]), {"a", "b"})
        for entry in result["scores"].values():
            self.assertGreaterEqual(entry["score"], 0.0)
            self.assertLessEqual(entry["score"], 1.0)

    def test_identical_evidence_scores_identically(self):
        evidence = decisions.function_evidence(
            "recv_loop", 412, 3, ["recv", "memcpy"], ["POST /upload"]
        )[0]
        items = [{"key": "first", "evidence": evidence}, {"key": "second", "evidence": evidence}]
        result = decisions.score_items(
            items, "net", "Does this function read data from the network?"
        )
        self.assertEqual(
            result["scores"]["first"]["score"], result["scores"]["second"]["score"]
        )

    def test_max_items_caps_requests_without_dropping_items(self):
        items = [
            {"key": f"k{i}", "evidence": f"function f{i}; size {i}; inbound refs 0"}
            for i in range(4)
        ]
        cfg = decisions.DecisionConfig(
            url=LIVE_URL, model=decisions.DEFAULT_MODEL, max_items=2
        )
        result = decisions.score_items(items, "q", "Is this a function?", config=cfg)
        self.assertEqual(result["scored"], 2)
        self.assertEqual(len(result["scores"]), 4)
        self.assertIsNone(result["scores"]["k3"]["score"])
        self.assertIn("max_items", result["scores"]["k3"]["error"])


if __name__ == "__main__":
    unittest.main()
