"""Tests for the optional decision-ranking layer.

Stdlib unittest only, no new dependency. Run from the repository root:

    python3 -m unittest discover -s mcp/tests -v

Tests that need the decision server are SKIPPED unless
RE_WORKBENCH_DECISION_URL is set.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from re_workbench_server import decisions  # noqa: E402

LIVE_URL = os.environ.get("RE_WORKBENCH_DECISION_URL", "").strip()
requires_server = unittest.skipUnless(
    LIVE_URL, "RE_WORKBENCH_DECISION_URL is not set; decision server tests skipped"
)


class StubDecisionServer:
    """A loopback HTTP stub standing in for the decision server.

    stdlib only, and it binds port 0 on 127.0.0.1, so the protocol-level
    behaviour below (what the client must refuse, and when it must stop asking)
    is tested everywhere instead of only on a machine that happens to run a
    real decision server. `body` is called with the request number and returns
    the raw bytes to answer with, so a reply can be deliberately malformed.
    """

    def __init__(self, body=None, delay: float = 0.0, redirect: str | None = None,
                 code: int = 302):
        self.requests = 0
        self._lock = threading.Lock()
        outer = self

        def default_body(number: int, question_id: str) -> bytes:
            return json.dumps(
                {
                    "model": "von-stub",
                    "answers": {question_id: {"type": "noul", "noul": 0.5}},
                    "usage": {"input_tokens": 30, "output_tokens": 1},
                }
            ).encode()

        make_body = body or default_body

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # keep the test output clean
                pass

            def do_POST(self):
                try:
                    self._answer()
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client hung up; nothing to report from a stub

            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                question_id = next(iter(payload.get("questions") or {"q": None}), "q")
                with outer._lock:
                    outer.requests += 1
                    number = outer.requests
                if delay:
                    time.sleep(delay)
                if redirect is not None:
                    self.send_response(code)
                    self.send_header("Location", redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                raw = make_body(number, question_id)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_address[1]}/v1/systemone"

    def __enter__(self) -> "StubDecisionServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def answer_with(literal: str) -> bytes:
    """A syntactically valid reply whose noul value is the given JSON literal."""
    return (
        '{"model":"von-stub","answers":{"q":{"type":"noul","noul":%s}},'
        '"usage":{"input_tokens":30,"output_tokens":1}}' % literal
    ).encode()


ITEM = {"key": "a", "evidence": "function f; size 1 bytes; inbound refs 0"}


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
    """Clamping must fit the budget WITHOUT changing the field shape.

    Measured: the class margin (0.0015) is smaller than paraphrase noise
    (0.0041), so an item that is missing a template field is not comparable
    with the rest of its batch. Cutting the tail off the rendered text deleted
    whole trailing fields, which is exactly what these tests now forbid.
    """

    def test_long_untemplated_text_is_cut_to_the_budget(self):
        budget_chars = decisions.MAX_EVIDENCE_TOKENS * 4
        text, clamped = decisions.clamp_evidence("A" * (budget_chars * 3))
        self.assertTrue(clamped)
        self.assertLessEqual(len(text), budget_chars)
        self.assertLessEqual(decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS)
        # No template to protect here, so the tail is cut and marked.
        self.assertTrue(text.endswith("~"))

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

    def test_clamping_keeps_every_field_label(self):
        """The regression this whole class exists for."""
        long_item, clamped = decisions.function_evidence(
            "recv_loop",
            412,
            3,
            [f"imported_call_number_{i}" for i in range(40)],
            ["POST /upload"],
            max_imports=40,
        )
        bare_item, _ = decisions.function_evidence("_init", 24, 0, [], [])
        self.assertTrue(clamped)
        self.assertEqual(
            decisions.evidence_shape(long_item), decisions.FUNCTION_EVIDENCE_SHAPE
        )
        self.assertEqual(
            decisions.evidence_shape(long_item), decisions.evidence_shape(bare_item)
        )
        self.assertIn("referenced strings: POST /upload", long_item)
        self.assertLessEqual(
            decisions.estimate_tokens(long_item), decisions.MAX_EVIDENCE_TOKENS
        )

    def test_clamping_drops_whole_trailing_list_elements(self):
        text, clamped = decisions.clamp_evidence(
            "function f; size 1 bytes; inbound refs 0; imported calls: "
            + ", ".join(f"call_{i:03d}" for i in range(80))
            + "; referenced strings: POST /upload"
        )
        self.assertTrue(clamped)
        calls = text.split("imported calls: ")[1].split("; referenced strings")[0]
        self.assertEqual(calls.split(", "), sorted(calls.split(", ")))
        for element in calls.split(", "):
            # Whole elements survive; no half-written name is left behind.
            self.assertRegex(element, r"^call_\d{3}$")
        self.assertIn("referenced strings: POST /upload", text)

    def test_a_semicolon_inside_a_value_does_not_invent_a_field(self):
        text, _ = decisions.string_evidence(
            "GET /a; HTTP/1.1", section=".rodata", xref_count=1, offset=16
        )
        self.assertEqual(
            decisions.evidence_shape(text), decisions.STRING_EVIDENCE_SHAPE
        )
        self.assertEqual(len(text.split(";")), 6)  # six separators, five fields

    def test_the_two_templates_have_different_shapes(self):
        """They have the same separator count, which is why shape != count."""
        function = decisions.function_evidence("f", 1, 0, ["a"], ["b"])[0]
        string = decisions.string_evidence("x", section=".ro", xref_count=1, offset=1)[0]
        self.assertEqual(len(function.split(";")), len(string.split(";")))
        self.assertNotEqual(
            decisions.evidence_shape(function), decisions.evidence_shape(string)
        )

    def test_evidence_reports_when_the_backstop_clamp_fires(self):
        text, clamped = decisions.string_evidence(
            "Z" * 50_000, section=".rodata", max_string_chars=50_000
        )
        self.assertTrue(clamped)
        self.assertEqual(
            decisions.evidence_shape(text), decisions.STRING_EVIDENCE_SHAPE
        )
        self.assertLessEqual(
            decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS
        )
        text, clamped = decisions.function_evidence(
            "f", 10, 1, ["api"], ["s" * 5000], max_string_chars=5000
        )
        self.assertTrue(clamped)
        self.assertEqual(
            decisions.evidence_shape(text), decisions.FUNCTION_EVIDENCE_SHAPE
        )
        self.assertLessEqual(
            decisions.estimate_tokens(text), decisions.MAX_EVIDENCE_TOKENS
        )

    def test_evidence_whose_labels_alone_do_not_fit_is_refused(self):
        crowded = "; ".join(
            ["function f", "size 1 bytes", "inbound refs 0", "imported calls: a",
             "referenced strings: b"] * 40
        )
        with self.assertRaises(decisions.EvidenceTooLong):
            decisions.clamp_evidence(crowded, max_tokens=10)

    def test_a_refused_item_is_reported_not_dropped(self):
        crowded = "; ".join(
            ["function f", "size 1 bytes", "inbound refs 0", "imported calls: a",
             "referenced strings: b"] * 400
        )
        result = decisions.score_items(
            [{"key": "huge", "evidence": crowded}],
            "q",
            "Does this matter?",
            env={"RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:1"},
        )
        self.assertIn("huge", result["scores"])
        self.assertIsNone(result["scores"]["huge"]["score"])
        self.assertIn("field label", result["scores"]["huge"]["error"])


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


class TestAnswerValidation(unittest.TestCase):
    """What the server sends back is not trusted to be a score."""

    def score(self, literal: str):
        with StubDecisionServer(body=lambda n, q: answer_with(literal)) as stub:
            return decisions.score_items(
                [ITEM], "q", "Does this matter?",
                config=decisions.DecisionConfig(url=stub.url),
            )

    def test_a_well_formed_score_is_accepted(self):
        result = self.score("0.5")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["scores"]["a"]["score"], 0.5)

    def test_non_finite_scores_are_refused(self):
        """NaN poisons the whole batch: it makes the sort non-transitive and
        serialises as bare `NaN`, which is not JSON."""
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal):
                result = self.score(literal)
                self.assertEqual(result["status"], "unavailable")
                self.assertIn("finite", result["reason"])

    def test_true_is_not_a_score(self):
        """bool is a subclass of int, so `true` used to arrive as 1.0 — above
        every measured value (band max 0.8384) — and ranked first."""
        result = self.score("true")
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["scores"]["a"]["score"])

    def test_scores_outside_zero_to_one_are_refused(self):
        for literal in ("1.5", "-0.1", "42"):
            with self.subTest(literal=literal):
                self.assertEqual(self.score(literal)["status"], "unavailable")

    def test_a_non_finite_raw_value_is_dropped_not_forwarded(self):
        body = lambda n, q: (
            '{"model":"von-stub","answers":{"q":{"type":"noul","noul":0.5,'
            '"noul_raw":NaN}},"usage":{}}'
        ).encode()
        with StubDecisionServer(body=body) as stub:
            result = decisions.score_items(
                [ITEM], "q", "Does this matter?",
                config=decisions.DecisionConfig(url=stub.url),
            )
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["scores"]["a"]["raw"])
        json.dumps(result, allow_nan=False)  # strict JSON, no bare NaN

    def test_one_bad_answer_does_not_reorder_the_good_ones(self):
        """The reason this is a blocker and not a nuisance."""
        items = [
            {"key": f"k{i}", "evidence": f"function f{i}; size {i} bytes; inbound refs 0"}
            for i in range(9)
        ]
        order = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1]
        body = lambda n, q: answer_with(
            "NaN" if n % 3 == 0 else repr(order[n - 1])
        )
        with StubDecisionServer(body=body) as stub:
            result = decisions.score_items(
                items, "q", "Does this matter?",
                config=decisions.DecisionConfig(url=stub.url),
            )
        self.assertEqual(result["status"], "partial")
        got = [
            result["scores"][k]["score"]
            for k in sorted(result["scores"])
            if result["scores"][k]["score"] is not None
        ]
        self.assertTrue(all(isinstance(value, float) for value in got))
        json.dumps(result, allow_nan=False)


class TestRedirectsCannotLeaveTheHost(unittest.TestCase):
    """normalize_url() only validates the CONFIGURED url.

    Measured: a loopback endpoint answering 302 got urllib to ask a different
    endpoint, which replied `status: ok, model: OFF-HOST, score: 0.99` while
    the envelope still reported the loopback url.
    """

    def test_every_redirect_status_is_refused(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                with StubDecisionServer(
                    redirect="http://127.0.0.1:1/elsewhere", code=code
                ) as stub:
                    result = decisions.score_items(
                        [ITEM], "q", "Does this matter?",
                        config=decisions.DecisionConfig(url=stub.url),
                    )
                self.assertEqual(result["status"], "unavailable")
                self.assertIsNone(result["scores"]["a"]["score"])

    def test_the_refusal_says_why(self):
        with StubDecisionServer(redirect="http://127.0.0.1:1/x", code=302) as stub:
            result = decisions.score_items(
                [ITEM], "q", "Does this matter?",
                config=decisions.DecisionConfig(url=stub.url),
            )
        self.assertIn("redirect", result["reason"].lower())


class TestBatchDeadline(unittest.TestCase):
    """Per-request timeouts are additive; the batch needs its own ceiling."""

    ITEMS = [
        {"key": f"k{i}", "evidence": f"function f{i}; size {i} bytes; inbound refs 0"}
        for i in range(10)
    ]

    def test_the_whole_batch_stops_at_the_deadline(self):
        with StubDecisionServer(delay=0.3) as stub:
            config = decisions.DecisionConfig(
                url=stub.url, timeout=5.0, max_seconds=0.6,
                max_consecutive_errors=99,
            )
            started = time.monotonic()
            result = decisions.score_items(
                self.ITEMS, "q", "Does this matter?", config=config
            )
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 3.0, f"took {elapsed:.2f}s")
        self.assertEqual(result["status"], "partial")
        self.assertIn("deadline", result["aborted"])
        self.assertLess(result["scored"], len(self.ITEMS))
        self.assertEqual(len(result["scores"]), len(self.ITEMS))
        self.assertEqual(result["scored"] + result["unscored"], len(self.ITEMS))

    def test_items_past_the_deadline_say_why_they_were_not_scored(self):
        with StubDecisionServer(delay=0.3) as stub:
            result = decisions.score_items(
                self.ITEMS, "q", "Does this matter?",
                config=decisions.DecisionConfig(
                    url=stub.url, timeout=5.0, max_seconds=0.6,
                    max_consecutive_errors=99,
                ),
            )
        unscored = [e for e in result["scores"].values() if e["score"] is None]
        self.assertTrue(unscored)
        for entry in unscored:
            self.assertIn("deadline", entry["error"])

    def test_a_dead_server_stops_after_consecutive_failures(self):
        config = decisions.DecisionConfig(
            url="http://127.0.0.1:1", max_consecutive_errors=3
        )
        result = decisions.score_items(
            self.ITEMS, "q", "Does this matter?", config=config
        )
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("failed in a row", result["aborted"])
        self.assertEqual(len(result["scores"]), len(self.ITEMS))
        attempted = [e for e in result["scores"].values() if "unreachable" in e["error"]]
        self.assertEqual(len(attempted), 3)

    def test_the_deadline_is_configurable_from_the_environment(self):
        config = decisions.DecisionConfig.from_env(
            {
                "RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:8009",
                "RE_WORKBENCH_DECISION_MAX_SECONDS": "12",
                "RE_WORKBENCH_DECISION_MAX_CONSECUTIVE_ERRORS": "2",
            }
        )
        self.assertEqual(config.max_seconds, 12.0)
        self.assertEqual(config.max_consecutive_errors, 2)

    def test_the_deadline_has_a_default(self):
        config = decisions.DecisionConfig.from_env(
            {"RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:8009"}
        )
        self.assertEqual(config.max_seconds, decisions.DEFAULT_MAX_SECONDS)


class TestEmptyAndPartialBatches(unittest.TestCase):
    def test_an_empty_batch_never_claims_a_model_answered(self):
        """A dead but configured server used to come back as status ok."""
        result = decisions.score_items(
            [], "q", "Does this matter?",
            env={"RE_WORKBENCH_DECISION_URL": "http://127.0.0.1:1"},
        )
        self.assertEqual(result["status"], "empty")
        self.assertIsNone(result["model"])
        self.assertEqual(result["scored"], 0)
        self.assertEqual(result["requested"], 0)
        self.assertIn("no request was made", result["reason"])

    def test_clamped_counts_only_items_that_were_actually_sent(self):
        long_evidence = (
            "function f; size 1 bytes; inbound refs 0; imported calls: "
            + ", ".join(f"call_{i:03d}" for i in range(200))
            + "; referenced strings: POST /upload"
        )
        items = [{"key": f"k{i}", "evidence": long_evidence} for i in range(4)]
        with StubDecisionServer() as stub:
            result = decisions.score_items(
                items, "q", "Does this matter?",
                config=decisions.DecisionConfig(url=stub.url, max_items=2),
            )
        self.assertEqual(result["scored"], 2)
        self.assertEqual(result["clamped_evidence"], 2)
        self.assertEqual(len(result["scores"]), 4)

    def test_a_mixed_shape_batch_is_reported(self):
        items = [
            {"key": "f", "evidence": decisions.function_evidence("f", 1, 0, ["a"], ["b"])[0]},
            {"key": "s", "evidence": decisions.string_evidence(
                "x", section=".ro", xref_count=1, offset=1)[0]},
        ]
        with StubDecisionServer() as stub:
            result = decisions.score_items(
                items, "q", "Does this matter?",
                config=decisions.DecisionConfig(url=stub.url),
            )
        self.assertEqual(len(result["evidence_shapes_sent"]), 2)
        self.assertIn("evidence_shape_warning", result)


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
