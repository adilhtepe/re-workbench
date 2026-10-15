"""Tests for eval/calibrate.py.

The calibration runner is the one component that forces the user to measure a
ranking question against their own data instead of trusting it, so a runner
that measures the wrong thing is worse than no runner at all. Everything here
is a regression test for a way it used to measure wrong.

Stdlib unittest only. Run from the repository root:

    python3 -m unittest discover -s mcp/tests -v
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "mcp" / "src"))

from re_workbench_server import decisions  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "re_workbench_calibrate", ROOT / "eval" / "calibrate.py"
)
calibrate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(calibrate)


def write_jsonl(directory: Path, name: str, rows: list[dict]) -> Path:
    path = directory / name
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


FUNCTION_ROW = decisions.function_evidence(
    "recv_loop", 412, 3, ["recv", "memcpy"], ["POST /upload"]
)[0]
BARE_ROW = decisions.function_evidence("_init", 24, 0, [], [])[0]
STRING_ROW = decisions.string_evidence(
    "admin:hunter2", section=".rodata", xref_count=3, offset=4096
)[0]


class TestRowsAreMatchedToTheirOwnScore(unittest.TestCase):
    """Two rows with the same "key" used to silently overwrite each other.

    Measured on a live server with a two-line file both keyed "same" (one true
    positive, one true negative): both rows were assigned 0.1878, the real
    0.819 of the positive was discarded, AUC came out 0.500 instead of 1.000
    and the verdict read "no - this question does not separate your data".
    """

    def test_every_row_gets_a_unique_score_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(
                Path(tmp),
                "dup.jsonl",
                [
                    {"key": "same", "label": 1, "evidence": FUNCTION_ROW},
                    {"key": "same", "label": 0, "evidence": BARE_ROW},
                ],
            )
            rows = calibrate.load_jsonl(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row["score_key"] for row in rows}), 2)
        self.assertEqual([row["key"] for row in rows], ["same", "same"])

    def test_repeated_display_keys_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(
                Path(tmp),
                "dup.jsonl",
                [
                    {"key": "same", "label": 1, "evidence": FUNCTION_ROW},
                    {"key": "same", "label": 0, "evidence": BARE_ROW},
                    {"key": "other", "label": 0, "evidence": BARE_ROW},
                ],
            )
            rows = calibrate.load_jsonl(path)
        self.assertEqual(calibrate.duplicate_keys(rows), {"same": [1, 2]})

    def test_rows_without_a_key_are_still_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(
                Path(tmp),
                "nokey.jsonl",
                [{"label": 1, "evidence": FUNCTION_ROW}, {"label": 0, "evidence": BARE_ROW}],
            )
            rows = calibrate.load_jsonl(path)
        self.assertEqual(len({row["score_key"] for row in rows}), 2)


class TestVerdictWithholdsJudgementOnSmallSamples(unittest.TestCase):
    """n < 30 used to be a note under a green "yes".

    The README's own first example command runs a ten-line hand-written fixture
    that the README itself says proves nothing, and it printed
    "DISCRIMINATES? yes, for ordering only".
    """

    STRONG_POS = [0.83, 0.81, 0.79, 0.77, 0.75]
    STRONG_NEG = [0.30, 0.28, 0.26, 0.24, 0.22]

    def test_a_strong_result_on_ten_items_is_unknown_not_yes(self):
        auc = calibrate.roc_auc(self.STRONG_POS, self.STRONG_NEG)
        result = calibrate.verdict(auc, self.STRONG_POS, self.STRONG_NEG, overlap=False)
        self.assertEqual(auc, 1.0)
        self.assertTrue(result["discriminates"].startswith("unknown"))
        self.assertIn("too few labelled items", result["discriminates"])

    def test_the_auc_is_still_reported(self):
        result = calibrate.verdict(
            calibrate.roc_auc(self.STRONG_POS, self.STRONG_NEG),
            self.STRONG_POS,
            self.STRONG_NEG,
            overlap=False,
        )
        self.assertEqual(result["auc"], 1.0)
        self.assertEqual(result["labelled_items"], 10)
        self.assertIn("1.000", result["reason"])

    def test_enough_items_do_get_a_verdict(self):
        pos = [0.80 - i * 0.001 for i in range(20)]
        neg = [0.30 - i * 0.001 for i in range(20)]
        result = calibrate.verdict(calibrate.roc_auc(pos, neg), pos, neg, overlap=False)
        self.assertEqual(result["discriminates"], "yes, for ordering only")
        self.assertEqual(result["labelled_items"], 40)

    def test_a_near_chance_result_is_still_a_no_when_there_is_enough_data(self):
        pos = [0.50 + (i % 2) * 0.001 for i in range(20)]
        neg = [0.50 + (i % 2) * 0.001 for i in range(20)]
        result = calibrate.verdict(calibrate.roc_auc(pos, neg), pos, neg, overlap=True)
        self.assertEqual(result["discriminates"], "no")


class TestShapeGuardComparesLabelsNotSeparators(unittest.TestCase):
    """`len(evidence.split(";"))` was wrong in both directions."""

    def test_the_two_templates_are_not_confused(self):
        """False negative: both templates have exactly five separators."""
        self.assertEqual(len(FUNCTION_ROW.split(";")), len(STRING_ROW.split(";")))
        self.assertNotEqual(
            decisions.evidence_shape(FUNCTION_ROW), decisions.evidence_shape(STRING_ROW)
        )

    def test_a_semicolon_in_a_value_is_not_a_new_shape(self):
        """False positive: a ";" inside a referenced string."""
        with_semicolon = decisions.string_evidence(
            "GET /a; HTTP/1.1", section=".rodata", xref_count=1, offset=16
        )[0]
        without = decisions.string_evidence(
            "GET /b HTTP/1.1", section=".rodata", xref_count=1, offset=32
        )[0]
        self.assertNotEqual(len(with_semicolon.split(";")), len(without.split(";")))
        self.assertEqual(
            decisions.evidence_shape(with_semicolon), decisions.evidence_shape(without)
        )

    def test_untemplated_evidence_has_no_shape(self):
        self.assertEqual(decisions.evidence_shape("some prose a model wrote"), ())


class TestTopKAndTies(unittest.TestCase):
    def test_top_k_recall_counts_the_whole_ranking(self):
        self.assertEqual(calibrate.top_k_recall([1, 0, 1, 0], 2), 0.5)
        self.assertEqual(calibrate.top_k_recall([1, 0, 1, 0], 4), 1.0)
        self.assertIsNone(calibrate.top_k_recall([0, 0], 2))

    def test_ties_are_broken_by_key_not_by_input_order(self):
        rows = [
            {"score": 0.1896, "score_key": "row1", "label": 0},
            {"score": 0.1896, "score_key": "row0", "label": 1},
        ]
        forward = sorted(rows, key=lambda r: (-r["score"], r["score_key"]))
        backward = sorted(rows[::-1], key=lambda r: (-r["score"], r["score_key"]))
        self.assertEqual(
            [r["score_key"] for r in forward], [r["score_key"] for r in backward]
        )
        self.assertEqual([r["score_key"] for r in forward], ["row0", "row1"])


class TestLoadJsonlRejectsBadInput(unittest.TestCase):
    def test_a_bad_label_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(
                Path(tmp), "bad.jsonl", [{"label": 2, "evidence": BARE_ROW}]
            )
            with self.assertRaises(SystemExit):
                calibrate.load_jsonl(path)

    def test_empty_evidence_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(Path(tmp), "bad.jsonl", [{"label": 1, "evidence": "  "}])
            with self.assertRaises(SystemExit):
                calibrate.load_jsonl(path)

    def test_comment_and_unlabelled_rows_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(
                Path(tmp),
                "mixed.jsonl",
                [
                    {"_comment": "notes"},
                    {"evidence": BARE_ROW},
                    {"label": 1, "evidence": BARE_ROW},
                ],
            )
            self.assertEqual(len(calibrate.load_jsonl(path)), 1)


if __name__ == "__main__":
    unittest.main()
