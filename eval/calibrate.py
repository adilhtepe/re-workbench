#!/usr/bin/env python3
"""Measure whether one ranking question separates YOUR labelled data.

The ranking tools (`rank_functions`, `rank_strings`) produce an ordering, not a
judgement, and the ordering is only as good as the question behind it. Measured
on this setup, a badly shaped question collapses an 8-function set to a score
spread of 0.0047 — inside paraphrase noise — while a single concrete condition
spreads the same set over 0.63. You cannot tell the two cases apart by reading
the output. You have to measure.

So: label a few dozen items yourself, run this, and only then decide whether
the order is worth anything for your question and your binaries.

Input: JSONL, one object per line, each {"evidence": "...", "label": 0|1}.
Lines carrying a "_comment" key, blank lines and lines without a "label" are
skipped. Build "evidence" with the SAME template the server uses
(re_workbench_server.decisions.function_evidence / string_evidence) — scores
produced from differently worded evidence are not comparable, and the runner
warns when the rows do not all have the same template field labels. An optional
"key" is a label for the report only; rows are matched to their scores by
position, so a repeated key cannot make one row take another's score.

Output: ROC AUC, top-k recall, per-class score ranges, and an explicit verdict
on whether the question discriminates on this data. Below 30 labelled items the
verdict is "unknown": the AUC is still printed, but it is not a result.

Usage:
    RE_WORKBENCH_DECISION_URL=http://127.0.0.1:8009 \\
    python3 eval/calibrate.py eval/example-functions.jsonl \\
        --question "Does this function read data from the network?"
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp" / "src"))

from re_workbench_server import decisions  # noqa: E402

#: Measured spread of the same facts rewritten four ways. A class margin below
#: this is indistinguishable from rewording the evidence.
PARAPHRASE_NOISE = 0.0041

#: Measured class margin of a question that did not work (for comparison).
MEASURED_FAILED_MARGIN = 0.0015

#: Below this many labelled items there is no verdict to give, only an AUC.
MIN_LABELLED_ITEMS = 30


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read the labelled rows, each with a score key that is unique by
    construction.

    The user's "key" is a label for reading the report, nothing else. It used
    to be the dictionary key the scores came back under, and nothing checked it
    for uniqueness: two rows keyed the same silently overwrote each other, so
    one row was reported with the OTHER row's score. Measured on a two-line
    file both keyed "same" (one true positive, one true negative): both rows
    were given 0.1878, AUC came out 0.500 instead of 1.000, and the verdict
    read "no - this question does not separate your data" about a question
    that separated it perfectly.
    """
    rows: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise SystemExit(f"{path}:{lineno}: not valid JSON: {exc}")
        if not isinstance(obj, dict) or "_comment" in obj or "label" not in obj:
            continue
        evidence = str(obj.get("evidence", "")).strip()
        if not evidence:
            raise SystemExit(f"{path}:{lineno}: empty 'evidence'")
        try:
            label = int(obj["label"])
        except (TypeError, ValueError):
            raise SystemExit(f"{path}:{lineno}: 'label' must be 0 or 1")
        if label not in (0, 1):
            raise SystemExit(f"{path}:{lineno}: 'label' must be 0 or 1, got {label}")
        rows.append(
            {
                # score_key is positional and therefore unique; key is for the
                # human reading the report.
                "score_key": f"row{len(rows)}",
                "key": str(obj.get("key") or f"line{lineno}"),
                "evidence": evidence,
                "label": label,
                "line": lineno,
            }
        )
    return rows


def duplicate_keys(rows: Sequence[dict[str, Any]]) -> dict[str, list[int]]:
    """Display keys used by more than one row, with their line numbers."""
    seen: dict[str, list[int]] = {}
    for row in rows:
        seen.setdefault(row["key"], []).append(row["line"])
    return {key: lines for key, lines in seen.items() if len(lines) > 1}


def roc_auc(pos: Sequence[float], neg: Sequence[float]) -> float | None:
    """Rank-based AUC (Mann-Whitney U), ties counted as half."""
    if not pos or not neg:
        return None
    wins = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def top_k_recall(ranked_labels: Sequence[int], k: int) -> float | None:
    total = sum(ranked_labels)
    if not total:
        return None
    return sum(ranked_labels[:k]) / total


def summarize(values: Sequence[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "min": round(min(values), 4),
        "median": round(statistics.median(values), 4),
        "max": round(max(values), 4),
        "mean": round(statistics.fmean(values), 4),
    }


def verdict(
    auc: float | None,
    pos: Sequence[float],
    neg: Sequence[float],
    overlap: bool,
) -> dict[str, Any]:
    """An explicit call on whether this question discriminates on this data."""
    if auc is None:
        return {
            "discriminates": "unknown",
            "reason": "the data needs at least one item of each label",
        }

    margin = statistics.median(pos) - statistics.median(neg)
    n = len(pos) + len(neg)
    notes: list[str] = []

    if n < MIN_LABELLED_ITEMS:
        # This used to be a note under a green "yes", which is the exact shape
        # of false confidence the whole runner exists to prevent: the README's
        # own first example (a ten-line hand-written fixture that proves
        # nothing) printed "DISCRIMINATES? yes, for ordering only".
        return {
            "discriminates": f"unknown - too few labelled items ({n})",
            "reason": (
                f"AUC {auc:.3f} with class margin {margin:+.4f} on {n} labelled "
                f"items. Below {MIN_LABELLED_ITEMS} items an AUC this far from "
                "0.5 happens by chance often enough that it is not a result; "
                "label more data before reading anything into the order."
            ),
            "auc": round(auc, 4),
            "class_margin_median": round(margin, 4),
            "labelled_items": n,
            "notes": notes,
        }

    if abs(margin) < PARAPHRASE_NOISE:
        notes.append(
            f"class margin {margin:+.4f} is inside the measured paraphrase noise "
            f"({PARAPHRASE_NOISE}): indistinguishable from rewording the evidence "
            f"(a question measured as non-working had margin {MEASURED_FAILED_MARGIN})"
        )
    if overlap:
        notes.append(
            "positive and negative score ranges overlap, so no cut-off exists; "
            "use the order, never a threshold"
        )

    if auc < 0.5:
        answer = "no — inverted"
        reason = (
            f"AUC {auc:.3f} is below chance: on this data the question ranks "
            "negatives above positives. Rewrite it or invert its sense."
        )
    elif auc < 0.65:
        answer = "no"
        reason = (
            f"AUC {auc:.3f} is near chance. This question does not separate "
            "your data; the resulting order carries no information."
        )
    elif auc < 0.80 or abs(margin) < PARAPHRASE_NOISE:
        answer = "weakly"
        reason = (
            f"AUC {auc:.3f} with class margin {margin:+.4f}. Usable as a hint "
            "for which item to look at first, and for nothing else."
        )
    else:
        answer = "yes, for ordering only"
        reason = (
            f"AUC {auc:.3f} with class margin {margin:+.4f}: the question ranks "
            "your positives above your negatives on this data. It still returns "
            "no verdict, and a low score still is not a negative answer."
        )
    return {
        "discriminates": answer,
        "reason": reason,
        "class_margin_median": round(margin, 4),
        "labelled_items": n,
        "notes": notes,
    }


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Calibrate one ranking question against labelled evidence."
    )
    ap.add_argument("data", type=Path, help="JSONL file of {evidence, label}")
    ap.add_argument(
        "--question",
        required=True,
        help="ONE concrete condition, exactly as it would be passed to rank_*",
    )
    ap.add_argument("--question-id", default="calibrate")
    ap.add_argument(
        "--top-k",
        default="1,3,5,10",
        help="comma-separated k values for top-k recall (default 1,3,5,10)",
    )
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = ap.parse_args(argv)

    rows = load_jsonl(args.data)
    if not rows:
        print(f"no labelled rows in {args.data}", file=sys.stderr)
        return 2

    # Field LABELS, not ";" counts. Counting separators is wrong in both
    # directions: function and string evidence both split into exactly five, so
    # a file mixing the two templates passed silently, while one ";" inside a
    # referenced string made two identically templated rows look different.
    shapes = sorted({decisions.evidence_shape(r["evidence"]) for r in rows})
    untemplated = [r["line"] for r in rows if not decisions.evidence_shape(r["evidence"])]
    duplicates = duplicate_keys(rows)

    n_pos = sum(r["label"] for r in rows)
    announced = decisions.estimate_batch_seconds(
        len(rows), max(decisions.estimate_tokens(r["evidence"]) for r in rows)
    )
    if not args.json:
        print(
            f"{len(rows)} items ({n_pos} positive, {len(rows) - n_pos} negative), "
            f"one request each, expected ~{announced}s"
        )

    scoring = decisions.score_items(
        [{"key": r["score_key"], "evidence": r["evidence"]} for r in rows],
        args.question_id,
        args.question,
    )
    if scoring.get("status") == "unavailable":
        print(
            "decision server unavailable: " + str(scoring.get("reason")), file=sys.stderr
        )
        return 3

    scores = scoring.get("scores") or {}
    scored = [
        r for r in rows if (scores.get(r["score_key"]) or {}).get("score") is not None
    ]
    for r in rows:
        entry = scores.get(r["score_key"]) or {}
        r["score"] = entry.get("score")
        r["clamped"] = bool(entry.get("clamped"))
        if entry.get("error"):
            r["error"] = entry["error"]
    if not scored:
        print("no item could be scored", file=sys.stderr)
        return 3

    clamped_rows = [r["line"] for r in rows if r.get("clamped")]
    unscored_rows = [
        {"line": r["line"], "key": r["key"], "error": r.get("error")}
        for r in rows
        if r["score"] is None
    ]

    pos = [r["score"] for r in scored if r["label"] == 1]
    neg = [r["score"] for r in scored if r["label"] == 0]
    # Tie-break on the score key, never on input order: resolving ties by the
    # order the rows happen to appear in makes top-k recall depend on how the
    # file was written. AUC already counts a tie as half, so only top-k needed
    # fixing.
    ranked = sorted(scored, key=lambda r: (-r["score"], r["score_key"]))
    labels = [r["label"] for r in ranked]
    tied = len(ranked) - len({r["score"] for r in ranked})

    ks: list[int] = []
    oversized: list[int] = []
    for part in str(args.top_k).split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or int(part) == 0:
            raise SystemExit(f"--top-k: {part!r} is not a positive integer")
        k = int(part)
        if k > len(ranked):
            # Kept, not dropped: a k larger than the item count used to vanish
            # from the report with nothing saying it had been skipped.
            oversized.append(k)
        ks.append(k)
    recall = {f"top_{k}": top_k_recall(labels, min(k, len(ranked))) for k in sorted(set(ks))}

    auc = roc_auc(pos, neg)
    overlap = bool(pos and neg and min(pos) <= max(neg) and min(neg) <= max(pos))

    report = {
        "data": str(args.data),
        "question": args.question,
        "model": scoring.get("model"),
        "template_version_note": (
            "evidence must come from the same template as the ranking tools; "
            f"server template is {decisions.EVIDENCE_TEMPLATE_VERSION}"
        ),
        "evidence_field_shapes_seen": [list(shape) for shape in shapes],
        "evidence_shapes_consistent": len(shapes) == 1 and not untemplated,
        "items": len(rows),
        "scored": len(scored),
        "clamped_evidence": scoring.get("clamped_evidence", 0),
        "clamped_lines": clamped_rows,
        "unscored": unscored_rows,
        "duplicate_keys": duplicates,
        "tied_scores": tied,
        "elapsed_s": scoring.get("elapsed_s"),
        "auc": round(auc, 4) if auc is not None else None,
        "positive_scores": summarize(pos),
        "negative_scores": summarize(neg),
        "ranges_overlap": overlap,
        "top_k_recall": {
            k: (round(v, 4) if v is not None else None) for k, v in recall.items()
        },
        "ranking": [
            {
                "rank": i,
                "score": round(r["score"], 4),
                "label": r["label"],
                "key": r["key"],
                "line": r["line"],  # the key may repeat; the line never does
            }
            for i, r in enumerate(ranked, start=1)
        ],
        "verdict": verdict(auc, pos, neg, overlap),
        "caveats": list(decisions.CAVEATS),
    }
    warnings: list[str] = []
    if len(shapes) > 1:
        warnings.append(
            f"evidence rows use {len(shapes)} different field shapes "
            f"({' | '.join(', '.join(s) for s in shapes)}); scores are only "
            "comparable within one template shape"
        )
    if untemplated:
        warnings.append(
            f"{len(untemplated)} row(s) carry no recognised template field at "
            f"all (lines {untemplated[:10]}); render evidence with "
            "decisions.function_evidence / string_evidence"
        )
    if duplicates:
        warnings.append(
            f"{len(duplicates)} 'key' value(s) are used by more than one row "
            f"({duplicates}); keys are only labels here, scores are matched by "
            "row position, but the report will be hard to read"
        )
    if clamped_rows:
        warnings.append(
            f"{len(clamped_rows)} row(s) were clamped to the "
            f"{decisions.MAX_EVIDENCE_TOKENS}-token budget (lines "
            f"{clamped_rows[:10]}); every field label survives but the values "
            "were shortened, so these rows are not byte-identical to what you "
            "wrote"
        )
    if unscored_rows:
        warnings.append(
            f"{len(unscored_rows)} row(s) could not be scored and are excluded "
            f"from every number below (lines {[r['line'] for r in unscored_rows][:10]})"
        )
    if scoring.get("aborted"):
        warnings.append(f"the batch stopped early: {scoring['aborted']}")
    if oversized:
        warnings.append(
            f"--top-k {sorted(set(oversized))} exceeds the {len(ranked)} scored "
            "items, so those rows cover the whole ranking and read 1.0 by "
            "definition"
        )
    report["warnings"] = warnings

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    v = report["verdict"]
    print(f"model             {report['model']}")
    print(f"scored            {report['scored']}/{report['items']} in {report['elapsed_s']}s")
    print(f"evidence shape    {' | '.join(', '.join(s) for s in shapes) or '(untemplated)'}")
    for warning in warnings:
        print(f"WARNING           {warning}")
    print(f"AUC               {report['auc']}")
    print(f"positives         {report['positive_scores']}")
    print(f"negatives         {report['negative_scores']}")
    print(f"ranges overlap    {report['ranges_overlap']}")
    for k, val in report["top_k_recall"].items():
        print(f"{k + ' recall':<18}{val}")
    if report["tied_scores"]:
        print(f"tied scores       {report['tied_scores']} (tie-break is by key, not input order)")
    print()
    print(f"DISCRIMINATES?    {v['discriminates']}")
    print(f"                  {v['reason']}")
    for note in v.get("notes", []):
        print(f"  note            {note}")
    print()
    print("ranking (score, label, key):")
    for row in report["ranking"]:  # ties already broken deterministically
        print(
            f"  {row['rank']:>3}  {row['score']:.4f}  label={row['label']}  "
            f"{row['key']} (line {row['line']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
