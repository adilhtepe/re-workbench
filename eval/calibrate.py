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
produced from differently worded evidence are not comparable.

Output: ROC AUC, top-k recall, per-class score ranges, and an explicit verdict
on whether the question discriminates on this data.

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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
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
                "key": str(obj.get("key") or f"line{lineno}"),
                "evidence": evidence,
                "label": label,
                "line": lineno,
            }
        )
    return rows


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

    if abs(margin) < PARAPHRASE_NOISE:
        notes.append(
            f"class margin {margin:+.4f} is inside the measured paraphrase noise "
            f"({PARAPHRASE_NOISE}): indistinguishable from rewording the evidence "
            f"(a question measured as non-working had margin {MEASURED_FAILED_MARGIN})"
        )
    if n < 30:
        notes.append(
            f"only {n} labelled items: too few to conclude, label more before "
            "acting on this"
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

    shapes = {len(r["evidence"].split(";")) for r in rows}
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
        [{"key": r["key"], "evidence": r["evidence"]} for r in rows],
        args.question_id,
        args.question,
    )
    if scoring.get("status") == "unavailable":
        print(
            "decision server unavailable: " + str(scoring.get("reason")), file=sys.stderr
        )
        return 3

    scores = scoring.get("scores") or {}
    scored = [r for r in rows if (scores.get(r["key"]) or {}).get("score") is not None]
    for r in scored:
        r["score"] = scores[r["key"]]["score"]
    if not scored:
        print("no item could be scored", file=sys.stderr)
        return 3

    pos = [r["score"] for r in scored if r["label"] == 1]
    neg = [r["score"] for r in scored if r["label"] == 0]
    ranked = sorted(scored, key=lambda r: -r["score"])
    labels = [r["label"] for r in ranked]

    ks = []
    for part in str(args.top_k).split(","):
        part = part.strip()
        if part.isdigit() and 0 < int(part) <= len(ranked):
            ks.append(int(part))
    recall = {f"top_{k}": top_k_recall(labels, k) for k in sorted(set(ks))}

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
        "evidence_field_shapes_seen": sorted(shapes),
        "items": len(rows),
        "scored": len(scored),
        "elapsed_s": scoring.get("elapsed_s"),
        "auc": round(auc, 4) if auc is not None else None,
        "positive_scores": summarize(pos),
        "negative_scores": summarize(neg),
        "ranges_overlap": overlap,
        "top_k_recall": {
            k: (round(v, 4) if v is not None else None) for k, v in recall.items()
        },
        "ranking": [
            {"rank": i, "score": round(r["score"], 4), "label": r["label"], "key": r["key"]}
            for i, r in enumerate(ranked, start=1)
        ],
        "verdict": verdict(auc, pos, neg, overlap),
        "caveats": list(decisions.CAVEATS),
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    v = report["verdict"]
    print(f"model             {report['model']}")
    print(f"scored            {report['scored']}/{report['items']} in {report['elapsed_s']}s")
    if len(shapes) > 1:
        print(
            f"WARNING           evidence lines have {len(shapes)} different field "
            "shapes; scores are only comparable within one template"
        )
    print(f"AUC               {report['auc']}")
    print(f"positives         {report['positive_scores']}")
    print(f"negatives         {report['negative_scores']}")
    print(f"ranges overlap    {report['ranges_overlap']}")
    for k, val in report["top_k_recall"].items():
        print(f"{k + ' recall':<18}{val}")
    print()
    print(f"DISCRIMINATES?    {v['discriminates']}")
    print(f"                  {v['reason']}")
    for note in v.get("notes", []):
        print(f"  note            {note}")
    print()
    print("ranking (score, label, key):")
    for row in report["ranking"]:
        print(f"  {row['rank']:>3}  {row['score']:.4f}  label={row['label']}  {row['key']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
