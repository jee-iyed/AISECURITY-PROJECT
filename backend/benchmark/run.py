"""Reproducible detection benchmark: regex baseline vs multilayer gateway.

Usage (from backend/):
    python -m benchmark.run              # detection + end-to-end, writes results/v1
    python -m benchmark.run --no-e2e     # detection only

Nothing here calls Gemini: generate() is replaced by a counter that fails if
invoked, so the run is offline, free and deterministic (except latency).
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = "v1"

# Isolate the application from real data before importing it.
_tmp = Path(tempfile.mkdtemp(prefix="gateway-bench-"))
os.environ.update(
    DATA_DIR=str(_tmp),
    LOG_DIR=str(_tmp / "logs"),
    DATABASE_URL="sqlite:///" + str(_tmp / "bench.db").replace("\\", "/"),
    GEMINI_API_KEY="",
    JWT_SECRET="benchmark-only-secret-with-at-least-32-chars",
    DEMO_DATA_DIR=str(ROOT.parents[1] / "demo-data"),
)
sys.path.insert(0, str(ROOT.parent))

from app.llm import gemini_client  # noqa: E402
from app.security.context_guard import ContentSource, analyze_context  # noqa: E402
from app.security.input_guard import analyze_input  # noqa: E402
from benchmark import charts  # noqa: E402
from benchmark.baseline_regex import analyze as baseline_analyze  # noqa: E402
from benchmark.metrics import (  # noqa: E402
    DATASET,
    EQUIVALENT,
    LABELS,
    binary,
    leakage_report,
    load,
    percentile,
)

LLM_CALLS = []


def _no_llm(*args, **kwargs):
    LLM_CALLS.append(1)
    raise gemini_client.LLMUnavailable("LLM disabled during benchmark")


gemini_client.generate = _no_llm


def gateway(row):
    if row["source"] == "user_prompt":
        r = analyze_input(row["text"])
    else:
        r = analyze_context(
            ContentSource(
                source_id=row["id"], source_type=row["source"], content=row["text"]
            )
        )
    return r["decision"], r["threat_type"], r["risk_score"]


def baseline(row):
    return baseline_analyze(row["text"], row["source"])


SYSTEMS = {"baseline_regex": baseline, "gateway_multilayer": gateway}


def timed(fn, row, repeat=5):
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        out = fn(row)
        samples.append((time.perf_counter() - start) * 1000)
    return out, statistics.median(samples)


def evaluate(rows):
    results = {}
    for name, fn in SYSTEMS.items():
        records = []
        for row in rows:
            (decision, threat, score), ms = timed(fn, row)
            predicted = decision == "BLOCK"
            threat = EQUIVALENT.get(threat, threat)
            records.append(
                {
                    **row,
                    "predicted": predicted,
                    "pred_threat": threat,
                    "score": score,
                    "ms": ms,
                }
            )
        results[name] = records
    return results


def summarize(records):
    out = {}
    for split in ("dev", "test", "all"):
        subset = [r for r in records if split == "all" or r["split"] == split]
        overall = binary([(r["predicted"], r["malicious"]) for r in subset])
        detected = [r for r in subset if r["predicted"] and r["malicious"]]
        overall["type_accuracy_on_detected"] = (
            round(
                sum(r["pred_threat"] == r["label"] for r in detected) / len(detected), 4
            )
            if detected
            else None
        )
        by = defaultdict(list)
        for r in subset:
            by[("category", r["category"])].append(r)
            by[("label", r["label"])].append(r)
            by[("language", r["language"])].append(r)
            by[("source", r["source"])].append(r)
        groups = {
            f"{kind}:{value}": binary([(r["predicted"], r["malicious"]) for r in rs])
            for (kind, value), rs in sorted(by.items())
        }
        cols = LABELS[:-1] + ["NOT_BLOCKED"]
        matrix = [[0] * len(cols) for _ in LABELS]
        for r in subset:
            key = str(r["pred_threat"]) if r["predicted"] else "NOT_BLOCKED"
            if key not in cols:  # blocked with a type outside the label set
                cols.append(key)
                for row in matrix:
                    row.append(0)
            matrix[LABELS.index(r["label"])][cols.index(key)] += 1
        ms = [r["ms"] for r in subset]
        out[split] = {
            "overall": overall,
            "groups": groups,
            "confusion": {"rows": LABELS, "cols": cols, "matrix": matrix},
            "latency_ms": {
                "p50": percentile(ms, 0.5),
                "p95": percentile(ms, 0.95),
                "max": round(max(ms), 4) if ms else None,
            },
        }
    return out


def threshold_sweep(records):
    test = [r for r in records if r["split"] == "test"]
    sweep = []
    for t in range(0, 101, 5):
        m = binary([(r["score"] >= t, r["malicious"]) for r in test])
        sweep.append(
            {"threshold": t, **{k: m[k] for k in ("precision", "recall", "fpr", "f1")}}
        )
    return sweep


def git_commit():
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=ROOT,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-e2e", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "results" / VERSION))
    args = parser.parse_args()
    out = Path(args.out)
    (out / "charts").mkdir(parents=True, exist_ok=True)

    rows = load()
    leakage = leakage_report(rows)
    records = evaluate(rows)
    summary = {name: summarize(recs) for name, recs in records.items()}
    sweep = threshold_sweep(records["gateway_multilayer"])
    report = {
        "benchmark_version": VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "git_commit": git_commit(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dataset": {
            "path": str(DATASET.relative_to(ROOT.parent)),
            "sha256": hashlib.sha256(DATASET.read_bytes()).hexdigest(),
            "size": len(rows),
            "splits": dict(Counter(r["split"] for r in rows)),
            "malicious": sum(r["malicious"] for r in rows),
            **leakage,
        },
        "positive_prediction": "decision == BLOCK (input guard for user prompts, "
        "context guard quarantine for documents/database content)",
        "systems": summary,
        "gateway_threshold_sweep_test": sweep,
        "llm_calls_during_detection": len(LLM_CALLS),
    }
    if not args.no_e2e:
        from benchmark.e2e import run_e2e

        report["end_to_end"] = run_e2e(rows)
        report["llm_calls_total"] = len(LLM_CALLS)

    (out / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    metric_rows = []
    for system, splits in summary.items():
        for split, data in splits.items():
            metric_rows.append(
                {
                    "system": system,
                    "split": split,
                    "group": "overall",
                    **data["overall"],
                }
            )
            for group, m in data["groups"].items():
                metric_rows.append(
                    {"system": system, "split": split, "group": group, **m}
                )
    write_csv(
        out / "metrics.csv",
        metric_rows,
        [
            "system",
            "split",
            "group",
            "n",
            "tp",
            "tn",
            "fp",
            "fn",
            "precision",
            "recall",
            "f1",
            "fpr",
            "fnr",
            "accuracy",
        ],
    )
    errors = [
        {"system": s, **r}
        for s, recs in records.items()
        for r in recs
        if r["predicted"] != r["malicious"]
    ]
    write_csv(
        out / "errors.csv",
        errors,
        [
            "system",
            "id",
            "split",
            "label",
            "category",
            "language",
            "source",
            "predicted",
            "pred_threat",
            "score",
            "text",
        ],
    )
    write_csv(
        out / "threshold_sweep.csv",
        sweep,
        ["threshold", "precision", "recall", "fpr", "f1"],
    )
    for system, splits in summary.items():
        conf = splits["test"]["confusion"]
        with (out / f"confusion_{system}_test.csv").open(
            "w", newline="", encoding="utf-8"
        ) as f:
            w = csv.writer(f)
            w.writerow(["true\\predicted", *conf["cols"]])
            for label, row in zip(conf["rows"], conf["matrix"], strict=True):
                w.writerow([label, *row])

    # Charts (test split only: the dev split was used while building detectors).
    b, g = summary["baseline_regex"]["test"], summary["gateway_multilayer"]["test"]
    metrics = ["precision", "recall", "f1", "fpr"]
    charts.grouped_bars(
        "Held-out test split: detection metrics",
        [m.upper() for m in metrics],
        [
            ("Gateway (multilayer)", [g["overall"][m] or 0 for m in metrics]),
            ("Baseline (regex)", [b["overall"][m] or 0 for m in metrics]),
        ],
        out / "charts" / "metrics_test.svg",
    )
    categories = [
        "explicit",
        "reformulated",
        "obfuscated",
        "multilingual",
        "indirect",
        "ambiguous",
    ]
    charts.grouped_bars(
        "Recall by category (test split)",
        categories,
        [
            (
                "Gateway (multilayer)",
                [
                    g["groups"].get(f"category:{c}", {}).get("recall", 0)
                    for c in categories
                ],
            ),
            (
                "Baseline (regex)",
                [
                    b["groups"].get(f"category:{c}", {}).get("recall", 0)
                    for c in categories
                ],
            ),
        ],
        out / "charts" / "recall_by_category_test.svg",
    )
    benign_cats = ["benign", "pedagogical", "ambiguous"]
    charts.grouped_bars(
        "False positive rate on benign categories (test split)",
        benign_cats,
        [
            (
                "Gateway (multilayer)",
                [
                    g["groups"].get(f"category:{c}", {}).get("fpr") or 0
                    for c in benign_cats
                ],
            ),
            (
                "Baseline (regex)",
                [
                    b["groups"].get(f"category:{c}", {}).get("fpr") or 0
                    for c in benign_cats
                ],
            ),
        ],
        out / "charts" / "fpr_by_category_test.svg",
    )
    for system, data in (("gateway_multilayer", g), ("baseline_regex", b)):
        conf = data["confusion"]
        charts.heatmap(
            f"Confusion matrix · {system} · test",
            conf["rows"],
            conf["cols"],
            conf["matrix"],
            out / "charts" / f"confusion_{system}_test.svg",
        )
    charts.lines(
        "Gateway threshold sweep (test split)",
        [s["threshold"] for s in sweep],
        [
            ("Precision", [s["precision"] for s in sweep], "ln1"),
            ("Recall", [s["recall"] for s in sweep], "ln2"),
            ("FPR", [s["fpr"] or 0 for s in sweep], "ln3"),
        ],
        out / "charts" / "threshold_sweep_test.svg",
        "risk score threshold",
    )

    for system in summary:
        o = summary[system]["test"]["overall"]
        print(
            f"{system:20} test  P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f} "
            f"FPR={o['fpr']:.3f} FNR={o['fnr']:.3f}  (TP={o['tp']} FP={o['fp']} TN={o['tn']} FN={o['fn']})"
        )
    print(f"LLM calls: {report.get('llm_calls_total', len(LLM_CALLS))}  -> {out}")


if __name__ == "__main__":
    main()
