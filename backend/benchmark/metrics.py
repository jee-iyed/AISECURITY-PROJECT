"""Side-effect-free dataset loading and metric helpers."""

import json
import re
from collections import Counter
from pathlib import Path

DATASET = Path(__file__).resolve().parent / "data" / "dataset_v1.jsonl"
LABELS = [
    "PROMPT_INJECTION",
    "INDIRECT_PROMPT_INJECTION",
    "JAILBREAK",
    "ROLE_MANIPULATION",
    "INFORMATION_LEAKAGE",
    "TOOL_ABUSE",
    "BENIGN",
]
# Predicted threat types that count as the same family as the true label.
EQUIVALENT = {"TOOL_MANIPULATION": "TOOL_ABUSE", "UNAUTHORIZED_ACTION": "TOOL_ABUSE"}


def load(path=DATASET):
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate ids"
    return rows


def _tokens(text):
    return set(re.findall(r"\w+", text.casefold()))


def leakage_report(rows, threshold=0.8):
    """Exact and near duplicates (token Jaccard >= threshold) across splits."""
    dev = [r for r in rows if r["split"] == "dev"]
    test = [r for r in rows if r["split"] == "test"]
    texts = [r["text"].strip().casefold() for r in rows]
    exact = [t for t, n in Counter(texts).items() if n > 1]
    near = []
    for t in test:
        tt = _tokens(t["text"])
        for d in dev:
            dt = _tokens(d["text"])
            if tt and dt and len(tt & dt) / len(tt | dt) >= threshold:
                near.append((t["id"], d["id"]))
    return {"exact_duplicates": exact, "near_duplicates_test_vs_dev": near}


def binary(preds):
    tp = sum(p and t for p, t in preds)
    tn = sum(not p and not t for p, t in preds)
    fp = sum(p and not t for p, t in preds)
    fn = sum(not p and t for p, t in preds)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "n": len(preds),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fp / (fp + tn), 4) if fp + tn else None,
        "fnr": round(fn / (fn + tp), 4) if fn + tp else None,
        "accuracy": round((tp + tn) / len(preds), 4) if preds else None,
    }


def percentile(values, q):
    values = sorted(values)
    if not values:
        return None
    k = (len(values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return round(values[lo] + (values[hi] - values[lo]) * (k - lo), 4)
