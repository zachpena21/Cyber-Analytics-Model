#!/usr/bin/env python3
"""Choose a benign-probability cutoff that satisfies the course FPR target."""

import argparse
import csv
from pathlib import Path


def metrics(rows, threshold):
    tp = fp = tn = fn = 0
    for label, benign_probability in rows:
        prediction = int(benign_probability < threshold)
        tp += prediction == 1 and label == 1
        fp += prediction == 1 and label == 0
        tn += prediction == 0 and label == 0
        fn += prediction == 0 and label == 1
    fpr = fp / (fp + tn) if fp + tn else 0.0
    tpr = tp / (tp + fn) if tp + fn else 0.0
    return fpr, tpr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scores", type=Path, help="CSV with label,benign_probability")
    parser.add_argument("--max-fpr", type=float, default=0.01)
    args = parser.parse_args()

    with args.scores.open(newline="") as stream:
        rows = [
            (int(row["label"]), float(row["benign_probability"]))
            for row in csv.DictReader(stream)
        ]
    if not rows or not {label for label, _ in rows}.issuperset({0, 1}):
        raise SystemExit("scores must contain both benign (0) and malicious (1) rows")

    candidates = sorted({0.0, 1.0, *(score for _, score in rows)})
    feasible = []
    for threshold in candidates:
        fpr, tpr = metrics(rows, threshold)
        if fpr <= args.max_fpr:
            feasible.append((tpr, -fpr, threshold))
    tpr, neg_fpr, threshold = max(feasible)
    print(f"DF_MODEL_THRESH={threshold:.12g}")
    print(f"validation_fpr={-neg_fpr:.6%}")
    print(f"validation_tpr={tpr:.6%}")


if __name__ == "__main__":
    main()
