#!/usr/bin/env python3
"""Compare six fixed import features with the completed v8 data baseline.

Uses the baseline cache and exact split; writes a separate development candidate.
No PE files are executed. Source holdouts are development diagnostics, because
previous holdout results informed this feature hypothesis. Obtain fresh data
before making a production decision.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

import reviewer_v8_workflow as w
from defender.models.boundary_reviewer import IMPORT_FEATURES, _import_values

SOURCES = ("batch-v7", "batch-v11", "reviewer-v4-v9-dev", "reviewer-v5-v10-diagnostic")


def augment_cache(cached):
    return {sha: dict(sample, structural_vector=sample["structural_vector"]
                     + list(_import_values(sample["attributes"])))
            for sha, sample in cached.items()}


def export_imports(clf, frozen, threshold):
    spec = dict(frozen, feature_names=list(frozen["feature_names"]) + list(IMPORT_FEATURES))
    payload = w.export(clf, spec, threshold)
    payload.update(format_version=8, import_features=list(IMPORT_FEATURES))
    reviewer = w.BoundaryReviewer.__new__(w.BoundaryReviewer)
    reviewer._load(payload)  # Validate feature order, precision and all trees.
    return payload


def category_summary(rows, predictions, cached):
    groups = {}
    for name, contains in (("has_fixed_kernel_driver_import", True),
                           ("no_fixed_kernel_driver_import", False)):
        indices = [i for i, row in enumerate(rows)
                   if bool(_import_values(cached[row["sha256"]]["attributes"])[-1]) == contains]
        groups[name] = w.metrics([rows[i] for i in indices], np.asarray(predictions)[indices])
    return groups


def verify_baseline(rows, cached, frozen, baseline, train_rows, cal_rows):
    metadata = json.loads((baseline / "metadata.json").read_text(encoding="utf-8"))
    manifest = json.loads((baseline / "split_manifest.json").read_text(encoding="utf-8"))
    payload = json.loads((baseline / "model.json").read_text(encoding="utf-8"))
    if (metadata.get("experiment") != "boundary_reviewer_v8_runtime_aligned_data_baseline"
            or metadata.get("configuration") != w.CONFIG
            or metadata.get("route_min") != frozen["route_min"]
            or metadata.get("original_threshold") != frozen["reviewer_threshold"]
            or metadata.get("source_counts") != dict(Counter(r["source"] for r in rows))
            or payload.get("feature_names") != frozen["feature_names"]
            or payload.get("format_version") != 7):
        raise ValueError("Baseline specification differs; rerun the baseline train command first")
    for key, group in (("training", train_rows), ("calibration", cal_rows)):
        if manifest.get(key) != [r["sha256"] for r in group]:
            raise ValueError(f"Baseline {key} split differs; experiment stopped")
    clf = w.fit(train_rows, cached, frozen["route_min"])
    threshold, calibrated, _ = w.calibrate(cal_rows, w.predict(clf, cal_rows, cached, frozen["route_min"]))
    reconstructed = w.export(clf, frozen, threshold)
    if reconstructed != payload or calibrated != metadata["calibration"]:
        raise ValueError("Completed baseline cannot be reproduced exactly; check cache, reports and dependencies")
    X = np.array([w.vector(r, cached[r["sha256"]]) for r in rows])
    parity = float(np.max(np.abs(clf.predict_proba(X)[:, 1] - w.model_probabilities(payload, X))))
    if parity > 1e-10:
        raise ValueError(f"Baseline export parity failed: {parity}")
    print(f"Completed baseline reproduced exactly; export parity={parity:.3g}", flush=True)
    return clf, threshold, payload


def experiment(rows, cached, frozen, baseline, output):
    train_rows, cal_rows = w.preserved_split(rows)
    if {r["sha256"] for r in train_rows} & {r["sha256"] for r in cal_rows}:
        raise ValueError("Training/calibration overlap")
    base_clf, base_t, _ = verify_baseline(rows, cached, frozen, baseline, train_rows, cal_rows)
    augmented = augment_cache(cached)
    route, original_t = frozen["route_min"], frozen["reviewer_threshold"]
    clf = w.fit(train_rows, augmented, route)
    probs = w.predict(clf, cal_rows, augmented, route)
    threshold, calibration, by_source = w.calibrate(cal_rows, probs)
    payload = export_imports(clf, frozen, threshold)
    X = np.array([w.vector(r, augmented[r["sha256"]]) for r in rows])
    parity = float(np.max(np.abs(clf.predict_proba(X)[:, 1] - w.model_probabilities(payload, X))))
    if parity > 1e-10:
        raise ValueError(f"Import candidate export parity failed: {parity}")
    bp = w.predict(base_clf, cal_rows, cached, route)
    shared = {}
    for name, predictions in (("baseline", bp >= base_t), ("import_candidate", probs >= threshold),
                              ("baseline_at_original_threshold", bp >= original_t),
                              ("import_candidate_at_original_threshold", probs >= original_t)):
        shared[name] = dict(overall=w.metrics(cal_rows, predictions),
                            by_category=category_summary(cal_rows, predictions, cached))
    changes = []
    for r, b, p in zip(cal_rows, bp, probs):
        before, after = int(b >= base_t), int(p >= threshold)
        if before != after:
            changes.append(dict(sha256=r["sha256"], source=r["source"], label=r["label"],
                                baseline_prediction=before, import_prediction=after,
                                baseline_probability=float(b), import_probability=float(p),
                                corrected=after == r["label"]))
    folds, score_rows, missed = [], [], []
    for source in SOURCES:
        heldout = [r for r in rows if r["source"] == source]
        fold_fit, fold_cal = w.preserved_split([r for r in rows if r["source"] != source])
        if any(r["source"] == source for r in fold_fit + fold_cal):
            raise ValueError("Source holdout leaked into fitting/calibration")
        result = dict(source=source, models={})
        scores, thresholds = {}, {}
        for name, features in (("baseline", cached), ("import_candidate", augmented)):
            fold_clf = w.fit(fold_fit, features, route)
            ft, fm, _ = w.calibrate(fold_cal, w.predict(fold_clf, fold_cal, features, route))
            hp = w.predict(fold_clf, heldout, features, route)
            scores[name], thresholds[name] = hp, ft
            result["models"][name] = dict(threshold=ft, calibration=fm,
                heldout=w.metrics(heldout, hp >= ft),
                heldout_at_original_threshold=w.metrics(heldout, hp >= original_t),
                by_category=category_summary(heldout, hp >= ft, cached))
            for r, probability in zip(heldout, hp):
                if int(probability >= ft) != r["label"]:
                    missed.append(dict(source=source, model=name, sha256=r["sha256"], label=r["label"],
                        probability=float(probability), threshold=ft,
                        import_features=dict(zip(IMPORT_FEATURES, _import_values(cached[r["sha256"]]["attributes"])))))
        folds.append(result)
        print(f"Held-out {source}: " + json.dumps({k: v["heldout"] for k, v in result["models"].items()}), flush=True)
        for i, r in enumerate(heldout):
            record = dict(sha256=r["sha256"], source=source, label=r["label"],
                          reviewer_routed=r["adapter_probability"] >= route,
                          adapter_probability=r["adapter_probability"])
            record.update(dict(zip(IMPORT_FEATURES, _import_values(cached[r["sha256"]]["attributes"]))))
            for name in scores:
                record[name + "_probability"] = float(scores[name][i]) if record["reviewer_routed"] else None
                record[name + "_threshold"] = thresholds[name]
                record[name + "_prediction"] = int(scores[name][i] >= thresholds[name])
                record[name + "_prediction_at_original_threshold"] = int(scores[name][i] >= original_t)
            score_rows.append(record)
    metadata = dict(experiment="boundary_reviewer_v8_fixed_import_features", development_only=True,
        warning="Feature hypothesis informed by prior source holdouts. Calibration and source holdouts are development diagnostics, not a fresh independent test or upstream leakage-safe skimmer scores.",
        configuration=w.CONFIG, seed=704, new_source_split_seed=1704, calibration_fraction=.2,
        model_format_version=8, tree_input_dtype="float32", route_min=route,
        reviewer_threshold=threshold, original_threshold=original_t, baseline_threshold=base_t,
        feature_names=payload["feature_names"], added_features=list(IMPORT_FEATURES),
        feature_definition="Case-insensitive ordinary-import library basenames; five presence indicators plus their sum. No filename, label, or hard benign bypass.",
        runtime_parity_max_abs_error=parity, calibration=calibration, calibration_by_source=by_source,
        shared_calibration=shared, calibration_prediction_changes=changes, leave_one_source_out=folds,
        baseline_model_sha256=hashlib.sha256((baseline / "model.json").read_bytes()).hexdigest(),
        source_counts=dict(Counter(r["source"] for r in rows)),
        sklearn_version=w.importlib.metadata.version("scikit-learn"), numpy_version=np.__version__)
    w.dump(output / "model.json", payload)
    w.dump(output / "metadata.json", metadata)
    w.dump(output / "split_manifest.json", dict(training=[r["sha256"] for r in train_rows],
        calibration=[r["sha256"] for r in cal_rows], baseline_split_preserved=True))
    w.dump(output / "source-holdout-errors.json", dict(errors=missed))
    with (output / "reviewer-source-heldout-scores.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(score_rows[0]))
        writer.writeheader()
        writer.writerows(score_rows)
    print(f"Import experiment written to {output}; calibration={calibration}", flush=True)
    print("Send metadata.json and source-holdout-errors.json. Keep production v7 unchanged.", flush=True)
    return metadata


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports-dir", type=Path, default=w.ROOT / "validation-data")
    ap.add_argument("--location", type=Path, action="append")
    ap.add_argument("--v7-model", type=Path, default=w.ROOT / "defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json")
    ap.add_argument("--baseline-output", type=Path, default=w.ROOT / "validation-data/reviewer-v8-development")
    ap.add_argument("--output", type=Path, default=w.ROOT / "validation-data/reviewer-v8-import-features-development")
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    args = ap.parse_args()
    try:
        if args.output.resolve() == args.baseline_output.resolve():
            raise ValueError("Import experiment output must differ from baseline output")
        for name in ("metadata.json", "model.json", "split_manifest.json", "inputs.json", "feature-cache.json"):
            if not (args.baseline_output / name).is_file():
                raise ValueError(f"Missing completed baseline file: {name}; run reviewer_v8_workflow.py train first")
        frozen = json.loads(args.v7_model.read_text(encoding="utf-8"))
        reviewer = w.BoundaryReviewer(args.v7_model)
        if frozen.get("format_version") != 6 or reviewer.model_type != "gradient_boosting" or abs(reviewer.route_min - .15) > 1e-12:
            raise ValueError("Expected original frozen v7 model, format 6, route_min=0.15")
        original_inputs = json.loads((args.baseline_output / "inputs.json").read_text(encoding="utf-8"))
        if original_inputs.get("frozen_model_sha256") != hashlib.sha256(args.v7_model.read_bytes()).hexdigest():
            raise ValueError("Frozen v7 model differs from baseline provenance")
        args.output.mkdir(parents=True, exist_ok=True)
        audit_rows, paths = w.load_audit(args.reports_dir)
        rows, old_paths = w.merge_training(args.reports_dir, audit_rows)
        paths.update(old_paths)
        cached = w.collect_features(rows, reviewer, args.v7_model, args.location or [args.reports_dir],
                                    args.baseline_output / "feature-cache.json", args.max_bytes)
        w.audit(audit_rows, cached, reviewer, frozen, args.output)
        w.dump(args.output / "inputs.json", dict(reports=paths,
            report_sha256={s: hashlib.sha256(Path(p).read_bytes()).hexdigest() for s, p in paths.items()},
            frozen_model_sha256=original_inputs["frozen_model_sha256"], baseline_output=str(args.baseline_output)))
        experiment(rows, cached, frozen, args.baseline_output, args.output)
    except (ValueError, OSError, ImportError, RuntimeError, KeyError) as error:
        ap.exit(2, f"V8 import experiment stopped: {error}\n")


if __name__ == "__main__":
    main()
