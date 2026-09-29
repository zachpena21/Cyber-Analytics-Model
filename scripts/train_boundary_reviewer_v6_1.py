#!/usr/bin/env python3
"""Train reviewer v6.1 with a small set of derived PE interaction features.

Development experiment only.  Keeps the v6 routing/model/LOSO selection policy,
but augments the reviewer representation with a deliberately small set of
interpretable PE relationships motivated by the v10 LOSO miss analysis.
"""

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import (
    CATEGORICAL_FIELDS,
    EXTRA_NUMERIC,
    SCORE_FEATURES,
    TEXT_FIELDS,
    NeedForSpeedModel,
    collect_attributes,
    export_forest,
    finite_number,
    forest_probability,
    rates,
    tokens,
    whole_split_probabilities,
)
from train_boundary_reviewer_v2 import class_counts, merge_reports
from train_boundary_reviewer_v5 import source_stratified_split_allow_small
from train_modern_adapter_v2_1 import choose_source_constrained_threshold


DERIVED_FEATURES = (
    "code_to_file_ratio",
    "virtual_to_file_ratio",
    "imports_per_section",
    "exports_per_section",
    "section_density",
    "has_exports",
    "large_export_table",
    "amd64_pe32plus",
    "amd64_pe32plus_many_sections",
    "modern_amd64_linker",
)


def _safe_ratio(numerator, denominator):
    numerator = finite_number(numerator)
    denominator = finite_number(denominator)
    if denominator <= 0.0:
        return 0.0
    value = numerator / denominator
    return value if math.isfinite(value) else 0.0


def derived_values(attributes):
    byte_size = finite_number(attributes.get("byte_size"))
    virtual_size = finite_number(attributes.get("virtual_size"))
    sizeof_code = finite_number(attributes.get("sizeof_code"))
    imports = finite_number(attributes.get("imports"))
    exports = finite_number(attributes.get("exports"))
    sections = finite_number(attributes.get("numberof_sections"))
    linker_major = finite_number(attributes.get("major_linker_version"))
    machine = str(attributes.get("machine", ""))
    magic = str(attributes.get("magic", ""))
    amd64 = float(machine == "MACHINE_TYPES.AMD64")
    pe32plus = float(magic == "PE32_PLUS")
    amd64_pe32plus = amd64 * pe32plus
    return (
        _safe_ratio(sizeof_code, byte_size),
        _safe_ratio(virtual_size, byte_size),
        _safe_ratio(imports, sections),
        _safe_ratio(exports, sections),
        _safe_ratio(byte_size, sections),
        float(exports > 0.0),
        float(exports >= 32.0),
        amd64_pe32plus,
        float(amd64_pe32plus == 1.0 and sections >= 6.0),
        float(amd64 == 1.0 and 12.0 <= linker_major <= 14.0),
    )


def build_feature_spec(train_rows, attributes):
    categories = {}
    for field in CATEGORICAL_FIELDS:
        categories[field] = sorted(
            {
                str(attributes[row["sha256"]].get(field, ""))
                for row in train_rows
            }
        )

    names = list(SCORE_FEATURES)
    names.extend(NeedForSpeedModel.NUMERICAL_ATTRIBUTES)
    names.extend(EXTRA_NUMERIC)
    names.extend(("byte_size", "byte_entropy"))
    for field in TEXT_FIELDS:
        names.extend(
            (
                f"{field}_token_count",
                f"{field}_unique_count",
                f"{field}_character_count",
            )
        )
    names.extend(DERIVED_FEATURES)
    for field in CATEGORICAL_FIELDS:
        names.extend(f"{field}={value}" for value in categories[field])
    return {"feature_names": names, "categories": categories}


def vectorize(row, attributes, spec):
    values = [finite_number(row[name]) for name in SCORE_FEATURES]
    values.extend(
        finite_number(attributes.get(name))
        for name in NeedForSpeedModel.NUMERICAL_ATTRIBUTES
    )
    values.extend(finite_number(attributes.get(name)) for name in EXTRA_NUMERIC)
    values.extend(
        (
            finite_number(attributes.get("byte_size")),
            finite_number(attributes.get("byte_entropy")),
        )
    )
    for field in TEXT_FIELDS:
        field_tokens = tokens(attributes.get(field))
        values.extend(
            (
                float(len(field_tokens)),
                float(len(set(field_tokens))),
                float(len(str(attributes.get(field, "") or ""))),
            )
        )
    values.extend(derived_values(attributes))
    for field in CATEGORICAL_FIELDS:
        actual = str(attributes.get(field, ""))
        values.extend(float(actual == value) for value in spec["categories"][field])
    if len(values) != len(spec["feature_names"]):
        raise ValueError(
            f"feature vector length mismatch: {len(values)} != {len(spec['feature_names'])}"
        )
    return values


def matrix(rows, attributes, spec):
    return np.asarray(
        [vectorize(row, attributes[row["sha256"]], spec) for row in rows],
        dtype=np.float64,
    )


def route_candidates(values):
    result = sorted({float(v) for v in values})
    if not result or any(v < 0 or v > 1 for v in result):
        raise ValueError("route candidates must be in [0,1]")
    return result


def model_configs():
    for family in ("random_forest", "extra_trees"):
        for depth in (2, 3, 4, 5):
            for leaf in (4, 8, 12, 20):
                yield family, depth, leaf


def make_classifier(family, depth, leaf, seed):
    common = dict(
        n_estimators=192,
        max_depth=depth,
        min_samples_leaf=leaf,
        max_features="sqrt",
        random_state=seed,
        n_jobs=-1,
    )
    if family == "random_forest":
        return RandomForestClassifier(class_weight="balanced_subsample", **common)
    return ExtraTreesClassifier(class_weight="balanced", **common)


def prepare_routed(rows, route_min):
    return [row for row in rows if row["adapter_probability"] >= route_min]


def fit_and_score(family, depth, leaf, seed, fit_rows, eval_rows, attributes, route_min):
    routed_fit = prepare_routed(fit_rows, route_min)
    routed_eval = prepare_routed(eval_rows, route_min)
    counts = class_counts(routed_fit)
    if counts["benign"] < 10 or counts["malicious"] < 10:
        return None
    spec = build_feature_spec(routed_fit, attributes)
    Xfit = matrix(routed_fit, attributes, spec)
    yfit = np.asarray([row["label"] for row in routed_fit], dtype=np.int8)
    clf = make_classifier(family, depth, leaf, seed)
    clf.fit(Xfit, yfit)
    if routed_eval:
        probs_routed = forest_probability(clf, matrix(routed_eval, attributes, spec))
    else:
        probs_routed = np.asarray([], dtype=np.float64)
    probs_all = whole_split_probabilities(eval_rows, routed_eval, probs_routed)
    return clf, spec, routed_fit, routed_eval, probs_all


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, action="append", type=Path)
    ap.add_argument("--location", required=True, action="append", type=Path)
    ap.add_argument("--holdout-source", action="append", default=[])
    ap.add_argument("--route-candidate", action="append", default=None)
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--min-tpr", type=float, default=0.95)
    ap.add_argument("--min-source-benign", type=int, default=100)
    ap.add_argument("--calibration-fraction", type=float, default=0.20)
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--seed", type=int, default=704)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "defender" / "defender" / "models" / "boundary_reviewer_v6_1_candidate",
    )
    args = ap.parse_args()

    routes = route_candidates(args.route_candidate or ["0.20", "0.25", "0.30", "0.35", "0.40", "0.45", "0.50"])
    for path in [*args.report, *args.location]:
        if not path.exists():
            raise SystemExit(f"required input not found: {path}")

    records, source_counts = merge_reports(args.report)
    train_rows, cal_rows, split_counts = source_stratified_split_allow_small(
        records, args.seed, args.calibration_fraction
    )
    print(f"Reviewer v6.1 rows: train={class_counts(train_rows)} cal={class_counts(cal_rows)}", flush=True)

    wanted = {row["sha256"] for row in records}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)

    folds = []
    for i, source in enumerate(args.holdout_source):
        heldout = [r for r in records if r["source"] == source]
        remaining = [r for r in records if r["source"] != source]
        fit, cal, counts = source_stratified_split_allow_small(
            remaining, args.seed + 1000 + i, args.calibration_fraction
        )
        folds.append((source, fit, cal, heldout, counts))
        print(f"LOSO {source}: fit={class_counts(fit)} cal={class_counts(cal)} heldout={class_counts(heldout)}", flush=True)

    best = None
    results = []
    for route in routes:
        for family, depth, leaf in model_configs():
            fitted = fit_and_score(family, depth, leaf, args.seed, train_rows, cal_rows, attributes, route)
            if fitted is None:
                continue
            clf, spec, routed_train, routed_cal, cal_probs = fitted
            try:
                threshold, cal_result, cal_by_source, worst_source_fpr = choose_source_constrained_threshold(
                    cal_rows, cal_probs, args.max_fpr, args.min_source_benign
                )
            except ValueError:
                continue

            loso = []
            for i, (source, fold_fit, fold_cal, heldout, fold_counts) in enumerate(folds):
                fold_fitted = fit_and_score(
                    family, depth, leaf, args.seed + 2000 + i,
                    fold_fit, fold_cal, attributes, route
                )
                if fold_fitted is None:
                    loso.append({"source": source, "invalid": True})
                    continue
                fold_clf, fold_spec, _, _, fold_cal_probs = fold_fitted
                try:
                    fold_threshold, fold_cal_result, fold_cal_by_source, fold_worst = choose_source_constrained_threshold(
                        fold_cal, fold_cal_probs, args.max_fpr, args.min_source_benign
                    )
                except ValueError:
                    loso.append({"source": source, "invalid": True})
                    continue
                routed_holdout = prepare_routed(heldout, route)
                if routed_holdout:
                    hp = forest_probability(fold_clf, matrix(routed_holdout, attributes, fold_spec))
                else:
                    hp = np.asarray([], dtype=np.float64)
                heldout_probs = whole_split_probabilities(heldout, routed_holdout, hp)
                heldout_result = rates(heldout, heldout_probs >= fold_threshold)
                loso.append({
                    "source": source,
                    "threshold": fold_threshold,
                    "calibration": fold_cal_result,
                    "calibration_worst_source_fpr": fold_worst,
                    "heldout": heldout_result,
                    "routed_heldout": class_counts(routed_holdout),
                })

            valid_loso = [x for x in loso if not x.get("invalid")]
            loso_targets = bool(valid_loso) and len(valid_loso) == len(folds) and all(
                x["heldout"]["tpr"] is not None and x["heldout"]["tpr"] >= args.min_tpr and
                x["heldout"]["fpr"] is not None and x["heldout"]["fpr"] <= args.max_fpr
                for x in valid_loso
            )
            worst_tpr = min((x["heldout"]["tpr"] for x in valid_loso if x["heldout"]["tpr"] is not None), default=0.0)
            worst_fpr = max((x["heldout"]["fpr"] for x in valid_loso if x["heldout"]["fpr"] is not None), default=1.0)
            cal_target = cal_result["tpr"] >= args.min_tpr
            family_rank = 1 if family == "random_forest" else 0
            rank = (
                int(loso_targets), worst_tpr, -worst_fpr,
                int(cal_target), cal_result["tpr"], -worst_source_fpr,
                -cal_result["fpr"], -depth, leaf, route, family_rank,
            )
            row = {
                "route_min": route,
                "family": family,
                "max_depth": depth,
                "min_samples_leaf": leaf,
                "reviewer_threshold": threshold,
                "calibration": cal_result,
                "calibration_worst_source_fpr": worst_source_fpr,
                "calibration_by_source": cal_by_source,
                "loso_targets_met": loso_targets,
                "worst_holdout_tpr": worst_tpr,
                "worst_holdout_fpr": worst_fpr,
                "loso": loso,
                "routed_counts": {
                    "training": class_counts(routed_train),
                    "calibration": class_counts(routed_cal),
                },
            }
            results.append(row)
            print(
                f"route={route:.2f} {family} depth={depth} leaf={leaf}: "
                f"cal_tpr={cal_result['tpr']:.4f} cal_fpr={cal_result['fpr']:.4f} "
                f"worst_src_fpr={worst_source_fpr:.4f} "
                f"loso_tpr={worst_tpr:.4f} loso_fpr={worst_fpr:.4f} targets={loso_targets}",
                flush=True,
            )
            if best is None or rank > best[0]:
                best = (rank, clf, spec, row)

    if best is None:
        raise SystemExit("no reviewer v6.1 candidate was trained")

    _, clf, spec, selected = best
    train_routed = prepare_routed(train_rows, selected["route_min"])
    train_probs_routed = forest_probability(clf, matrix(train_routed, attributes, spec))
    train_probs = whole_split_probabilities(train_rows, train_routed, train_probs_routed)
    training_result = rates(train_rows, train_probs >= selected["reviewer_threshold"])

    payload = {
        "format_version": 5,
        "route_min": selected["route_min"],
        "reviewer_threshold": selected["reviewer_threshold"],
        "feature_names": spec["feature_names"],
        "categories": spec["categories"],
        "derived_features": list(DERIVED_FEATURES),
        "estimators": export_forest(clf),
    }
    metadata = {
        "format_version": 5,
        "experiment": "boundary_reviewer_v6_1",
        "warning": "Development candidate only; do not use for a final evaluation until runtime parity is implemented and verified.",
        "selection_policy": "v6 source-constrained calibration plus v9/v10 LOSO robustness with derived PE features",
        "max_calibration_fpr": args.max_fpr,
        "min_tpr": args.min_tpr,
        "route_candidates": routes,
        "derived_features": list(DERIVED_FEATURES),
        "selected": selected,
        "training": training_result,
        "source_reports": source_counts,
        "split_counts": split_counts,
        "parser_failures": failures,
        "candidate_results": results,
        "feature_count": len(spec["feature_names"]),
        "n_estimators": len(clf.estimators_),
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "model.json").write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("SELECTED", json.dumps(selected, sort_keys=True), flush=True)
    print(f"feature_count={len(spec['feature_names'])} derived={len(DERIVED_FEATURES)}", flush=True)
    print(f"wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
