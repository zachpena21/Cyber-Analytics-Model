#!/usr/bin/env python3
"""Search for a tiny post-reviewer v6.1 skimmer with near-zero incremental FPR.

Development-only diagnostic. Replays the selected reviewer-v6.1 v10 LOSO fold,
then evaluates a constrained family of simple export/architecture rules that can
only flip reviewer-benign samples to malicious. Rules are scored under the actual
combined pipeline FPR ceiling rather than rescue-only FPR.
"""

import argparse
import json
import sys
from itertools import product
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import (  # noqa: E402
    collect_attributes,
    forest_probability,
    rates,
    whole_split_probabilities,
)
from train_boundary_reviewer_v2 import merge_reports  # noqa: E402
from train_boundary_reviewer_v5 import source_stratified_split_allow_small  # noqa: E402
from train_boundary_reviewer_v6_1 import fit_and_score, matrix, prepare_routed  # noqa: E402
from train_modern_adapter_v2_1 import choose_source_constrained_threshold  # noqa: E402


def class_counts(rows):
    return {
        "count": len(rows),
        "benign": sum(int(r["label"]) == 0 for r in rows),
        "malicious": sum(int(r["label"]) == 1 for r in rows),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, action="append", type=Path)
    ap.add_argument("--location", required=True, action="append", type=Path)
    ap.add_argument("--source", default="reviewer-v5-v10-diagnostic")
    ap.add_argument("--route-min", type=float, default=0.20)
    ap.add_argument("--family", default="random_forest", choices=["random_forest", "extra_trees"])
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--leaf", type=int, default=4)
    ap.add_argument("--seed", type=int, default=704)
    ap.add_argument("--fold-index", type=int, default=1)
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--min-source-benign", type=int, default=100)
    ap.add_argument("--calibration-fraction", type=float, default=0.20)
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--output", type=Path,
                    default=ROOT / "validation-data" / "reviewer-v6-1-skimmer-feasibility.json")
    args = ap.parse_args()

    for p in [*args.report, *args.location]:
        if not p.exists():
            raise SystemExit(f"required input not found: {p}")

    records, _ = merge_reports(args.report)
    heldout = [r for r in records if r["source"] == args.source]
    remaining = [r for r in records if r["source"] != args.source]
    if not heldout:
        raise SystemExit(f"source not present: {args.source}")

    fold_seed = args.seed + 1000 + args.fold_index
    fit_rows, cal_rows, _ = source_stratified_split_allow_small(
        remaining, fold_seed, args.calibration_fraction
    )

    wanted = {r["sha256"] for r in records}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)

    fitted = fit_and_score(
        args.family, args.depth, args.leaf, args.seed + 2000 + args.fold_index,
        fit_rows, cal_rows, attributes, args.route_min
    )
    if fitted is None:
        raise SystemExit("selected fold could not be fit")
    clf, spec, _, _, cal_probs = fitted
    threshold, cal_result, _, worst_source_fpr = choose_source_constrained_threshold(
        cal_rows, cal_probs, args.max_fpr, args.min_source_benign
    )

    routed_holdout = prepare_routed(heldout, args.route_min)
    routed_probs = forest_probability(clf, matrix(routed_holdout, attributes, spec))
    base_probs = whole_split_probabilities(heldout, routed_holdout, routed_probs)
    base_pred = base_probs >= threshold
    base_result = rates(heldout, base_pred)

    base_by_sha = {r["sha256"]: bool(p) for r, p in zip(heldout, base_pred)}

    export_thresholds = (1, 8, 16, 32, 64, 128)
    import_maxes = (0, 1, 2, 4, 8)
    min_sections = (5, 6, 7, 8)
    min_entropy = (0.0, 6.0, 6.5, 7.0)
    min_size = (0, 100_000, 500_000, 1_000_000)
    require_no_reloc = (False, True)
    require_modern_linker = (False, True)

    results = []
    for exp_min, imp_max, sec_min, ent_min, size_min, no_reloc, modern_linker in product(
        export_thresholds, import_maxes, min_sections, min_entropy, min_size,
        require_no_reloc, require_modern_linker
    ):
        skimmer_pred = []
        rescued = []
        added_fp = []
        for row in heldout:
            attrs = attributes[row["sha256"]]
            machine = str(attrs.get("machine", ""))
            magic = str(attrs.get("magic", ""))
            exports = float(attrs.get("exports", 0) or 0)
            imports = float(attrs.get("imports", 0) or 0)
            sections = float(attrs.get("numberof_sections", 0) or 0)
            entropy = float(attrs.get("byte_entropy", 0) or 0)
            byte_size = float(attrs.get("byte_size", 0) or 0)
            has_signature = float(attrs.get("has_signature", 0) or 0)
            has_relocations = float(attrs.get("has_relocations", 0) or 0)
            linker_major = float(attrs.get("major_linker_version", 0) or 0)
            rule = (
                machine == "MACHINE_TYPES.AMD64"
                and magic == "PE32_PLUS"
                and has_signature == 0.0
                and sections >= sec_min
                and exports >= exp_min
                and imports <= imp_max
                and entropy >= ent_min
                and byte_size >= size_min
                and (not no_reloc or has_relocations == 0.0)
                and (not modern_linker or 12.0 <= linker_major <= 14.0)
            )
            final_pred = base_by_sha[row["sha256"]] or rule
            skimmer_pred.append(final_pred)
            if rule and not base_by_sha[row["sha256"]]:
                if int(row["label"]) == 1:
                    rescued.append(row["sha256"])
                else:
                    added_fp.append(row["sha256"])

        result = rates(heldout, np.asarray(skimmer_pred, dtype=bool))
        if result["fpr"] is None or result["fpr"] > args.max_fpr:
            continue
        results.append({
            "rule": {
                "export_min": exp_min,
                "import_max": imp_max,
                "section_min": sec_min,
                "entropy_min": ent_min,
                "byte_size_min": size_min,
                "require_no_relocations": no_reloc,
                "require_modern_linker_12_14": modern_linker,
                "require_amd64_pe32plus": True,
                "require_unsigned": True,
            },
            "combined": result,
            "incremental_fp": len(added_fp),
            "rescued_malware": len(rescued),
            "rescued_sha256": rescued,
            "added_fp_sha256": added_fp,
        })

    results.sort(key=lambda r: (
        r["rescued_malware"],
        -r["incremental_fp"],
        r["combined"]["tpr"] if r["combined"]["tpr"] is not None else -1.0,
        -(r["combined"]["fpr"] if r["combined"]["fpr"] is not None else 1.0),
    ), reverse=True)

    output = {
        "warning": "Development feasibility only. Do not wire runtime logic from this result without separate validation.",
        "config": {
            "source": args.source,
            "route_min": args.route_min,
            "family": args.family,
            "depth": args.depth,
            "leaf": args.leaf,
            "reviewer_threshold": threshold,
            "max_fpr": args.max_fpr,
            "fold_seed": fold_seed,
            "classifier_seed": args.seed + 2000 + args.fold_index,
        },
        "calibration": cal_result,
        "calibration_worst_source_fpr": worst_source_fpr,
        "parser_failures": failures,
        "heldout_counts": class_counts(heldout),
        "base_result": base_result,
        "searched_rule_count": len(export_thresholds) * len(import_maxes) * len(min_sections) * len(min_entropy) * len(min_size) * len(require_no_reloc) * len(require_modern_linker),
        "feasible_rule_count": len(results),
        "best_rules": results[: args.top],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(output["config"], indent=2, sort_keys=True))
    print("base:", json.dumps(base_result, sort_keys=True))
    print(f"searched={output['searched_rule_count']} feasible={len(results)}")
    for i, row in enumerate(results[:10], 1):
        print(
            f"#{i} rescued={row['rescued_malware']} added_fp={row['incremental_fp']} "
            f"tpr={row['combined']['tpr']:.4f} fpr={row['combined']['fpr']:.4f} "
            f"rule={row['rule']}"
        )
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
