#!/usr/bin/env python3
"""Audit reviewer-v7 errors, then fit a controlled v8 data-expansion baseline.

Run `audit` first, then `train`. Both commands run locally without Docker.
Original models and reports are read-only. Malware is parsed in memory, never
executed or extracted to disk. All results are development results.
"""

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "defender"))
from defender.models.boundary_reviewer import (  # noqa: E402
    BoundaryReviewer, SCORE_FEATURES, _byte_entropy,
)
from check_data_overlap import payloads  # noqa: E402

OLD_SOURCES = (
    "reviewer-core-v4", "reviewer-benign-final-2-v4",
    "adapter-score-production-v4", "reviewer-v5-new-batch",
    "reviewer-v2-v6-new-batch", "reviewer-v3-v8-new-batch",
    "reviewer-v4-v9-dev", "reviewer-v5-v10-diagnostic",
)
OLD_COUNTS = dict(zip(OLD_SOURCES, (1930, 1099, 1036, 1033, 1011, 1007, 1003, 1020)))
AUDIT_COUNTS = {"batch-v7": (1000, 8), "batch-v8": (1000, 7),
                "batch-v9": (1000, 3), "batch-v10": (1000, 20), "batch-v11": (589, 13)}
AUDIT_NAMES = {
    "batch-v7": ("reviewer-v7-all-v7.csv",),
    "batch-v8": ("reviewer-v7-v8-diagnostic.csv",),
    "batch-v9": ("reviewer-v7-v9-diagnostic.csv",),
    "batch-v10": ("reviewer-v7-v10-diagnostic.csv",),
    "batch-v11": ("reviewer-v7-v11-fresh(1).csv", "reviewer-v7-v11-fresh.csv"),
}
CONFIG = dict(n_estimators=128, learning_rate=0.1, max_depth=3,
              min_samples_leaf=8, max_features="sqrt", subsample=1.0)


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temp.replace(path)


def boolean(value):
    if str(value).strip().lower() in ("1", "true", "yes", "on"):
        return 1.0
    if str(value).strip().lower() in ("0", "false", "no", "off", "", "none"):
        return 0.0
    raise ValueError(f"Invalid boolean: {value!r}")


def read_report(path, source, audit=False):
    required = {"sha256", "label", *SCORE_FEATURES}
    if audit:
        required |= {"current_prediction", "reviewer_probability", "reviewer_threshold",
                     "reviewer_routed", "adapter_threshold"}
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if required - set(reader.fieldnames or ()):
            raise ValueError(f"Missing columns in {path}: {sorted(required - set(reader.fieldnames or ()))}")
        records = {}
        for raw in reader:
            sha = raw["sha256"].strip().lower()
            if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                raise ValueError(f"Invalid SHA-256 in {path}")
            row = dict(sha256=sha, label=int(raw["label"]), source=source)
            if row["label"] not in (0, 1):
                raise ValueError(f"Invalid label for {sha}")
            for key in SCORE_FEATURES:
                row[key] = float(raw[key]) if key.endswith("probability") else boolean(raw[key])
            if any(not math.isfinite(row[k]) or not 0 <= row[k] <= 1 for k in SCORE_FEATURES):
                raise ValueError(f"Invalid component value for {sha}")
            if audit:
                for key in ("reviewer_probability", "reviewer_threshold", "adapter_threshold"):
                    row[key] = float(raw[key]) if raw[key] else None
                row["reviewer_routed"] = bool(boolean(raw["reviewer_routed"]))
                row["current_prediction"] = int(raw["current_prediction"])
                if row["current_prediction"] not in (0, 1):
                    raise ValueError(f"Invalid prediction for {sha}")
                for key in ("reviewer_threshold", "adapter_threshold"):
                    if row[key] is None or not math.isfinite(row[key]) or not 0 <= row[key] <= 1:
                        raise ValueError(f"Invalid {key} for {sha}")
                score = row["reviewer_probability"]
                if row["reviewer_routed"] and (score is None or not math.isfinite(score) or not 0 <= score <= 1):
                    raise ValueError(f"Invalid routed score for {sha}")
                predicted = int(score >= row["reviewer_threshold"]) if row["reviewer_routed"] else int(row["adapter_probability"] >= row["adapter_threshold"])
                if predicted != row["current_prediction"]:
                    raise ValueError(f"Recorded prediction disagrees with recorded policy for {sha}")
            if sha in records and records[sha] != row:
                raise ValueError(f"Conflicting duplicate SHA in {path}: {sha}")
            records[sha] = row
    if not records:
        raise ValueError(f"Empty report: {path}")
    return list(records.values())


def find_report(directory, names):
    for name in names:
        direct = directory / name
        if direct.exists():
            return direct
        matches = sorted(directory.rglob(name))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"Multiple copies of {name}; put the intended report in {directory}")
    raise ValueError(f"Missing report in {directory}: {' or '.join(names)}")


def load_audit(directory):
    rows, paths, seen = [], {}, set()
    for source, names in AUDIT_NAMES.items():
        path = find_report(directory, names)
        batch = read_report(path, source, audit=True)
        actual = (sum(r["label"] == 0 for r in batch), sum(r["label"] == 1 for r in batch))
        if actual != AUDIT_COUNTS[source]:
            raise ValueError(f"Incomplete/wrong {source} report: expected benign/malware {AUDIT_COUNTS[source]}, found {actual}")
        overlap = seen & {r["sha256"] for r in batch}
        if overlap:
            raise ValueError(f"Audit batches overlap: {source}, {len(overlap)} samples")
        seen.update(r["sha256"] for r in batch)
        rows.extend(batch)
        paths[source] = str(path)
    return rows, paths


def vector(row, cached):
    return [row[k] for k in SCORE_FEATURES] + cached["structural_vector"]


def normalize_cached_flags(cached, feature_names):
    """Restore Docker/LIEF 0.11.5 flag spelling without reparsing PE bytes.

    Later LIEF versions add CHARACTERISTICS. to header flags and may render
    DLL flags as decimal integers. V7 includes their text lengths as features.
    Keep raw attributes for provenance; change only the six flag-text features.
    Flag values: https://lief.re/doc/latest/formats/pe/python.html
    """
    dll_names = {
        32: "HIGH_ENTROPY_VA", 64: "DYNAMIC_BASE", 128: "FORCE_INTEGRITY",
        256: "NX_COMPAT", 512: "NO_ISOLATION", 1024: "NO_SEH",
        2048: "NO_BIND", 4096: "APPCONTAINER", 8192: "WDM_DRIVER",
        16384: "GUARD_CF", 32768: "TERMINAL_SERVER_AWARE",
    }
    changed = False
    attributes = cached["attributes"]
    for field in ("characteristics_list", "dll_characteristics_list"):
        if field not in attributes:
            continue
        tokens = str(attributes[field] or "").split()
        if field == "characteristics_list":
            tokens = [t.removeprefix("HEADER_CHARACTERISTICS.").removeprefix("CHARACTERISTICS.")
                      for t in tokens]
            # LIEF 0.11.5 EnumToString.cpp uses this historical spelling.
            tokens = ["CHARA_32BIT_MACHINE" if t == "NEED_32BIT_MACHINE" else t
                      for t in tokens]
        else:
            tokens = [t.removeprefix("DLL_CHARACTERISTICS.") for t in tokens]
            tokens = [dll_names.get(int(t), t) if t.isdecimal() else t for t in tokens]
        text = " ".join(tokens)
        for suffix, value in (("token_count", len(tokens)),
                              ("unique_count", len(set(tokens))),
                              ("character_count", len(text))):
            name = f"{field}_{suffix}"
            index = feature_names.index(name) - len(SCORE_FEATURES)
            if cached["structural_vector"][index] != float(value):
                cached["structural_vector"][index] = float(value)
                changed = True
    return changed


def normalize_cached_exports(cached, feature_names):
    """Match LIEF 0.11.5 Parser.cpp's MAX_EXPORT_NAME_SIZE = 300 bytes.

    That parser removes oversized named export entries; exported_functions
    subsequently includes only entries with nonempty names. Preserve the raw
    extraction while correcting text, counts, and dependent reviewer features.
    """
    attributes = cached["attributes"]
    names = str(attributes.get("exports_list", "") or "").split()
    kept = [name for name in names if len(name.encode("utf-8")) <= 300]
    if len(kept) == len(names):
        return False
    if len(names) != float(attributes.get("exports", 0)):
        raise ValueError("Cannot safely normalize export names: count/text mismatch")
    cached.setdefault("raw_attributes", dict(attributes))
    attributes = dict(attributes, exports=len(kept), exports_list=" ".join(kept))
    cached["attributes"] = attributes
    sections = float(attributes.get("numberof_sections", 0))
    updates = {
        "exports": len(kept),
        "exports_list_token_count": len(kept),
        "exports_list_unique_count": len(set(kept)),
        "exports_list_character_count": len(attributes["exports_list"]),
        "exports_per_section": len(kept) / sections if sections > 0 else 0.,
        "has_exports": float(bool(kept)),
        "large_export_table": float(len(kept) >= 32),
    }
    for name, value in updates.items():
        if name in feature_names:
            cached["structural_vector"][feature_names.index(name) - len(SCORE_FEATURES)] = float(value)
    return True


def needs_import_refresh(sample):
    """Old caches lack delay-import provenance; refresh possible aggregates."""
    attributes = sample["attributes"]
    return (not sample.get("legacy_imports_compatible", False)
            and len(str(attributes.get("libraries", "") or "").split())
            > float(attributes.get("imports", 0)))


def legacy_import_attributes(extractor, attributes):
    """Match LIEF 0.11.5's ordinary-import-only aggregate text.

    LIEF 1.0 appends delayed imports to libraries/imported_functions. Remove
    that exact suffix, retaining ordinary ordinal names resolved by LIEF.
    Do not rebuild function names from raw entries (which loses ordinals).
    """
    attributes = dict(attributes)
    if not needs_import_refresh(dict(attributes=attributes)):
        return attributes
    binary = extractor.lief_binary
    ordinary = [entry.name for entry in binary.imports]
    delayed = list(binary.delay_imports)
    delayed_libraries = [entry.name for entry in delayed]
    aggregate = str(attributes.get("libraries", "") or "")
    if aggregate != " ".join(ordinary + delayed_libraries):
        raise ValueError("LIEF library aggregation differs from ordinary + delayed imports")
    delayed_names = [entry.name for library in delayed for entry in library.entries
                     if not entry.is_ordinal and entry.name]
    functions = str(attributes.get("functions", "") or "")
    suffix = " ".join(delayed_names)
    if suffix:
        if functions == suffix:
            functions = ""
        elif functions.endswith(" " + suffix):
            functions = functions[:-(len(suffix) + 1)]
        else:
            raise ValueError("LIEF function aggregation lacks expected delayed-import suffix")
    attributes["libraries"] = " ".join(ordinary)
    attributes["functions"] = functions
    return attributes


def collect_features(rows, reviewer, model_path, locations, cache_path, max_bytes):
    """Cache structural features, not labels or upstream model scores."""
    extractor_path = ROOT / "defender/defender/models/attribute_extractor.py"
    runtime_path = ROOT / "defender/defender/models/boundary_reviewer.py"
    fingerprint = hashlib.sha256(extractor_path.read_bytes() + runtime_path.read_bytes()).hexdigest()
    try:
        lief_version = importlib.metadata.version("lief")
    except importlib.metadata.PackageNotFoundError:
        lief_version = None
    provenance = dict(extractor_runtime_sha256=fingerprint, lief_version=lief_version,
                      feature_names=list(reviewer.feature_names), max_bytes=max_bytes)
    cached = {}
    if cache_path.exists():
        previous = json.loads(cache_path.read_text(encoding="utf-8"))
        if previous.get("provenance") == provenance:
            cached = previous["samples"]
        else:
            print("Feature cache specification changed; rebuilding.", flush=True)
    required = {r["sha256"] for r in rows}
    refresh = {sha for sha in required & set(cached) if needs_import_refresh(cached[sha])}
    wanted = (required - set(cached)) | refresh
    if refresh:
        print(f"Refreshing {len(refresh)} cached samples for ordinary-import compatibility.",
              flush=True)
    if wanted:
        import pyzipper
        from defender.models.attribute_extractor import PEAttributeExtractor
        zeros = {k: 0.0 for k in SCORE_FEATURES}
        needed = len(wanted)
        failures = []
        archive_warnings = []

        def record_archive_warning(details):
            archive_warnings.append(details)
            # Preserve diagnostics and features even if a later member fails.
            if len(archive_warnings) <= 5 or len(archive_warnings) % 100 == 0:
                dump(cache_path.parent / "archive-read-warnings.json",
                     dict(warnings=archive_warnings))
                dump(cache_path, dict(provenance=provenance, samples=cached))
            if len(archive_warnings) <= 5:
                print(f"Skipping unreadable ZIP entry: {details['archive']} "
                      f"member={details.get('member')!r}: {details['message']}",
                      flush=True)

        for location in locations:
            if not location.exists():
                raise ValueError(f"Missing PE location: {location}")
            for bytez in payloads(location, pyzipper.AESZipFile,
                                  on_error=record_archive_warning):
                if len(bytez) > max_bytes:
                    continue
                sha = hashlib.sha256(bytez).hexdigest()
                if sha not in wanted:
                    continue
                try:
                    extractor = PEAttributeExtractor(bytez)
                    raw_attributes = extractor.extract()
                    attributes = legacy_import_attributes(extractor, raw_attributes)
                    full_vector = reviewer._vectorize(attributes, bytez, zeros)
                    cached[sha] = dict(structural_vector=full_vector[len(SCORE_FEATURES):],
                                       attributes=attributes, raw_attributes=raw_attributes,
                                       legacy_imports_compatible=True)
                    wanted.remove(sha)
                except Exception as error:
                    failures.append(dict(sha256=sha, error=type(error).__name__, message=str(error)))
                if (needed - len(wanted)) % 100 == 0:
                    print(f"Extracted {needed - len(wanted)}/{needed} additional samples", flush=True)
                    dump(cache_path, dict(provenance=provenance, samples=cached))
                if not wanted:
                    break
            if not wanted:
                break
        dump(cache_path, dict(provenance=provenance, samples=cached))
        if archive_warnings:
            dump(cache_path.parent / "archive-read-warnings.json",
                 dict(warnings=archive_warnings))
            print(f"Logged {len(archive_warnings)} unreadable archive entries; "
                  "required SHA coverage is still enforced. "
                  "See archive-read-warnings.json.", flush=True)
        if wanted:
            dump(cache_path.parent / "extraction-failures.json",
                 dict(missing=sorted(wanted), parser_failures=failures,
                      archive_read_warnings=archive_warnings))
            raise ValueError(f"Could not find/parse {len(wanted)} required samples. See extraction-failures.json; first SHA: {sorted(wanted)[0]}")
    normalized = 0
    for sample in cached.values():
        flags_changed = normalize_cached_flags(sample, reviewer.feature_names)
        exports_changed = normalize_cached_exports(sample, reviewer.feature_names)
        normalized += flags_changed or exports_changed
    if normalized:
        dump(cache_path, dict(provenance=provenance, samples=cached))
        print(f"Restored legacy PE features for {normalized} cached samples; "
              "raw attributes preserved. Full score parity is still required.", flush=True)
    return cached


def model_probabilities(payload, X):
    raw = np.full(len(X), float(payload["initial_raw_score"]))
    for tree in payload["estimators"]:
        raw += float(payload["learning_rate"]) * np.array([
            BoundaryReviewer._tree_leaf(tree, x, "raw_value") for x in X
        ])
    return np.exp(-np.logaddexp(0.0, -raw))


def metrics(rows, predictions):
    y = np.array([r["label"] for r in rows])
    pred = np.asarray(predictions, dtype=bool)
    n0, n1 = int(sum(y == 0)), int(sum(y == 1))
    fp, fn = int(sum(pred & (y == 0))), int(sum(~pred & (y == 1)))
    return dict(count=len(rows), benign=n0, malicious=n1, fp=fp, fn=fn,
                fpr=fp / n0 if n0 else None, tpr=1 - fn / n1 if n1 else None)


def audit(rows, cached, reviewer, payload, output):
    X = np.array([vector(r, cached[r["sha256"]]) for r in rows])
    probabilities = model_probabilities(payload, X)
    checked = [i for i, r in enumerate(rows) if r["reviewer_routed"]]
    error = max((abs(probabilities[i] - rows[i]["reviewer_probability"]) for i in checked), default=0)
    versions = {}
    for package in ("lief", "numpy", "scikit-learn", "pandas", "pyzipper"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    requirements = ROOT / "defender/docker-requirements.txt"
    docker_pins = {}
    if requirements.exists():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            if "==" in line and not line.lstrip().startswith("#"):
                name, version = line.strip().split("==", 1)
                docker_pins[name] = version
    by_batch_parity = {}
    for source in sorted({r["source"] for r in rows}):
        indices = [i for i in checked if rows[i]["source"] == source]
        differences = [abs(float(probabilities[i]) - rows[i]["reviewer_probability"])
                       for i in indices]
        by_batch_parity[source] = dict(
            rows=sum(r["source"] == source for r in rows),
            routed_checked=len(indices),
            score_mismatches=sum(d > 1e-8 for d in differences),
            max_abs_error=max(differences, default=0.0),
            median_abs_error=float(np.median(differences)) if differences else None,
            mean_abs_error=float(np.mean(differences)) if differences else None,
            threshold_mismatches=sum(abs(rows[i]["reviewer_threshold"] - reviewer.threshold) > 1e-12
                                     for i in indices),
            decision_changes=sum(int(probabilities[i] >= reviewer.threshold) != rows[i]["current_prediction"]
                                 for i in indices),
            recorded_thresholds=sorted({rows[i]["reviewer_threshold"] for i in indices}),
        )
    worst = sorted(checked, key=lambda i: (-abs(float(probabilities[i]) - rows[i]["reviewer_probability"]),
                                          rows[i]["sha256"]))[:30]
    examples = [
        dict(sha256=rows[i]["sha256"], source=rows[i]["source"], label=rows[i]["label"],
             recorded_score=rows[i]["reviewer_probability"],
             local_score=float(probabilities[i]),
             absolute_error=abs(float(probabilities[i]) - rows[i]["reviewer_probability"]),
             recorded_prediction=rows[i]["current_prediction"],
             local_prediction=int(probabilities[i] >= reviewer.threshold),
             components={k: rows[i][k] for k in SCORE_FEATURES},
             local_features=dict(zip(reviewer.feature_names, map(float, X[i]))),
             pe_attributes=cached[rows[i]["sha256"]]["attributes"])
        for i in worst if abs(float(probabilities[i]) - rows[i]["reviewer_probability"]) > 1e-8
    ]
    threshold_mismatch = any(abs(rows[i]["reviewer_threshold"] - reviewer.threshold) > 1e-12 for i in checked)
    diagnostics = dict(
        passed=bool(error <= 1e-8 and not threshold_mismatch),
        max_abs_error=float(error), python_version=sys.version.split()[0],
        local_dependency_versions=versions, docker_dependency_pins=docker_pins,
        dependency_differences={name: dict(local=versions[name], docker=docker_pins[name])
                                for name in versions if name in docker_pins and versions[name] != docker_pins[name]},
        feature_count=len(reviewer.feature_names), feature_names=list(reviewer.feature_names),
        model_route_min=reviewer.route_min, model_threshold=reviewer.threshold,
        model_stage_count=len(payload["estimators"]),
        by_batch=by_batch_parity, largest_mismatches=examples,
        explanation="Descriptive diagnostics only. A dependency difference suggests a possible cause; it does not establish it. Recorded scores are not replaced and training remains blocked on parity failure.",
    )
    inputs_path = output / "inputs.json"
    if inputs_path.exists():
        diagnostics["inputs"] = json.loads(inputs_path.read_text(encoding="utf-8"))
    dump(output / "parity-diagnostics.json", diagnostics)
    if not diagnostics["passed"]:
        for source, result in by_batch_parity.items():
            print(f"Parity {source}: {result['score_mismatches']}/{result['routed_checked']} "
                  f"score mismatches, max_abs={result['max_abs_error']:.6f}, "
                  f"decision changes={result['decision_changes']}", flush=True)
        raise ValueError(f"Frozen v7 model does not reproduce reports (max score error {error:.3g}). "
                         "Send parity-diagnostics.json; training remains blocked until the mismatch is resolved.")
    # Descriptive distance only: log-transform PE counts, then robust scaling.
    S = np.log1p(np.maximum(X[:, len(SCORE_FEATURES):], 0))
    scale = np.percentile(S, 75, axis=0) - np.percentile(S, 25, axis=0)
    fallback = np.std(S, axis=0)
    scale = np.where(scale > 1e-9, scale, np.where(fallback > 1e-9, fallback, 1.0))
    Z = (S - np.median(S, axis=0)) / scale
    names = list(reviewer.feature_names)[len(SCORE_FEATURES):]
    errors = []
    correct = np.array([r["label"] == r["current_prediction"] for r in rows])
    for i, row in enumerate(rows):
        if correct[i]:
            continue
        distances = np.mean(np.minimum(np.abs(Z - Z[i]), 10.0), axis=1)
        comparisons = {}
        for label, name in ((row["label"], "same_class_correct"), (1 - row["label"], "opposite_class_correct")):
            choices = [j for j, r in enumerate(rows) if correct[j] and r["label"] == label]
            neighbors = sorted(choices, key=lambda j: (distances[j], rows[j]["sha256"]))[:10]
            comparisons[name] = [dict(sha256=rows[j]["sha256"], source=rows[j]["source"],
                                      distance=float(distances[j]),
                                      reviewer_probability=rows[j]["reviewer_probability"]) for j in neighbors]
            if name == "same_class_correct" and neighbors:
                med = np.median(X[neighbors, len(SCORE_FEATURES):], axis=0)
                standardized_difference = np.abs(Z[i] - np.median(Z[neighbors], axis=0))
                comparisons["largest_neighbor_feature_differences"] = [
                    dict(feature=names[k], value=float(X[i, k + len(SCORE_FEATURES)]),
                         correct_neighbor_median=float(med[k]))
                    for k in np.argsort(-standardized_difference, kind="stable")[:12]
                ]
        errors.append(dict(**row, error_type="false_negative" if row["label"] else "false_positive",
                           pe_attributes=cached[row["sha256"]]["attributes"], comparisons=comparisons))
    by_batch = {s: metrics([r for r in rows if r["source"] == s],
                          [r["current_prediction"] for r in rows if r["source"] == s])
                for s in sorted({r["source"] for r in rows})}
    zone_rows = defaultdict(list)
    for row in rows:
        if row["adapter_probability"] >= row["adapter_threshold"] and row["current_prediction"] == 0:
            zone_rows["adapter_malware_reviewer_benign"].append(row)
        if not row["base_trigger_adjusted"] and row["adapter_probability"] < row["adapter_threshold"] and row["current_prediction"] == 1:
            zone_rows["base_adapter_benign_reviewer_malware"].append(row)
        if row["reviewer_probability"] is not None and abs(row["reviewer_probability"] - reviewer.threshold) <= .1:
            zone_rows["reviewer_within_0.10_of_threshold"].append(row)
    zones = {name: metrics(group, [r["current_prediction"] for r in group]) for name, group in zone_rows.items()}
    with (output / "features.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["sha256", "source", "label", "current_prediction", "recorded_reviewer_probability", *reviewer.feature_names])
        for row, x in zip(rows, X):
            writer.writerow([row["sha256"], row["source"], row["label"], row["current_prediction"], row["reviewer_probability"], *x])
    result = dict(scope="Descriptive development audit. Neighbors are structural similarities, not malware-family assignments or causal explanations.",
                  runtime_score_parity_max_abs_error=float(error), by_batch=by_batch,
                  zones=zones, errors=errors,
                  warning="Zones overlap. Train a future skimmer on all routed examples, with leakage-safe upstream predictions; these v7 scores are not out-of-fold training scores.")
    dump(output / "error-audit.json", result)
    print(json.dumps(by_batch, indent=2), flush=True)
    print(f"Audit contains {len(errors)} errors. Send error-audit.json for review.", flush=True)


def split(rows, seed=704, fraction=.2):
    """Match the existing v5/v7 source/class split, including singleton handling."""
    grouped = defaultdict(list)
    for r in rows:
        grouped[(r["source"], r["label"])].append(r)
    train, cal = [], []
    for index, key in enumerate(sorted(grouped)):
        group = sorted(grouped[key], key=lambda r: r["sha256"])
        order = np.arange(len(group))
        np.random.RandomState(seed + index).shuffle(order)
        n = 0 if len(group) == 1 else 1 if len(group) < 5 else min(len(group) - 1, max(1, round(len(group) * fraction)))
        reserved = set(order[:n])
        train.extend(r for i, r in enumerate(group) if i not in reserved)
        cal.extend(r for i, r in enumerate(group) if i in reserved)
    rng = np.random.RandomState(seed)
    rng.shuffle(train)
    rng.shuffle(cal)
    return train, cal


def preserved_split(rows):
    old = [r for r in rows if r["source"] in OLD_SOURCES]
    new = [r for r in rows if r["source"] not in OLD_SOURCES]
    train, cal = split(old)
    extra_train, extra_cal = split(new, seed=1704)
    return train + extra_train, cal + extra_cal


def merge_training(directory, audit_rows):
    records, reports = {}, {}
    for source in OLD_SOURCES:
        path = find_report(directory, (source + ".csv",))
        reports[source] = str(path)
        batch = read_report(path, source)
        if len(batch) != OLD_COUNTS[source]:
            raise ValueError(f"Incomplete original source {source}: expected {OLD_COUNTS[source]} unique report rows, found {len(batch)}")
        for row in batch:
            sha = row["sha256"]
            previous = records.get(sha)
            if previous and any(previous[k] != row[k] for k in ("label", *SCORE_FEATURES)):
                raise ValueError(f"Conflicting label/components across reports for {sha}")
            records.setdefault(sha, row)
    for row in audit_rows:
        if row["source"] not in ("batch-v7", "batch-v11"):
            continue
        sha = row["sha256"]
        if sha in records:
            raise ValueError(f"New development batch overlaps existing training pool: {sha}")
        records[sha] = {k: row[k] for k in ("sha256", "source", "label", *SCORE_FEATURES)}
    return list(records.values()), reports


def fit(rows, cached, route):
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.utils.class_weight import compute_sample_weight
    routed = [r for r in rows if r["adapter_probability"] >= route]
    y = np.array([r["label"] for r in routed])
    if set(y) != {0, 1}:
        raise ValueError("Both classes are required in routed training data")
    X = np.array([vector(r, cached[r["sha256"]]) for r in routed])
    clf = GradientBoostingClassifier(**CONFIG, random_state=704)
    clf.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    return clf


def predict(clf, rows, cached, route):
    probabilities = np.zeros(len(rows))
    indices = [i for i, r in enumerate(rows) if r["adapter_probability"] >= route]
    if indices:
        probabilities[indices] = clf.predict_proba(np.array([vector(rows[i], cached[rows[i]["sha256"]]) for i in indices]))[:, 1]
    return probabilities


def calibrate(rows, probabilities, max_fpr=.01):
    best = None
    unique = np.unique(probabilities)
    for threshold in np.unique(np.concatenate((unique, np.nextafter(unique, np.inf), [1.0]))):
        if threshold <= 0 or threshold > 1:
            continue
        preds = probabilities >= threshold
        overall = metrics(rows, preds)
        per_source = {s: metrics([r for r in rows if r["source"] == s],
                                [preds[i] for i, r in enumerate(rows) if r["source"] == s])
                      for s in sorted({r["source"] for r in rows})}
        constrained = [m["fpr"] for m in per_source.values() if m["benign"] >= 100]
        worst = max(constrained, default=0)
        if overall["fpr"] <= max_fpr + 1e-15 and worst <= max_fpr + 1e-15:
            rank = (overall["tpr"], -worst, -overall["fpr"], float(threshold))
            if best is None or rank > best[0]:
                best = (rank, float(threshold), overall, per_source)
    if best is None:
        raise ValueError("No valid runtime threshold <=1 meets the calibration FPR caps")
    return best[1:]


def export(clf, frozen, threshold):
    trees = []
    for stage in clf.estimators_:
        t = stage[0].tree_
        trees.append(dict(children_left=t.children_left.tolist(), children_right=t.children_right.tolist(),
                          feature=t.feature.tolist(), threshold=t.threshold.tolist(), raw_value=t.value[:, 0, 0].tolist()))
    return dict(format_version=6, model_type="gradient_boosting", route_min=frozen["route_min"],
                reviewer_threshold=threshold, learning_rate=float(clf.learning_rate),
                initial_raw_score=float(clf._raw_predict_init(np.zeros((1, clf.n_features_in_)))[0, 0]),
                feature_names=frozen["feature_names"], categories=frozen["categories"],
                derived_features=frozen["derived_features"], estimators=trees)


def train(rows, cached, frozen, output, input_reports):
    route = frozen["route_min"]
    train_rows, cal_rows = preserved_split(rows)
    if {r["sha256"] for r in train_rows} & {r["sha256"] for r in cal_rows}:
        raise ValueError("Training/calibration overlap")
    # Check reconstruction before calling the expanded-data experiment a v7 baseline.
    original_fit = [r for r in train_rows if r["source"] in OLD_SOURCES]
    old_clf = fit(original_fit, cached, route)
    Xold = np.array([vector(r, cached[r["sha256"]]) for r in original_fit])
    reconstruction_error = float(np.max(np.abs(old_clf.predict_proba(Xold)[:, 1] - model_probabilities(frozen, Xold))))
    if reconstruction_error > 1e-8:
        raise ValueError(f"Original v7 fit cannot be reconstructed (max error {reconstruction_error:.3g}); check original reports/model/dependencies before training")
    clf = fit(train_rows, cached, route)
    probabilities = predict(clf, cal_rows, cached, route)
    threshold, calibrated, per_source = calibrate(cal_rows, probabilities)
    payload = export(clf, frozen, threshold)
    Xall = np.array([vector(r, cached[r["sha256"]]) for r in rows])
    parity = float(np.max(np.abs(clf.predict_proba(Xall)[:, 1] - model_probabilities(payload, Xall))))
    if parity > 1e-10:
        raise ValueError(f"Export parity failed: {parity}")
    # Freeze configuration before source holdouts: no candidate ranking on these results.
    folds, oof = [], []
    for source in ("batch-v7", "batch-v11", "reviewer-v4-v9-dev", "reviewer-v5-v10-diagnostic"):
        heldout = [r for r in rows if r["source"] == source]
        remaining = [r for r in rows if r["source"] != source]
        fold_fit, fold_cal = preserved_split(remaining)
        fold_clf = fit(fold_fit, cached, route)
        fold_t, fold_cal_metrics, _ = calibrate(fold_cal, predict(fold_clf, fold_cal, cached, route))
        hp = predict(fold_clf, heldout, cached, route)
        result = metrics(heldout, hp >= fold_t)
        folds.append(dict(source=source, threshold=fold_t, heldout=result, calibration=fold_cal_metrics))
        print(f"Held-out {source}: {result}", flush=True)
        for r, probability in zip(heldout, hp):
            oof.append(dict(**r, reviewer_routed=r["adapter_probability"] >= route,
                            reviewer_probability=float(probability) if r["adapter_probability"] >= route else None,
                            reviewer_threshold=fold_t, current_prediction=int(probability >= fold_t)))
    dump(output / "model.json", payload)
    dump(output / "split_manifest.json", dict(training=[r["sha256"] for r in train_rows],
         calibration=[r["sha256"] for r in cal_rows], old_source_split_preserved=True))
    metadata = dict(experiment="boundary_reviewer_v8_data_baseline", development_only=True,
                    warning="Source holdouts assess this fixed reviewer configuration, not the entire upstream pipeline. No skimmer is fitted; archived v7 scores must not be used as leakage-safe skimmer training scores.",
                    configuration=CONFIG, seed=704, new_source_split_seed=1704, calibration_fraction=.2,
                    sklearn_version=importlib.metadata.version("scikit-learn"), numpy_version=np.__version__,
                    route_min=route, original_threshold=frozen["reviewer_threshold"], reviewer_threshold=threshold,
                    feature_names=frozen["feature_names"], source_counts=dict(Counter(r["source"] for r in rows)),
                    input_reports=input_reports, original_v7_reconstruction_error=reconstruction_error,
                    runtime_parity_max_abs_error=parity, calibration=calibrated, calibration_by_source=per_source,
                    calibration_at_original_threshold=metrics(cal_rows, probabilities >= frozen["reviewer_threshold"]),
                    leave_one_source_out=folds)
    dump(output / "metadata.json", metadata)
    with (output / "reviewer-source-heldout-scores.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(oof[0]))
        writer.writeheader()
        writer.writerows(oof)
    print(f"V8 baseline written to {output}; threshold={threshold:.9f}; calibration={calibrated}", flush=True)
    print("Send metadata.json and error-audit.json. Keep production v7 unchanged pending review.", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=("audit", "train"))
    ap.add_argument("--reports-dir", type=Path, default=ROOT / "validation-data")
    ap.add_argument("--location", type=Path, action="append", help="PE roots/ZIPs; default: validation-data")
    ap.add_argument("--v7-model", type=Path, default=ROOT / "defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json")
    ap.add_argument("--output", type=Path, default=ROOT / "validation-data/reviewer-v8-development")
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    args = ap.parse_args()
    try:
        frozen = json.loads(args.v7_model.read_text(encoding="utf-8"))
        reviewer = BoundaryReviewer(args.v7_model)
        if reviewer.model_type != "gradient_boosting" or abs(reviewer.route_min - .15) > 1e-12:
            raise ValueError("Expected frozen reviewer v7 GBDT with its original route_min=0.15")
        args.output.mkdir(parents=True, exist_ok=True)
        audit_rows, paths = load_audit(args.reports_dir)
        rows = audit_rows
        if args.command == "train":
            rows, old_paths = merge_training(args.reports_dir, audit_rows)
            paths.update(old_paths)
        cached = collect_features(rows, reviewer, args.v7_model, args.location or [args.reports_dir],
                                  args.output / "feature-cache.json", args.max_bytes)
        dump(args.output / "inputs.json", dict(reports=paths, frozen_model=str(args.v7_model),
             frozen_model_sha256=hashlib.sha256(args.v7_model.read_bytes()).hexdigest()))
        # Always validate the audit against the frozen model before fitting.
        audit(audit_rows, cached, reviewer, frozen, args.output)
        if args.command == "train":
            train(rows, cached, frozen, args.output, paths)
    except (ValueError, OSError, ImportError, RuntimeError) as error:
        ap.exit(2, f"V8 workflow stopped: {error}\n")


if __name__ == "__main__":
    main()
