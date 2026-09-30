#!/usr/bin/env python3
"""Check PE hashes against recorded reviewer training/calibration source pools.

Run from any directory; defaults target data batch v7. This checks source-pool
membership, not exact fitted membership after split and routing selection.
Exit codes: 0 = complete/no overlap, 1 = overlap, 2 = incomplete/error.
"""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ("reviewer-core-v4", 1930),
    ("reviewer-benign-final-2-v4", 1099),
    ("adapter-score-production-v4", 1036),
    ("reviewer-v5-new-batch", 1033),
    ("reviewer-v2-v6-new-batch", 1011),
    ("reviewer-v3-v8-new-batch", 1007),
    ("reviewer-v4-v9-dev", 1003),
    ("reviewer-v5-v10-diagnostic", 1020),
)
MODEL_PREFIXES = {
    "v1": 2, "v2": 4, "v3": 5, "v4": 6,
    "v5": 7, "v6": 8, "v6.1": 8, "v7": 8,
}


def archive_payloads(archive, reader):
    for entry in archive.infolist():
        if entry.is_dir():
            continue
        try:
            data = archive.read(entry, pwd=b"infected")
        except Exception as error:
            raise RuntimeError(
                f"Cannot read {entry.filename!r} from {archive.filename!r}; "
                f"ZIP method={entry.compress_type}: {error}"
            ) from error
        if data[:2] == b"MZ":
            yield data
        else:
            stream = io.BytesIO(data)
            if zipfile.is_zipfile(stream):
                stream.seek(0)
                with reader(stream) as nested:
                    yield from archive_payloads(nested, reader)


def payloads(path, reader):
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                yield from payloads(child, reader)
        return
    with path.open("rb") as stream:
        header = stream.read(2)
    if header == b"MZ":
        yield path.read_bytes()
    elif zipfile.is_zipfile(path):
        # pyzipper 0.3.6 requires a string rather than a pathlib.Path.
        with reader(str(path)) as archive:
            yield from archive_payloads(archive, reader)


def pe_hashes(path, reader):
    if not path.exists():
        raise ValueError(f"Missing dataset: {path}")
    hashes = {
        hashlib.sha256(data).hexdigest()
        for data in payloads(path, reader) if data[:2] == b"MZ"
    }
    if not hashes:
        raise ValueError(f"No PE payloads found in {path}")
    return hashes


def source_pool(report_root, name, expected_rows):
    paths = sorted(report_root.rglob(name + ".csv"))
    hashes = set()
    files = []
    complete = False
    for path in paths:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        values = [(row.get("sha256") or "").strip().lower() for row in rows]
        valid = bool(values) and all(
            len(h) == 64 and all(c in "0123456789abcdef" for c in h)
            for h in values
        )
        if valid:
            hashes.update(values)
        full_copy = valid and len(rows) == expected_rows
        complete = complete or full_copy
        files.append({"path": str(path), "rows": len(rows),
                      "valid_hashes": valid, "complete_copy": full_copy})
    return hashes, {
        "expected_rows": expected_rows, "complete": complete,
        "unique_hashes": len(hashes), "files": files,
    }


def check(malicious, benign, report_root, models, reader):
    datasets = {"malware": pe_hashes(malicious, reader),
                "benign": pe_hashes(benign, reader)}
    conflicts = datasets["malware"] & datasets["benign"]
    if conflicts:
        raise ValueError(f"{len(conflicts)} SHA-256 hashes occur in both classes")
    pools = {}
    coverage = {}
    required = max(MODEL_PREFIXES[model] for model in models)
    for name, expected in SOURCES[:required]:
        pools[name], coverage[name] = source_pool(report_root, name, expected)
    results = {}
    for model in models:
        names = [name for name, _ in SOURCES[:MODEL_PREFIXES[model]]]
        known = set().union(*(pools[name] for name in names))
        missing = [name for name in names if not coverage[name]["complete"]]
        overlap = {label: sorted(hashes & known)
                   for label, hashes in datasets.items()}
        status = "incomplete" if missing else (
            "overlap_found" if any(overlap.values()) else "no_overlap"
        )
        results[model] = {
            "status": status, "sources": names, "incomplete_sources": missing,
            "overlap_counts": {label: len(hashes)
                               for label, hashes in overlap.items()},
            "overlap_hashes": overlap,
        }
    return {
        "scope": "Recorded source pools include training and calibration; "
                 "overlap does not prove a sample was fitted after routing.",
        "paths": {"malicious": str(malicious), "benign": str(benign),
                  "reports": str(report_root)},
        "unique_pe_counts": {label: len(hashes)
                             for label, hashes in datasets.items()},
        "source_coverage": coverage, "models": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malicious", type=Path, default=ROOT / "validation-data"
                        / "malwarebazaar-v7-final-20260925")
    parser.add_argument("--benign", type=Path, default=ROOT / "validation-data"
                        / "benign-final-6.zip")
    parser.add_argument("--reports-dir", type=Path,
                        default=ROOT / "validation-data")
    parser.add_argument("--models", nargs="+", choices=MODEL_PREFIXES,
                        default=list(MODEL_PREFIXES))
    parser.add_argument("--output-prefix", type=Path,
                        default=ROOT / "validation-data" / "v7-overlap-check")
    args = parser.parse_args()
    try:
        import pyzipper
    except ImportError:
        parser.exit(2, "Missing pyzipper. Install the existing dependency with "
                    "./.venv/bin/python -m pip install pyzipper==0.3.6\n")
    try:
        report = check(args.malicious, args.benign, args.reports_dir,
                       args.models, pyzipper.AESZipFile)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"Overlap check failed: {error}\n")
    output = Path(str(args.output_prefix) + ".json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Unique PE samples:", report["unique_pe_counts"])
    for model, result in report["models"].items():
        print(f"reviewer {model}: {result['status'].upper()} "
              f"{result['overlap_counts']}")
        if result["incomplete_sources"]:
            print("  Missing/incomplete:", ", ".join(result["incomplete_sources"]))
        for label, hashes in result["overlap_hashes"].items():
            for digest in hashes[:5]:
                print(f"  {label}: {digest}")
    print("Summary:", output)
    print(report["scope"])
    statuses = {result["status"] for result in report["models"].values()}
    return 2 if "incomplete" in statuses else (1 if "overlap_found" in statuses else 0)


if __name__ == "__main__":
    sys.exit(main())
