#!/usr/bin/env python3
"""Verify and stage the supplied course model without loading its pickle."""

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path


EXPECTED_ARCHIVE_SHA256 = "c2fa463b24c4c83ea0c8e5ca3808b008da209500f48ebd5cf855c725d6263f48"
EXPECTED_MEMBER_SHA256 = "bd38cc6367a9b2f54c669e76feb38967b1101fece9d00ab8d9ba9d3fc80c5477"
EXPECTED_MEMBER_SIZE = 197_623_613
EXPECTED_MEMBER = "NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl"
OUTPUT_NAME = "NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl.gz"


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path, help="course-provided model ZIP")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "defender" / "defender" / "models",
    )
    args = parser.parse_args()

    if digest(args.archive) != EXPECTED_ARCHIVE_SHA256:
        print("error: archive SHA-256 does not match the supplied model", file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    destination = args.output_dir / OUTPUT_NAME
    temporary = destination.with_suffix(destination.suffix + ".tmp")

    checksum = hashlib.sha256()
    total = 0
    with zipfile.ZipFile(args.archive) as archive:
        names = archive.namelist()
        if names != [EXPECTED_MEMBER]:
            print(f"error: unexpected ZIP members: {names}", file=sys.stderr)
            return 2
        with archive.open(EXPECTED_MEMBER) as source, temporary.open("wb") as target:
            while block := source.read(1024 * 1024):
                checksum.update(block)
                total += len(block)
                target.write(block)

    if total != EXPECTED_MEMBER_SIZE or checksum.hexdigest() != EXPECTED_MEMBER_SHA256:
        temporary.unlink(missing_ok=True)
        print("error: extracted model failed size/SHA-256 verification", file=sys.stderr)
        return 2

    temporary.replace(destination)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
