#!/usr/bin/env python3
"""Safely collect MalShare PE samples for defensive validation.

Sample responses are held in memory, validated, and written directly into
AES-encrypted ZIP archives.  The script never writes a plaintext executable.
Run it only inside an approved, disposable malware-research VM.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import struct
import sys
import time
from pathlib import Path

import pyzipper
import requests


API_URL = "https://malshare.com/api.php"
ZIP_PASSWORD = b"infected"
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{32})?$")
DEFAULT_MAX_SAMPLE_BYTES = 16 * 1024 * 1024


def sample_count(value):
    value = int(value)
    if not 1 <= value <= 500:
        raise argparse.ArgumentTypeError("count must be between 1 and 500")
    return value


def api_get(session, api_key, params, *, stream=False, timeout=(10, 120)):
    query = {"api_key": api_key, **params}
    try:
        response = session.get(
            API_URL,
            params=query,
            headers={"User-Agent": "Cyber-Analytics-Model defensive validation"},
            stream=stream,
            timeout=timeout,
        )
    except requests.RequestException as error:
        # requests exceptions may contain the prepared URL (and therefore key).
        raise RuntimeError("MalShare request failed") from error
    if response.status_code != 200:
        raise RuntimeError(f"MalShare returned HTTP {response.status_code}")
    return response


def extract_hashes(payload):
    """Normalize the list/dict variants returned by MalShare endpoints."""
    if isinstance(payload, dict):
        for key in ("data", "samples", "results", "hashes"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        raise RuntimeError("MalShare returned an unexpected hash-list format")

    hashes = []
    for item in payload:
        candidates = [item] if isinstance(item, str) else []
        if isinstance(item, dict):
            for key in ("sha256", "SHA256", "sha1", "SHA1", "md5", "MD5", "hash"):
                if item.get(key):
                    candidates.append(str(item[key]))
        for candidate in candidates:
            candidate = candidate.strip().lower()
            if HASH_RE.fullmatch(candidate):
                hashes.append(candidate)
                break
    # Preserve API order while removing duplicates.
    return list(dict.fromkeys(hashes))


def query_hashes(session, api_key, file_type):
    response = api_get(
        session,
        api_key,
        {"action": "type", "type": file_type},
        timeout=(10, 60),
    )
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as error:
        # Do not print server response bodies because an upstream error page
        # could reflect the API key supplied in the query string.
        raise RuntimeError("MalShare hash query returned non-JSON data") from error
    hashes = extract_hashes(payload)
    if not hashes:
        raise RuntimeError("MalShare returned no usable hashes for the requested type")
    return hashes


def read_limited(response, max_bytes):
    content = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        content.extend(chunk)
        if len(content) > max_bytes:
            raise RuntimeError(f"sample exceeds the {max_bytes}-byte safety limit")
    return bytes(content)


def validate_pe(content):
    if len(content) < 64 or content[:2] != b"MZ":
        raise RuntimeError("response is not a DOS/PE executable")
    pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
    if pe_offset < 64 or pe_offset > len(content) - 4:
        raise RuntimeError("response has an invalid PE header offset")
    if content[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise RuntimeError("response does not contain a valid PE signature")


def verify_requested_hash(requested_hash, content):
    algorithms = {32: "md5", 40: "sha1", 64: "sha256"}
    algorithm = algorithms.get(len(requested_hash))
    if algorithm is None:
        raise RuntimeError("MalShare returned an unsupported hash format")
    actual = hashlib.new(algorithm, content).hexdigest()
    if actual != requested_hash.lower():
        raise RuntimeError(f"downloaded bytes do not match the requested {algorithm}")


def write_encrypted_archive(destination, member_name, content):
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    temporary.unlink(missing_ok=True)
    try:
        with pyzipper.AESZipFile(
            temporary,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as archive:
            archive.setpassword(ZIP_PASSWORD)
            archive.setencryption(pyzipper.WZ_AES, nbits=256)
            archive.writestr(member_name, content)

        # Fail closed unless the encrypted archive decrypts to the exact bytes.
        with pyzipper.AESZipFile(temporary, "r") as archive:
            archive.setpassword(ZIP_PASSWORD)
            names = archive.namelist()
            if names != [member_name]:
                raise RuntimeError("encrypted archive contains unexpected members")
            restored = archive.read(member_name)
        if hashlib.sha256(restored).digest() != hashlib.sha256(content).digest():
            raise RuntimeError("encrypted archive verification failed")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def archive_is_valid(destination, expected_sha256):
    try:
        with pyzipper.AESZipFile(destination, "r") as archive:
            archive.setpassword(ZIP_PASSWORD)
            names = archive.namelist()
            if len(names) != 1:
                return False
            content = archive.read(names[0])
        validate_pe(content)
        return hashlib.sha256(content).hexdigest() == expected_sha256
    except (OSError, RuntimeError, ValueError, pyzipper.BadZipFile):
        return False


def download_sample(session, api_key, requested_hash, max_bytes):
    response = api_get(
        session,
        api_key,
        {"action": "getfile", "hash": requested_hash},
        stream=True,
    )
    content = read_limited(response, max_bytes)
    validate_pe(content)
    verify_requested_hash(requested_hash, content)
    return content


def main():
    parser = argparse.ArgumentParser(
        description="Download MalShare PE samples directly into AES-encrypted ZIPs"
    )
    parser.add_argument("--count", type=sample_count, default=25)
    parser.add_argument("--file-type", choices=("PE32", "PE32+"), default="PE32")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("validation-data") / "malshare",
    )
    parser.add_argument("--max-sample-bytes", type=int, default=DEFAULT_MAX_SAMPLE_BYTES)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument(
        "--acknowledge-live-malware",
        action="store_true",
        help="confirm use inside an approved isolated research VM",
    )
    args = parser.parse_args()

    if not args.acknowledge_live_malware:
        parser.error(
            "--acknowledge-live-malware is required; use only in an approved isolated VM"
        )
    if args.max_sample_bytes < 64:
        parser.error("--max-sample-bytes must be at least 64")
    api_key = os.getenv("MALSHARE_API_KEY")
    if not api_key:
        raise SystemExit("MALSHARE_API_KEY is not set")

    args.output.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    candidates = query_hashes(session, api_key, args.file_type)
    manifest = {
        "source": "MalShare",
        "api": API_URL,
        "collected_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "requested_count": args.count,
        "requested_file_type": args.file_type,
        "label_warning": "MalShare states that not every hosted file is necessarily malicious.",
        "storage": "AES-256 ZIP; password infected",
        "samples": [],
        "failures": [],
    }

    for requested_hash in candidates:
        if len(manifest["samples"]) >= args.count:
            break
        try:
            # We can only name/reuse an archive before download when given SHA-256.
            if len(requested_hash) == 64:
                destination = args.output / f"{requested_hash}.zip"
                if destination.exists() and archive_is_valid(destination, requested_hash):
                    manifest["samples"].append({
                        "requested_hash": requested_hash,
                        "sha256": requested_hash,
                        "file_type": args.file_type,
                        "archive": destination.name,
                        "status": "existing",
                        "archive_bytes": destination.stat().st_size,
                    })
                    print(f"[{len(manifest['samples'])}/{args.count}] {requested_hash} existing", flush=True)
                    continue

            content = download_sample(
                session, api_key, requested_hash, args.max_sample_bytes
            )
            sha256 = hashlib.sha256(content).hexdigest()
            destination = args.output / f"{sha256}.zip"
            write_encrypted_archive(destination, f"{sha256}.exe", content)
            manifest["samples"].append({
                "requested_hash": requested_hash,
                "sha256": sha256,
                "file_type": args.file_type,
                "archive": destination.name,
                "status": "downloaded",
                "sample_bytes": len(content),
                "archive_bytes": destination.stat().st_size,
            })
            print(f"[{len(manifest['samples'])}/{args.count}] {sha256} encrypted", flush=True)
        except (RuntimeError, OSError, pyzipper.BadZipFile) as error:
            manifest["failures"].append({
                "requested_hash": requested_hash,
                "error": str(error),
            })
            print(f"skipped {requested_hash}: {error}", file=sys.stderr, flush=True)
        time.sleep(max(0.0, args.delay))

    manifest_path = args.output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(manifest['samples'])} encrypted archives to {args.output}")
    print(f"Manifest: {manifest_path}")
    if len(manifest["samples"]) < args.count:
        print(
            f"Only {len(manifest['samples'])} of {args.count} requested samples were collected",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
