#!/usr/bin/env python3
"""Standard-library regression checks for the v8 ZIP scanner."""
import ast
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

from check_data_overlap import archive_payloads, pe_hashes

ROOT = Path(__file__).resolve().parents[1]
GOOD_PE = b"MZ-readable-fixture"
MISSING_PE = b"MZ-unreadable-fixture"


def damaged_zip(bad_name="autofill/profile.txt", bad_data=b"text"):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(bad_name, bad_data)
        archive.writestr("good.exe", GOOD_PE)
        offset = archive.getinfo(bad_name).header_offset
    data = bytearray(stream.getvalue())
    data[offset:offset + 4] = b"BAD!"
    return bytes(data)


class ArchiveScanTests(unittest.TestCase):
    def test_flag_compatibility_preserves_raw_attributes_and_other_features(self):
        source = (ROOT / "scripts/reviewer_v8_workflow.py").read_text(encoding="utf-8")
        function = next(node for node in ast.parse(source).body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "normalize_cached_flags")
        scope = dict(SCORE_FEATURES=tuple(range(6)))
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "<actual flag compatibility>", "exec"), scope)
        fields = ("characteristics_list", "dll_characteristics_list")
        names = [str(i) for i in range(6)] + [
            f"{field}_{suffix}" for field in fields
            for suffix in ("token_count", "unique_count", "character_count")]
        names.append("unrelated_feature")
        raw = dict(characteristics_list="CHARACTERISTICS.EXECUTABLE_IMAGE CHARACTERISTICS.LARGE_ADDRESS_AWARE",
                   dll_characteristics_list="32 64 256")
        sample = dict(attributes=raw.copy(), structural_vector=[2., 2., 68., 3., 3., 9., 123.])
        normalize = scope["normalize_cached_flags"]
        self.assertTrue(normalize(sample, names))
        self.assertEqual(sample["structural_vector"],
                         [2., 2., 36., 3., 3., 38., 123.])
        self.assertEqual(sample["attributes"], raw)
        self.assertFalse(normalize(sample, names))
        sample["attributes"] = dict(characteristics_list="EXECUTABLE_IMAGE LARGE_ADDRESS_AWARE",
                                    dll_characteristics_list="HIGH_ENTROPY_VA DYNAMIC_BASE NX_COMPAT")
        self.assertFalse(normalize(sample, names))

    def test_strict_scan_rejects_bad_member(self):
        with zipfile.ZipFile(io.BytesIO(damaged_zip())) as archive:
            with self.assertRaisesRegex(RuntimeError, "Bad magic number"):
                list(archive_payloads(archive, zipfile.ZipFile))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "damaged.zip"
            path.write_bytes(damaged_zip())
            with self.assertRaises(RuntimeError):
                pe_hashes(path, zipfile.ZipFile)

    def test_tolerant_scan_reads_later_members(self):
        warnings = []
        with zipfile.ZipFile(io.BytesIO(damaged_zip())) as archive:
            result = list(archive_payloads(archive, zipfile.ZipFile,
                                          on_error=warnings.append, origin="fixture.zip"))
        self.assertEqual(result, [GOOD_PE])
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]["archive"], "fixture.zip")
        self.assertEqual(warnings[0]["member"], "autofill/profile.txt")
        self.assertEqual(warnings[0]["compression_method"], 8)

    def test_nested_warning_preserves_archive_path(self):
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("nested.zip", damaged_zip())
            archive.writestr("later.exe", b"MZ-outer-fixture")
        warnings = []
        with zipfile.ZipFile(io.BytesIO(outer.getvalue())) as archive:
            result = list(archive_payloads(archive, zipfile.ZipFile,
                                          on_error=warnings.append, origin="outer.zip"))
        self.assertEqual(result, [GOOD_PE, b"MZ-outer-fixture"])
        self.assertEqual(warnings[0]["archive"], "outer.zip!/nested.zip")

    def test_v8_requires_every_expected_sha_after_skipping(self):
        # Execute the actual extraction function in isolation. Stub only the PE
        # parser and AES reader; no numpy/sklearn/LIEF imports are needed here.
        source = (ROOT / "scripts/reviewer_v8_workflow.py").read_text(encoding="utf-8")
        parsed = ast.parse(source)
        functions = [node for node in parsed.body
                     if isinstance(node, ast.FunctionDef)
                     and node.name in ("collect_features", "normalize_cached_flags")]
        from check_data_overlap import payloads

        def dump(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding="utf-8")

        score_features = ("benign_probability", "adapter_probability",
                          "base_trigger_raw", "base_trigger_adjusted",
                          "signature_checked", "signature_verified")
        scope = dict(ROOT=ROOT, hashlib=hashlib, importlib=importlib, json=json,
                     SCORE_FEATURES=score_features, dump=dump, payloads=payloads)
        exec(compile(ast.Module(body=functions, type_ignores=[]),
                     "<actual v8 collect_features>", "exec"), scope)

        reader = types.ModuleType("pyzipper")
        reader.AESZipFile = zipfile.ZipFile
        defender = types.ModuleType("defender")
        defender.__path__ = []
        models = types.ModuleType("defender.models")
        models.__path__ = []
        extractor_module = types.ModuleType("defender.models.attribute_extractor")

        class Extractor:
            def __init__(self, data):
                self.data = data

            def extract(self):
                return {"size": len(self.data)}

        extractor_module.PEAttributeExtractor = Extractor

        class Reviewer:
            feature_names = [*score_features, "size"]

            def _vectorize(self, attributes, bytez, components):
                return [0.0] * len(score_features) + [float(len(bytez))]

        replacements = {"pyzipper": reader, "defender": defender,
                        "defender.models": models,
                        "defender.models.attribute_extractor": extractor_module}
        with tempfile.TemporaryDirectory() as directory, patch.dict(sys.modules, replacements):
            directory = Path(directory)
            archive = directory / "samples.zip"
            archive.write_bytes(damaged_zip("missing.exe", MISSING_PE))
            missing_sha = hashlib.sha256(MISSING_PE).hexdigest()
            cache = directory / "feature-cache.json"
            collect = scope["collect_features"]
            with self.assertRaisesRegex(ValueError, "Could not find/parse 1 required"):
                collect([{"sha256": missing_sha}], Reviewer(), directory / "unused-model.json",
                        [archive], cache, 1024)
            failures = json.loads((directory / "extraction-failures.json").read_text())
            self.assertEqual(failures["missing"], [missing_sha])
            self.assertEqual(failures["archive_read_warnings"][0]["member"], "missing.exe")
            good_sha = hashlib.sha256(GOOD_PE).hexdigest()
            found = collect([{"sha256": good_sha}], Reviewer(), directory / "unused-model.json",
                            [archive], directory / "good-cache.json", 1024)
            self.assertIn(good_sha, found)


if __name__ == "__main__":
    unittest.main()
