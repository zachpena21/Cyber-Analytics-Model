import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

import pyzipper


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "download_malshare.py"
SPEC = importlib.util.spec_from_file_location("download_malshare", SCRIPT_PATH)
download_malshare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(download_malshare)


def minimal_pe():
    content = bytearray(128)
    content[:2] = b"MZ"
    content[0x3C:0x40] = (64).to_bytes(4, "little")
    content[64:68] = b"PE\x00\x00"
    content[68:] = bytes(range(60))
    return bytes(content)


class MalShareDownloaderTests(unittest.TestCase):
    def test_extract_hashes_accepts_documented_response_shapes(self):
        sha256 = "a" * 64
        md5 = "b" * 32
        payload = {"data": [{"sha256": sha256}, {"MD5": md5}, {"bad": "value"}]}
        self.assertEqual(download_malshare.extract_hashes(payload), [sha256, md5])

    def test_validates_pe_header_and_requested_hash(self):
        content = minimal_pe()
        download_malshare.validate_pe(content)
        digest = hashlib.sha256(content).hexdigest()
        download_malshare.verify_requested_hash(digest, content)
        with self.assertRaises(RuntimeError):
            download_malshare.validate_pe(b"MZ" + b"not-a-pe")
        with self.assertRaises(RuntimeError):
            download_malshare.verify_requested_hash("0" * 64, content)

    def test_writes_only_aes_encrypted_archive(self):
        content = minimal_pe()
        digest = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / f"{digest}.zip"
            member_name = f"{digest}.exe"
            download_malshare.write_encrypted_archive(destination, member_name, content)

            raw_archive = destination.read_bytes()
            self.assertNotIn(content, raw_archive)
            with pyzipper.AESZipFile(destination, "r") as archive:
                with self.assertRaises(RuntimeError):
                    archive.read(member_name, pwd=b"wrong-password")
                self.assertEqual(archive.read(member_name, pwd=b"infected"), content)
            self.assertTrue(download_malshare.archive_is_valid(destination, digest))
            self.assertFalse(destination.with_suffix(".zip.part").exists())


if __name__ == "__main__":
    unittest.main()
