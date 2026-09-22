import tempfile
import unittest
from pathlib import Path

import pyzipper

from test import file_bytes_generator


class ArchiveReaderTests(unittest.TestCase):
    def test_reads_aes_encrypted_nested_zip_without_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "sample.zip"
            with pyzipper.AESZipFile(
                archive_path,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as archive:
                archive.setpassword(b"infected")
                archive.writestr("sample.exe", b"MZ" + b"test-data")

            samples = list(file_bytes_generator(directory, maxsize=1024))
            self.assertEqual(len(samples), 1)
            self.assertEqual(samples[0][1], b"MZ" + b"test-data")


if __name__ == "__main__":
    unittest.main()
