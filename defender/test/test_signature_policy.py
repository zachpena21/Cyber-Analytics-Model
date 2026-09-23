import unittest
from unittest.mock import MagicMock, patch

from defender.signature_policy import has_verified_microsoft_signature


class SignaturePolicyTests(unittest.TestCase):
    @staticmethod
    def certificate(organization):
        certificate = MagicMock()
        certificate.subject.get_components.return_value = [organization]
        return certificate

    @patch("defender.signature_policy.AuthenticodeFile")
    def test_accepts_verified_microsoft_leaf(self, authenticode_file):
        root = self.certificate("Trusted Root")
        leaf = self.certificate("Microsoft Corporation")
        signed_file = authenticode_file.from_stream.return_value
        signed_file.verify.return_value = [(object(), object(), [[root, leaf]])]

        self.assertTrue(has_verified_microsoft_signature(b"MZsample"))
        signed_file.verify.assert_called_once_with(
            multi_verify_mode="best", signature_types="embedded"
        )

    @patch("defender.signature_policy.AuthenticodeFile")
    def test_rejects_non_microsoft_leaf(self, authenticode_file):
        root = self.certificate("Microsoft Corporation")
        leaf = self.certificate("Untrusted Publisher")
        authenticode_file.from_stream.return_value.verify.return_value = [
            (object(), object(), [[root, leaf]])
        ]

        self.assertFalse(has_verified_microsoft_signature(b"MZsample"))

    @patch("defender.signature_policy.AuthenticodeFile.from_stream")
    def test_verification_error_fails_closed(self, from_stream):
        from_stream.side_effect = ValueError("invalid signature")
        self.assertFalse(has_verified_microsoft_signature(b"MZsample"))


if __name__ == "__main__":
    unittest.main()
