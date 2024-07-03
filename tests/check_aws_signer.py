"""Test AWSSigner"""

import unittest

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import AWSSigner, Signer


class TestAWSSigner(unittest.TestCase):
    """Test AWSSigner"""

    def test_aws_import_sign_verify(self):
        # Test full signer flow with localstack
        # - see tests/scripts/init-aws-kms.sh for how keys are created
        # - see tox.ini for how credentials etc. are passed via env vars
        keys_and_schemes = [
            (
                "alias/rsa",
                "rsassa-pss-sha256",
                [
                    "rsassa-pss-sha256",
                    "rsassa-pss-sha384",
                    "rsassa-pss-sha512",
                    "rsa-pkcs1v15-sha256",
                    "rsa-pkcs1v15-sha384",
                    "rsa-pkcs1v15-sha512",
                ],
            ),
            (
                "alias/ecdsa_nistp256",
                "ecdsa-sha2-nistp256",
                ["ecdsa-sha2-nistp256"],
            ),
            (
                "alias/ecdsa_nistp384",
                "ecdsa-sha2-nistp384",
                ["ecdsa-sha2-nistp384"],
            ),
        ]
        for aws_keyid, default_scheme, schemes in keys_and_schemes:
            for scheme in schemes:
                # Test import
                uri, public_key = AWSSigner.import_(aws_keyid, scheme)
                self.assertEqual(uri, f"{AWSSigner.SCHEME}:{aws_keyid}")
                self.assertEqual(scheme, public_key.scheme)

                # Test import with default_scheme
                if scheme == default_scheme:
                    uri2, public_key2 = AWSSigner.import_(aws_keyid)
                    self.assertEqual(uri, uri2)
                    self.assertEqual(public_key, public_key2)

                # Test load
                signer = Signer.from_priv_key_uri(uri, public_key)
                self.assertIsInstance(signer, AWSSigner)

                # Test sign and verify
                signature = signer.sign(b"DATA")
                self.assertIsNone(public_key.verify_signature(signature, b"DATA"))
                with self.assertRaises(UnverifiedSignatureError):
                    public_key.verify_signature(signature, b"NOT DATA")


if __name__ == "__main__":
    unittest.main(verbosity=1)
