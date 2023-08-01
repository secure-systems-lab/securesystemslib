"""This module confirms that signing using AWS KMS keys works.

The purpose is to do a smoke test, not to exhaustively test every possible key
and environment combination.

For AWS, the requirements to successfully test are:
* AWS authentication details
have to be available in the environment
* The key defined in the test has to be
available to the authenticated user

Remember to replace the REDACTED fields to include the necessary values:
* keyid: Hash of the public key
* public: The public key, refer to other KMS tests to see the format
* aws_id: AWS KMS ID or alias
"""

import unittest

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import AWSSigner, Key, Signer


class TestAWSKMSKeys(unittest.TestCase):
    """Test that AWS KMS keys can be used to sign."""

    pubkey = Key.from_dict(
        "REDACTED",
        {
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyval": {
                "public": "-----BEGIN PUBLIC KEY-----\nREDACTED\n-----END PUBLIC KEY-----\n"
            },
        },
    )
    aws_key_id = "REDACTED"

    def test_aws_sign(self):
        """Test that AWS KMS key works for signing"""

        data = "data".encode("utf-8")

        signer = Signer.from_priv_key_uri(
            f"awskms:{self.aws_key_id}", self.pubkey
        )
        sig = signer.sign(data)

        self.pubkey.verify_signature(sig, data)
        with self.assertRaises(UnverifiedSignatureError):
            self.pubkey.verify_signature(sig, b"NOT DATA")

    def test_aws_import(self):
        """Test that AWS KMS key can be imported"""

        uri, key = AWSSigner.import_(self.aws_key_id, self.pubkey.scheme)
        self.assertEqual(key.keytype, self.pubkey.keytype)
        self.assertEqual(uri, f"awskms:{self.aws_key_id}")


if __name__ == "__main__":
    unittest.main(verbosity=1)
