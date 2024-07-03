"""
This module confirms that signing using Azure KMS keys works.

The purpose is to do a smoke test, not to exhaustively test every possible
key and environment combination.

For Azure, the requirements to successfully test are:
* Azure authentication details have to be available in the environment
* The key defined in the test has to be available to the authenticated user

NOTE: the filename is purposefully check_ rather than test_ so that tests are
only run when explicitly invoked.
"""

import unittest

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import AzureSigner, Key, Signer


class TestAzureKeys(unittest.TestCase):
    """Test that KMS keys can be used to sign."""

    azure_pubkey = Key.from_dict(
        "8b4af6aec66518bc66718474aa15c8becd3286e8e2b958c497a60a828d591d04",
        {
            "keytype": "ecdsa",
            "scheme": "ecdsa-sha2-nistp256",
            "keyval": {
                "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE95qxD+/kX6oCace7hrfChtz2IYGK\nHNBmUwtf3wXH0VEdLPWVoFgGITonvA7vxqYrF8ZzAeeZYNyEBbod7SEeaw==\n-----END PUBLIC KEY-----\n"
            },
        },
    )
    azure_id = "azurekms://fsn-vault-1.vault.azure.net/keys/ec-key-1/b1089bbf068742d483970282f02090de"

    def test_azure_sign(self):
        """Test that Azure KMS key works for signing

        Note that this test requires valid credentials available.
        """

        data = "data".encode("utf-8")

        signer = Signer.from_priv_key_uri(self.azure_id, self.azure_pubkey)
        sig = signer.sign(data)

        print(sig.signature)

        self.azure_pubkey.verify_signature(sig, data)
        with self.assertRaises(UnverifiedSignatureError):
            self.azure_pubkey.verify_signature(sig, b"NOT DATA")

    def test_azure_import(self):
        """Test that Azure KMS key works for signing

        Note that this test requires valid credentials available.
        """

        uri, pubkey = AzureSigner.import_("fsn-vault-1", "ec-key-1")

        self.assertEqual(pubkey, self.azure_pubkey)
        self.assertEqual(uri, self.azure_id)


if __name__ == "__main__":
    unittest.main(verbosity=1, buffer=True)
