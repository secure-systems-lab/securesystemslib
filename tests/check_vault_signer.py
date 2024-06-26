"""Test VaultSigner"""

import unittest

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import Signer, VaultSigner


class TestVaultSigner(unittest.TestCase):
    """Test VaultSigner"""

    def test_vault_import_sign_verify(self):
        # Test full signer flow with vault
        # - see tests/scripts/init-vault.sh for how keys are created
        # - see tox.ini for how credentials etc. are passed via env vars
        keys_and_schemes = [("test-key-ed25519", 1, "ed25519")]
        for name, version, scheme in keys_and_schemes:
            # Test import
            uri, public_key = VaultSigner.import_(name)

            self.assertEqual(uri, f"{VaultSigner.SCHEME}:{name}/{version}")
            self.assertEqual(public_key.scheme, scheme)

            # Test load
            signer = Signer.from_priv_key_uri(uri, public_key)
            self.assertIsInstance(signer, VaultSigner)

            # Test sign and verify
            signature = signer.sign(b"DATA")
            self.assertIsNone(public_key.verify_signature(signature, b"DATA"))
            with self.assertRaises(UnverifiedSignatureError):
                public_key.verify_signature(signature, b"NOT DATA")


if __name__ == "__main__":
    unittest.main(verbosity=1)
