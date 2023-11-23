"""Test key migration script"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from docs.migrate_key import main as migrate_key_cli
from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.interface import (
    import_privatekey_from_file,
    import_publickeys_from_file,
)
from securesystemslib.signer import CryptoSigner, SSlibKey, SSlibSigner


class TestMigrateKey(unittest.TestCase):
    """Test key migration and backwards compatibility of signatures."""

    @classmethod
    def setUpClass(cls):
        cls.old_keys = Path(__file__).parent / "data" / "legacy"
        cls.new_keys = Path(tempfile.mkdtemp())

        # Migrate private, private encrypted and public keys for each algo
        for algo in ["rsa", "ecdsa", "ed25519"]:
            for type_, name_suffix, has_password in [
                ("private", "_encrypted", True),
                ("private", "_unencrypted", False),
                ("public", "", False),
            ]:
                args = [
                    "migrate_key.py",
                    "--type",
                    type_,
                    "--algo",
                    algo,
                    "--in",
                    str(cls.old_keys / f"{algo}_{type_}{name_suffix}"),
                    "--out",
                    str(cls.new_keys / f"{algo}_{type_}{name_suffix}"),
                ]

                if has_password:
                    args += ["--password", "password"]

                with patch.object(sys, "argv", args):
                    migrate_key_cli()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.new_keys)

    def _from_file(self, algo):
        with open(self.new_keys / f"{algo}_public", "rb") as f:
            pem = f.read()
        return load_pem_public_key(pem)

    def test_migrated_keys(self):
        for algo in ["rsa", "ecdsa", "ed25519"]:
            # Load public key
            crypto_key = self._from_file(algo)
            public_key = SSlibKey.from_crypto(crypto_key)

            # Load unencrypted private key
            path = self.new_keys / f"{algo}_private_unencrypted"
            uri = f"file:{path}?encrypted=false"
            signer_unenc = CryptoSigner.from_priv_key_uri(uri, public_key)

            # Load encrypted private key
            path = self.new_keys / f"{algo}_private_encrypted"
            uri = f"file:{path}?encrypted=true"
            signer_enc = CryptoSigner.from_priv_key_uri(
                uri, public_key, lambda sec: "password"
            )

            # Sign and test signatures
            for signer in [signer_unenc, signer_enc]:
                sig = signer.sign(b"data")
                self.assertIsNone(public_key.verify_signature(sig, b"data"))
                with self.assertRaises(UnverifiedSignatureError):
                    public_key.verify_signature(sig, b"not data")

    def test_new_signature_verifies_with_old_key(self):
        for algo in ["rsa", "ecdsa", "ed25519"]:
            # Load old public key
            key_dicts = import_publickeys_from_file(
                [str(self.old_keys / f"{algo}_public")], [algo]
            )
            key_dict = list(key_dicts.values())[0]
            public_key = SSlibKey.from_securesystemslib_key(key_dict)

            # Load new private key
            # NOTE: The signer is loaded with the old public key, thus the old
            # keyid will be assigned to any new signatures.
            path = self.new_keys / f"{algo}_private_unencrypted"
            uri = f"file:{path}?encrypted=false"
            signer = CryptoSigner.from_priv_key_uri(uri, public_key)

            # Sign and test signatures
            sig = signer.sign(b"data")
            self.assertIsNone(public_key.verify_signature(sig, b"data"))
            with self.assertRaises(UnverifiedSignatureError):
                public_key.verify_signature(sig, b"not data")

    def test_old_signature_verifies_with_new_key(self):
        for algo in ["rsa", "ecdsa", "ed25519"]:
            # Load old private key
            private_key = import_privatekey_from_file(
                str(self.old_keys / f"{algo}_private_unencrypted"), algo
            )
            signer = SSlibSigner(private_key)

            # Load new public key
            crypto_key = self._from_file(algo)
            # NOTE: The new auto-keyid would differ from the old keyid.
            # Set it explicitly, to verify signatures with old keyid below
            public_key = SSlibKey.from_crypto(
                crypto_key, keyid=private_key["keyid"]
            )

            # Sign and test signature
            sig = signer.sign(b"data")
            self.assertIsNone(public_key.verify_signature(sig, b"data"))
            with self.assertRaises(UnverifiedSignatureError):
                public_key.verify_signature(sig, b"not data")


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
