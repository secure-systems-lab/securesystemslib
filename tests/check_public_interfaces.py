"""
<Program Name>
  check_public_interfaces.py

<Author>
  Joshua Lock <jlock@vmware.com>

<Started>
  January 6, 2020.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Public facing modules must be importable, even if the optional dependencies
  are not installed.

  Each public facing function should always be callable and present
  meaningful user-feedback if an optional dependency that is required for
  that function is not installed.

  This test purposefully only checks the public functions with a native
  dependency, to avoid duplicated tests.

  NOTE: the filename is purposefully check_ rather than test_ so that test
  discovery doesn't find this unittest and the tests within are only run
  when explicitly invoked.
"""

import os
import shutil
import tempfile
import unittest

import securesystemslib._gpg.constants
import securesystemslib._gpg.util
import securesystemslib.exceptions
from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    VerificationError,
)
from securesystemslib.signer import (
    CryptoSigner,
    GPGKey,
    Key,
    Signature,
    SpxKey,
    SpxSigner,
    SSlibKey,
)
from securesystemslib.signer._sigstore_signer import SigstoreKey


class TestPublicInterfaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(dir=os.getcwd())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir)

    def test_gpg_functions(self):
        """Public GPG functions must raise error on missing cryptography lib."""
        expected_error = securesystemslib.exceptions.UnsupportedLibraryError
        expected_error_msg = securesystemslib._gpg.functions.NO_CRYPTO_MSG

        with self.assertRaises(expected_error) as ctx:
            securesystemslib._gpg.functions.create_signature("bar")
        self.assertEqual(expected_error_msg, str(ctx.exception))

        with self.assertRaises(expected_error) as ctx:
            securesystemslib._gpg.functions.verify_signature(None, "f00", "bar")
        self.assertEqual(expected_error_msg, str(ctx.exception))

        with self.assertRaises(expected_error) as ctx:
            securesystemslib._gpg.functions.export_pubkey("f00")
        self.assertEqual(expected_error_msg, str(ctx.exception))

    def test_sslib_key_from_crypto(self):
        """Assert raise UnsupportedLibraryError on SSlibKey.from_crypto()."""
        with self.assertRaises(UnsupportedLibraryError):
            SSlibKey.from_crypto("mock pyca/crypto pubkey")  # type: ignore

    def test_crypto_signer_from_priv_key_uri(self):
        """Assert raise UnsupportedLibraryError on 'from_priv_key_uri'."""

        public_key = SSlibKey("aa", "rsa", "rsa-pkcs1v15-sha512", {"public": "val"})
        with self.assertRaises(UnsupportedLibraryError):
            CryptoSigner.from_priv_key_uri(
                "file:should/fail/before/urlparse", public_key, None
            )

    def test_signer_generate(self):
        """Assert raise UnsupportedLibraryError on CryptoSigner.generate()."""
        for generate in [
            CryptoSigner.generate_rsa,
            CryptoSigner.generate_ecdsa,
            CryptoSigner.generate_ed25519,
        ]:
            with self.assertRaises(UnsupportedLibraryError):
                generate()

    def test_signer_verify(self):
        """Assert generic VerificationError from UnsupportedLibraryError."""
        keyid = "aa"
        sig = Signature(keyid, "aaaaaaaa", {"other_headers": "aaaaaa"})

        keys = [
            GPGKey(keyid, "rsa", "pgp+rsa-pkcsv1.5", {"public": "val"}),
            SSlibKey(keyid, "rsa", "rsa-pkcs1v15-sha512", {"public": "val"}),
            SigstoreKey(
                keyid,
                "sigstore-oidc",
                "Fulcio",
                {"identity": "val", "issuer": "val"},
            ),
            SpxKey(keyid, "sphincs", "sphincs-shake-128s", {"public": "val"}),
        ]

        for key in keys:
            with self.assertRaises(VerificationError) as ctx:
                key.verify_signature(sig, b"data")

            self.assertIsInstance(
                ctx.exception.__cause__, (UnsupportedLibraryError, ImportError)
            )

    def test_signer_sign(self):
        """Assert UnsupportedLibraryError in sign."""
        signers = [
            SpxSigner(
                b"private",
                SpxKey("aa", "sphincs", "sphincs-shake-128s", {"public": "val"}),
            )
        ]

        for signer in signers:
            with self.assertRaises(UnsupportedLibraryError):
                signer.sign(b"data")

    def test_signer_ed25519_fallback(self):
        """Assert ed25519 signature verification works in pure Python."""
        data = b"The quick brown fox jumps over the lazy dog"
        keyid = "aaa"
        sig = Signature.from_dict(
            {
                "keyid": keyid,
                "sig": "2ec7a5e295fa6265e10f3da7f1a432e7742f041f081b4faecab3a12bf0fc8f366c919c90c267e9ed1dfdeb7a7556b959a96dd0dcfea17da358622d39af36bf09",
            }
        )

        key = Key.from_dict(
            keyid,
            {
                "keytype": "ed25519",
                "scheme": "ed25519",
                "keyval": {
                    "public": "beb75c268206554e963c45dcbf3c004140d1cb69bbfe9370ef736f19388c9b26"
                },
            },
        )

        self.assertIsNone(key.verify_signature(sig, data))

        with self.assertRaises(securesystemslib.exceptions.UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")


if __name__ == "__main__":
    unittest.main(verbosity=1, buffer=True)
