"""
Test SigstoreSigner API.

NOTE: The filename prefix is check_ instead of test_ so that tests are
only run when explicitly invoked in a suited environment.

"""
import os
import unittest

from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    Signer,
    SigstoreSigner,
)

SIGNER_FOR_URI_SCHEME[SigstoreSigner.SCHEME] = SigstoreSigner


class TestSigstoreSigner(unittest.TestCase):
    """Test public key parsing, signature creation and verification.

    Requires ambient credentials for signing (e.g. from GitHub Action).

    See sigstore-python docs for more infos about ambient credentials:
    https://github.com/sigstore/sigstore-python#signing-with-ambient-credentials

    See securesystemslib SigstoreSigner docs for how to test locally.
    """

    def test_sign(self):
        identity = os.getenv("CERT_ID")
        self.assertIsNotNone(identity, "certificate identity required")
        issuer = os.getenv("CERT_ISSUER")
        self.assertIsNotNone(issuer, "OIDC issuer required")

        uri, public_key = SigstoreSigner.import_(identity, issuer)
        signer = Signer.from_priv_key_uri(uri, public_key)

        sig = signer.sign(b"data")
        public_key.verify_signature(sig, b"data")


if __name__ == "__main__":
    unittest.main(verbosity=4, buffer=False)
