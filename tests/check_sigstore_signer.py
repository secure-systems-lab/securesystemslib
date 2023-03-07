"""
Test SigstoreSigner API.

NOTE: The filename prefix is check_ instead of test_ so that tests are
only run when explicitly invoked in a suited environment.

"""
import os
import unittest

from sigstore.oidc import detect_credential  # pylint: disable=import-error

from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    Key,
    SigstoreKey,
    SigstoreSigner,
)

KEY_FOR_TYPE_AND_SCHEME.update(
    {
        ("sigstore-oidc", "Fulcio"): SigstoreKey,
    }
)


class TestSigstoreSigner(unittest.TestCase):
    """Test public key parsing, signature creation and verification.

    Requires ambient credentials for signing (e.g. from GitHub Action).

    See sigstore-python docs for more infos about ambient credentials:
    https://github.com/sigstore/sigstore-python#signing-with-ambient-credentials

    See securesystemslib SigstoreSigner docs for how to test locally.
    """

    def test_sign(self):
        token = detect_credential()
        self.assertIsNotNone(token, "ambient credentials required")

        identity = os.getenv("CERT_ID")
        self.assertIsNotNone(token, "certificate identity required")

        issuer = os.getenv("CERT_ISSUER")
        self.assertIsNotNone(token, "OIDC issuer required")

        public_key = Key.from_dict(
            "abcdef",
            {
                "keytype": "sigstore-oidc",
                "scheme": "Fulcio",
                "keyval": {
                    "issuer": issuer,
                    "identity": identity,
                },
            },
        )

        signer = SigstoreSigner(token, public_key)
        sig = signer.sign(b"data")
        public_key.verify_signature(sig, b"data")


if __name__ == "__main__":
    unittest.main(verbosity=4, buffer=False)
