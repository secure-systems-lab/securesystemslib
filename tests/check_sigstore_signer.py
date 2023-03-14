"""
Test SigstoreSigner API.

NOTE: The filename prefix is check_ instead of test_ so that tests are
only run when explicitly invoked in a suited environment.

"""
import os
import unittest

from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    SIGNER_FOR_URI_SCHEME,
    Key,
    Signer,
    SigstoreKey,
    SigstoreSigner,
)

KEY_FOR_TYPE_AND_SCHEME.update(
    {
        ("sigstore-oidc", "Fulcio"): SigstoreKey,
    }
)

SIGNER_FOR_URI_SCHEME.update({SigstoreSigner.SCHEME: SigstoreSigner})


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
        signer = Signer.from_priv_key_uri("sigstore:", public_key)
        sig = signer.sign(b"data")
        public_key.verify_signature(sig, b"data")


if __name__ == "__main__":
    unittest.main(verbosity=4, buffer=False)
