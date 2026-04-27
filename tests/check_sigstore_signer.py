"""
Test SigstoreSigner API.

These tests require git and will use it to fetch a testing identity token from
https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon

Because of these unusual requirements (and because sometimes the fetch may take
a longer time) the test file is named check_* and is not included in the default
tests.
"""

import functools
import unittest
from unittest import mock
from urllib import request

from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    Signer,
    SigstoreSigner,
)

SIGNER_FOR_URI_SCHEME[SigstoreSigner.SCHEME] = SigstoreSigner

TEST_IDENTITY = "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com"
TEST_ISSUER = "https://accounts.google.com"
TOKEN_URL = "https://storage.googleapis.com/sigstore-conformance-testing-token/untrusted-testing-token.txt"


@functools.cache
def token() -> str:
    """Fetch and cache testing token"""
    with request.urlopen(TOKEN_URL) as response:
        return response.read().decode()


class TestSigstoreSigner(unittest.TestCase):
    """Test public key parsing, signature creation and verification."""

    def test_sign(self) -> None:
        uri, public_key = SigstoreSigner.import_(TEST_IDENTITY, TEST_ISSUER)
        with mock.patch("sigstore.oidc.detect_credential", return_value=token()):
            signer = Signer.from_priv_key_uri(uri, public_key)

        sig = signer.sign(b"data")

        # Successful verification
        public_key.verify_signature(sig, b"data")

        # Signature mismatch
        with self.assertRaises(UnverifiedSignatureError):
            public_key.verify_signature(sig, b"incorrect data")

        # Broken bundle
        sig.unrecognized_fields["bundle"]["verificationMaterial"] = None
        with self.assertRaises(VerificationError):
            public_key.verify_signature(sig, b"data")


if __name__ == "__main__":
    unittest.main(verbosity=4, buffer=False)
