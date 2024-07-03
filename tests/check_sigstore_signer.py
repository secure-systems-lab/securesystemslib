"""
Test SigstoreSigner API.

These tests require git and will use it to fetch a testing identity token from
https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon

Because of these unusual requirements (and because sometimes the fetch may take
a longer time) the test file is named check_* and is not included in the default
tests.
"""

import json
import os
import subprocess
import time
import unittest
from base64 import b64decode
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

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

TEST_IDENTITY = (
    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/"
    "workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)
TEST_ISSUER = "https://token.actions.githubusercontent.com"


def identity_token() -> str:
    """Return identity token for TEST_IDENTITY"""
    # following code is modified from extremely-dangerous-public-oidc-beacon download-token.py.
    # Caching can be made smarter (to return the cached token only if it is valid) if token
    # starts going invalid during runs
    min_validity = timedelta(seconds=5)
    max_retry_time = timedelta(minutes=5 if os.getenv("CI") else 1)
    retry_sleep_secs = 30 if os.getenv("CI") else 5
    git_url = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon.git"

    def git_clone(url: str, dir_: str) -> None:
        base_cmd = [
            "git",
            "clone",
            "--quiet",
            "--branch",
            "current-token",
            "--depth",
            "1",
        ]
        subprocess.run(base_cmd + [url, dir_], check=True)

    def is_valid_at(token: str, reference_time: datetime) -> bool:
        # split token, b64 decode (with padding), parse as json, validate expiry
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        payload_json = json.loads(b64decode(payload))

        expiry = datetime.fromtimestamp(payload_json["exp"])
        return reference_time < expiry

    start_time = datetime.now()
    while datetime.now() <= start_time + max_retry_time:
        with TemporaryDirectory() as tempdir:
            git_clone(git_url, tempdir)

            with Path(tempdir, "oidc-token.txt").open(encoding="utf-8") as f:
                token = f.read().rstrip()

            if is_valid_at(token, datetime.now() + min_validity):
                return token

        print(
            f"Current token expires too early, retrying in {retry_sleep_secs} seconds."
        )
        time.sleep(retry_sleep_secs)

    raise TimeoutError(f"Failed to find a valid token in {max_retry_time}")


class TestSigstoreSigner(unittest.TestCase):
    """Test public key parsing, signature creation and verification."""

    @classmethod
    def setUpClass(cls):
        cls.token = identity_token()

    def test_sign(self):
        uri, public_key = SigstoreSigner.import_(TEST_IDENTITY, TEST_ISSUER)
        with mock.patch("sigstore.oidc.detect_credential", return_value=self.token):
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
