"""Tests for lazy imports in the signer package."""

import subprocess
import sys
import unittest


class TestSignerImports(unittest.TestCase):
    def _run_python(self, source: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", source],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_base_import_does_not_load_optional_signers(self) -> None:
        result = self._run_python(
            """
import sys
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer

optional_modules = {
    "boto3",
    "azure.identity",
    "google.cloud.kms",
    "hvac",
    "pkcs11",
    "sigstore",
}
loaded = optional_modules.intersection(sys.modules)
if loaded:
    raise AssertionError(f"optional signer modules were imported: {sorted(loaded)}")

expected_schemes = {"awskms", "azurekms", "file2", "gcpkms", "gnupg", "hsm", "hv", "tkey"}
assert set(SIGNER_FOR_URI_SCHEME) == expected_schemes
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_signer_import_is_still_supported(self) -> None:
        result = self._run_python(
            """
import sys
from securesystemslib.signer import AWSSigner, SIGNER_FOR_URI_SCHEME

assert AWSSigner.SCHEME == "awskms"
assert "securesystemslib.signer._aws_signer" in sys.modules
assert SIGNER_FOR_URI_SCHEME[AWSSigner.SCHEME] is AWSSigner
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_registry_override_takes_precedence_over_builtin(self) -> None:
        result = self._run_python(
            """
import sys
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME

class CustomSigner:
    pass

SIGNER_FOR_URI_SCHEME["awskms"] = CustomSigner
assert SIGNER_FOR_URI_SCHEME["awskms"] is CustomSigner
assert "securesystemslib.signer._aws_signer" not in sys.modules
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_registry_copy_retains_builtin_entries(self) -> None:
        result = self._run_python(
            """
from securesystemslib.signer import AWSSigner, SIGNER_FOR_URI_SCHEME

registry_copy = SIGNER_FOR_URI_SCHEME.copy()
assert registry_copy.keys() == SIGNER_FOR_URI_SCHEME.keys()
assert registry_copy["awskms"] is AWSSigner
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_star_import_keeps_public_signers(self) -> None:
        result = self._run_python(
            """
namespace = {}
exec("from securesystemslib.signer import *", namespace)
expected = {"AWSSigner", "CryptoSigner", "GCPSigner", "Signer", "VaultSigner"}
assert expected.issubset(namespace)
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)
