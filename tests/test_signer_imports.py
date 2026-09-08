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

assert isinstance(SIGNER_FOR_URI_SCHEME, dict)
assert not SIGNER_FOR_URI_SCHEME
assert "securesystemslib.signer._crypto_signer" not in sys.modules
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
assert not SIGNER_FOR_URI_SCHEME
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_registry_override_takes_precedence_over_builtin(self) -> None:
        result = self._run_python(
            """
import sys
from unittest.mock import Mock, sentinel
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer

class CustomSigner:
    from_priv_key_uri = Mock(return_value=sentinel.signer)

for scheme in ("awskms", "custom"):
    SIGNER_FOR_URI_SCHEME[scheme] = CustomSigner
    uri = f"{scheme}:key"
    assert Signer.from_priv_key_uri(uri, sentinel.key, sentinel.handler) is sentinel.signer
    CustomSigner.from_priv_key_uri.assert_called_with(uri, sentinel.key, sentinel.handler)
assert "securesystemslib.signer._aws_signer" not in sys.modules
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_factory_loads_and_caches_builtin(self) -> None:
        result = self._run_python(
            """
import sys
from unittest.mock import patch, sentinel
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer
from securesystemslib.signer import _signer

assert "securesystemslib.signer._aws_signer" not in sys.modules
original_import = _signer.importlib.import_module

with patch.object(_signer.importlib, "import_module", wraps=original_import) as load:
    with patch("securesystemslib.signer._aws_signer.AWSSigner.from_priv_key_uri", return_value=sentinel.signer) as factory:
        load.reset_mock()
        for _ in range(2):
            assert Signer.from_priv_key_uri("awskms:key", sentinel.key, sentinel.handler) is sentinel.signer
        factory.assert_called_with("awskms:key", sentinel.key, sentinel.handler)
        load.assert_called_once_with("securesystemslib.signer._aws_signer")

from securesystemslib.signer import AWSSigner
assert SIGNER_FOR_URI_SCHEME == {"awskms": AWSSigner}

registry_copy = SIGNER_FOR_URI_SCHEME.copy()
SIGNER_FOR_URI_SCHEME.clear()
assert registry_copy == {"awskms": AWSSigner}
with patch.object(AWSSigner, "from_priv_key_uri", return_value=sentinel.signer):
    assert Signer.from_priv_key_uri("awskms:key", sentinel.key) is sentinel.signer
assert SIGNER_FOR_URI_SCHEME == registry_copy
assert "securesystemslib.signer._gcp_signer" not in sys.modules
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_factory_errors(self) -> None:
        result = self._run_python(
            """
import unittest
from unittest.mock import patch, sentinel
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer

case = unittest.TestCase()
with patch("securesystemslib.signer._signer.importlib.import_module") as load:
    with case.assertRaisesRegex(ValueError, "Unsupported private key scheme unknown"):
        Signer.from_priv_key_uri("unknown:key", sentinel.key)
    load.assert_not_called()

    load.side_effect = ImportError("missing optional dependency")
    with case.assertRaisesRegex(ImportError, "missing optional dependency"):
        Signer.from_priv_key_uri("awskms:key", sentinel.key)
    assert "awskms" not in SIGNER_FOR_URI_SCHEME
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
