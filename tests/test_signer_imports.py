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
import securesystemslib.signer as signer_package

assert dir(signer_package) == sorted(signer_package.__all__)

signer_modules = {
    "securesystemslib.signer._aws_signer",
    "securesystemslib.signer._azure_signer",
    "securesystemslib.signer._crypto_signer",
    "securesystemslib.signer._gcp_signer",
    "securesystemslib.signer._hsm_signer",
    "securesystemslib.signer._sigstore_signer",
    "securesystemslib.signer._tkey_signer",
    "securesystemslib.signer._vault_signer",
}
loaded = signer_modules.intersection(sys.modules)
if loaded:
    raise AssertionError(f"optional signer modules were imported: {sorted(loaded)}")

assert isinstance(SIGNER_FOR_URI_SCHEME, dict)
expected_schemes = {"awskms", "azurekms", "file2", "gcpkms", "gnupg", "hsm", "hv", "tkey"}
assert set(SIGNER_FOR_URI_SCHEME) == expected_schemes
assert "securesystemslib.signer._gpg_signer" in sys.modules
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
assert "awskms" in SIGNER_FOR_URI_SCHEME
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
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch, sentinel
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer

assert "securesystemslib.signer._aws_signer" not in sys.modules

class TestSigner:
    from_priv_key_uri = Mock(return_value=sentinel.signer)

module = SimpleNamespace(AWSSigner=TestSigner)
with patch("securesystemslib.signer._signer.importlib.import_module", return_value=module) as load:
    for _ in range(2):
        assert Signer.from_priv_key_uri("awskms:key", sentinel.key, sentinel.handler) is sentinel.signer
    TestSigner.from_priv_key_uri.assert_called_with("awskms:key", sentinel.key, sentinel.handler)
    load.assert_called_once_with("securesystemslib.signer._aws_signer")

assert SIGNER_FOR_URI_SCHEME["awskms"] is TestSigner

registry_copy = SIGNER_FOR_URI_SCHEME.copy()
assert registry_copy["awskms"] is TestSigner
assert set(registry_copy) == {"awskms", "azurekms", "file2", "gcpkms", "gnupg", "hsm", "hv", "tkey"}
assert SIGNER_FOR_URI_SCHEME == registry_copy
assert "securesystemslib.signer._gcp_signer" not in sys.modules

del SIGNER_FOR_URI_SCHEME["awskms"]
with patch("securesystemslib.signer._signer.importlib.import_module") as load:
    with unittest.TestCase().assertRaisesRegex(ValueError, "Unsupported private key scheme awskms"):
        Signer.from_priv_key_uri("awskms:key", sentinel.key)
    load.assert_not_called()
assert registry_copy["awskms"] is TestSigner
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_registry_removal_disables_builtin(self) -> None:
        result = self._run_python(
            """
from unittest.mock import patch, sentinel
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer

del SIGNER_FOR_URI_SCHEME["awskms"]
with patch("securesystemslib.signer._signer.importlib.import_module") as load:
    try:
        Signer.from_priv_key_uri("awskms:key", sentinel.key)
    except ValueError as error:
        assert str(error) == "Unsupported private key scheme awskms"
    else:
        raise AssertionError("disabled built-in signer was loaded")
    load.assert_not_called()

SIGNER_FOR_URI_SCHEME.clear()
with patch("securesystemslib.signer._signer.importlib.import_module") as load:
    try:
        Signer.from_priv_key_uri("gcpkms:key", sentinel.key)
    except ValueError as error:
        assert str(error) == "Unsupported private key scheme gcpkms"
    else:
        raise AssertionError("cleared built-in signer was loaded")
    load.assert_not_called()
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signer_modules_can_be_imported(self) -> None:
        result = self._run_python(
            """
import importlib

for module_name in (
    "_aws_signer",
    "_azure_signer",
    "_crypto_signer",
    "_gcp_signer",
    "_hsm_signer",
    "_sigstore_signer",
    "_tkey_signer",
    "_vault_signer",
):
    importlib.import_module(f"securesystemslib.signer.{module_name}")
"""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_factory_errors(self) -> None:
        result = self._run_python(
            """
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch, sentinel
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer

case = unittest.TestCase()
lazy_entry = SIGNER_FOR_URI_SCHEME["awskms"]
with patch("securesystemslib.signer._signer.importlib.import_module") as load:
    with case.assertRaisesRegex(ValueError, "Unsupported private key scheme unknown"):
        Signer.from_priv_key_uri("unknown:key", sentinel.key)
    load.assert_not_called()

    load.side_effect = ImportError("missing optional dependency")
    with case.assertRaisesRegex(ImportError, "missing optional dependency"):
        Signer.from_priv_key_uri("awskms:key", sentinel.key)
    assert SIGNER_FOR_URI_SCHEME["awskms"] == lazy_entry

    class TestSigner:
        from_priv_key_uri = Mock(return_value=sentinel.signer)

    load.side_effect = None
    load.return_value = SimpleNamespace(AWSSigner=TestSigner)
    assert Signer.from_priv_key_uri("awskms:key", sentinel.key) is sentinel.signer
    assert SIGNER_FOR_URI_SCHEME["awskms"] is TestSigner
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
