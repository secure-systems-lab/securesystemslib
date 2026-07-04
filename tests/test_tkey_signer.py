import hashlib
import unittest
from unittest.mock import MagicMock, patch

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer import SSlibKey, TKeySigner


class TestTKeySigner(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_public_key = MagicMock(spec=SSlibKey)
        self.mock_public_key.keytype = "ml-dsa"
        self.mock_public_key.scheme = "ml-dsa-44/1"
        self.mock_public_key.keyid = "mock_keyid"
        self.mock_public_key.keyval = {"public": "mock_pubkey_pem"}

    @patch("securesystemslib.signer._tkey_signer.SignApp")
    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    def test_init_unsupported_scheme(
        self,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
        mock_sign_app_class: MagicMock,
    ) -> None:
        mock_app = MagicMock()
        mock_sign_app_class.load_mldsa.return_value = mock_app

        mock_tk_inst = MagicMock()
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tkey_class.return_value = mock_tk_inst

        # Mismatched scheme
        self.mock_public_key.scheme = "unsupported-scheme"

        with self.assertRaises(ValueError) as ctx:
            TKeySigner(
                device_path="/dev/ttyACM0",
                public_key=self.mock_public_key,
                digest="7c75714",
            )
        self.assertIn("unsupported scheme unsupported-scheme", str(ctx.exception))

    @patch("securesystemslib.signer._tkey_signer.SignApp")
    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    def test_init_public_key_mismatch(
        self,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
        mock_sign_app_class: MagicMock,
    ) -> None:
        mock_app = MagicMock()
        mock_sign_app_class.load_mldsa.return_value = mock_app

        # Mock derived key to have different keyval
        mock_derived_key = MagicMock(spec=SSlibKey)
        mock_derived_key.keyval = "different_keyval"
        mock_from_crypto.return_value = mock_derived_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tkey_class.return_value = mock_tk_inst

        self.mock_public_key.keyval = "expected_keyval"

        with self.assertRaises(RuntimeError) as ctx:
            TKeySigner(
                device_path="/dev/ttyACM0",
                public_key=self.mock_public_key,
                digest="7c75714",
            )
        self.assertIn("TKey public key does not match", str(ctx.exception))

    @patch("securesystemslib.signer._tkey_signer.TKeySigner.__init__")
    def test_from_priv_key_uri_parsing(self, mock_init: MagicMock) -> None:
        mock_init.return_value = None

        # 1. Path and digest
        TKeySigner.from_priv_key_uri(
            "tkey:/dev/ttyACM0?digest=7c75714", self.mock_public_key
        )
        mock_init.assert_called_with(
            "/dev/ttyACM0",
            public_key=self.mock_public_key,
            secrets_handler=None,
            digest="7c75714",
        )

        # 2. Digest only (auto-detect device path)
        TKeySigner.from_priv_key_uri("tkey:?digest=7c75714", self.mock_public_key)
        mock_init.assert_called_with(
            None,
            public_key=self.mock_public_key,
            secrets_handler=None,
            digest="7c75714",
        )

        # 3. Passphrase=true with secrets_handler
        secrets_handler = MagicMock(return_value="mysecret")
        TKeySigner.from_priv_key_uri(
            "tkey:?digest=7c75714&passphrase=true",
            self.mock_public_key,
            secrets_handler,
        )
        mock_init.assert_called_with(
            None,
            public_key=self.mock_public_key,
            secrets_handler=secrets_handler,
            digest="7c75714",
        )

        # 4. Passphrase=false
        mock_init.reset_mock()
        TKeySigner.from_priv_key_uri(
            "tkey:?digest=7c75714&passphrase=false",
            self.mock_public_key,
            secrets_handler,
        )
        mock_init.assert_called_with(
            None,
            public_key=self.mock_public_key,
            secrets_handler=None,
            digest="7c75714",
        )

    def test_from_priv_key_uri_failures(self) -> None:
        # Invalid scheme
        with self.assertRaises(ValueError) as ctx:
            TKeySigner.from_priv_key_uri(
                "nontkey:?digest=7c75714", self.mock_public_key
            )
        self.assertIn("does not support nontkey:", str(ctx.exception))

        # Missing digest
        with self.assertRaises(ValueError) as ctx:
            TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0", self.mock_public_key)
        self.assertIn("TKey URI must include 'digest'", str(ctx.exception))

        # Passphrase=true but no secrets_handler
        with self.assertRaises(ValueError) as ctx:
            TKeySigner.from_priv_key_uri(
                "tkey:?digest=7c75714&passphrase=true", self.mock_public_key
            )
        self.assertIn("no secrets_handler was given", str(ctx.exception))

        # Non-SSlibKey public key
        with self.assertRaises(ValueError) as ctx:
            TKeySigner.from_priv_key_uri("tkey:?digest=7c75714", MagicMock())
        self.assertIn("expected SSlibKey", str(ctx.exception))

    @patch("securesystemslib.signer._tkey_signer.SignApp")
    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    def test_import_success(
        self,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
        mock_sign_app_class: MagicMock,
    ) -> None:
        mock_app = MagicMock()
        mock_app.digest = "7c75714ca3748257bc"
        mock_sign_app_class.load_mldsa.return_value = mock_app

        mock_tk_inst = MagicMock()
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        # Mocking context manager
        mock_tkey_class.return_value.__enter__.return_value = mock_tk_inst

        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        # 1. Import with default options
        uri, key = TKeySigner.import_(digest="7c75714")
        self.assertEqual(uri, "tkey:?digest=7c75714")
        self.assertEqual(key, mock_key)
        mock_sign_app_class.load_mldsa.assert_called_with(digest="7c75714")
        mock_tkey_class.assert_called_with(mock_app, None, None)

        # 2. Import with path and passphrase
        mock_sign_app_class.load_mldsa.reset_mock()
        mock_tkey_class.reset_mock()
        uri, key = TKeySigner.import_(
            digest="7c75714", device_path="/dev/ttyACM0", passphrase="mysecret"
        )
        self.assertEqual(uri, "tkey:/dev/ttyACM0?digest=7c75714&passphrase=true")
        self.assertEqual(key, mock_key)
        mock_sign_app_class.load_mldsa.assert_called_with(digest="7c75714")
        mock_tkey_class.assert_called_with(mock_app, "/dev/ttyACM0", "mysecret")

    @patch("securesystemslib.signer._tkey_signer.TKEY_IMPORT_ERROR", "Import error")
    def test_import_import_error(self) -> None:
        with self.assertRaises(UnsupportedLibraryError) as ctx:
            TKeySigner.import_(digest="7c75714")
        self.assertIn("Import error", str(ctx.exception))

    @patch("securesystemslib.signer._tkey_signer.SignApp")
    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch("securesystemslib.signer._tkey_signer.serialization.load_pem_public_key")
    def test_sign(
        self,
        mock_load_pem: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
        mock_sign_app_class: MagicMock,
    ) -> None:
        mock_app = MagicMock()
        mock_sign_app_class.load_mldsa.return_value = mock_app

        mock_derived_key = MagicMock(spec=SSlibKey)
        mock_derived_key.keyval = self.mock_public_key.keyval
        mock_from_crypto.return_value = mock_derived_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tk_inst.sign.return_value = b"dummy_signature"
        mock_tkey_class.return_value = mock_tk_inst

        # Mock public key loading & serialization
        mock_pk = MagicMock()
        mock_pk.public_bytes.return_value = b"raw_pk_bytes"
        mock_load_pem.return_value = mock_pk

        # Instantiate signer
        signer = TKeySigner(
            device_path="/dev/ttyACM0",
            public_key=self.mock_public_key,
            digest="7c75714",
        )

        # Call sign
        signature = signer.sign(b"mypayload")
        self.assertEqual(signature.keyid, "mock_keyid")
        self.assertEqual(signature.signature, b"dummy_signature".hex())

        # Check serialization parameters
        mock_load_pem.assert_called_once_with(b"mock_pubkey_pem")

        # Check sign parameters (SHA512 of payload with prefix)
        digest = hashlib.sha512(b"mypayload").digest()
        expected_tuf_msg = b"tuf" + bytes([1]) + digest
        mock_tk_inst.sign.assert_called_once_with(expected_tuf_msg, b"raw_pk_bytes")


if __name__ == "__main__":
    unittest.main()
