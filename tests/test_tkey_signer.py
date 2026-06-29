import hashlib
import unittest
from unittest.mock import MagicMock, patch
from urllib import parse

from keylet.tkey import (
    PROTO_DATA_LENGTH,
    FwCmd,
    FwRsp,
    Rsp,
    TKey,
    TKeyError,
)
from keylet.tkey_sign import (
    SignApp,
    SignRsp,
    TKeySign,
)

from securesystemslib.signer import SSlibKey, TKeySigner


def make_response_frame(
    fid: int,
    eid: int,
    status: int,
    rsp: Rsp,
    data: bytes = b"",
) -> bytes:
    header = (fid << 5) | (eid << 3) | (status << 2) | rsp.len_idx
    resp_len = PROTO_DATA_LENGTH[rsp.len_idx]
    resp_data = bytearray(resp_len)
    resp_data[0] = rsp.id
    if data:
        resp_data[1 : 1 + len(data)] = data
    return bytes([header]) + bytes(resp_data)


class MockStreamConnection:
    def __init__(self, reads: list[bytes]) -> None:
        self.reads = reads
        self.written = bytearray()
        self.timeout = 5.0

    def write(self, data: bytes) -> int:
        self.written.extend(data)
        return len(data)

    def read(self, n: int) -> bytes:
        if not self.reads:
            return b""
        block = self.reads[0]
        chunk = block[:n]
        if len(chunk) == len(block):
            self.reads.pop(0)
        else:
            self.reads[0] = block[n:]
        return chunk

    def close(self) -> None:
        pass

    @property
    def in_waiting(self) -> int:
        return sum(len(b) for b in self.reads)


class TestTKeySignerOffline(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_public_key = MagicMock(spec=SSlibKey)
        self.mock_public_key.keytype = "ml-dsa"
        self.mock_public_key.scheme = "ml-dsa-44/1"
        self.mock_public_key.keyid = "mock_keyid"
        self.mock_public_key.keyval = {"public": "mock_pubkey_pem"}

    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_from_priv_key_uri_parsing(
        self,
        mock_load_mldsa: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        mock_key = MagicMock(spec=SSlibKey)
        mock_key.keyval = self.mock_public_key.keyval
        mock_from_crypto.return_value = mock_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tkey_class.return_value = mock_tk_inst

        # path and digest
        TKeySigner.from_priv_key_uri(
            "tkey:/dev/ttyACM0?digest=7c75714", self.mock_public_key
        )
        mock_tkey_class.assert_called_with(
            SignApp(b"dummy", None, ("test", "app"), 10, 20), "/dev/ttyACM0", None
        )

        # digest only
        TKeySigner.from_priv_key_uri("tkey:?digest=7c75714", self.mock_public_key)
        mock_tkey_class.assert_called_with(SignApp(b"dummy", None, ("test", "app"), 10, 20), None, None)

        # No digest
        with self.assertRaises(ValueError):
            TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0", self.mock_public_key)

        # passphrase=true without secrets_handler should raise ValueError
        with self.assertRaises(ValueError) as ctx:
            TKeySigner.from_priv_key_uri(
                "tkey:/dev/ttyACM0?digest=7c75714&passphrase=true",
                self.mock_public_key,
            )
        self.assertIn("no secrets_handler was given", str(ctx.exception))

        # passphrase=true with secrets_handler
        secrets_handler = MagicMock(return_value="mysecret")
        TKeySigner.from_priv_key_uri(
            "tkey:/dev/ttyACM0?digest=7c75714&passphrase=true",
            self.mock_public_key,
            secrets_handler,
        )
        secrets_handler.assert_called_once_with("Passphrase")
        mock_tkey_class.assert_called_with(
            SignApp(b"dummy", None, ("test", "app"), 10, 20), "/dev/ttyACM0", "mysecret"
        )

        # passphrase=false
        mock_tkey_class.reset_mock()
        secrets_handler.reset_mock()
        TKeySigner.from_priv_key_uri(
            "tkey:/dev/ttyACM0?digest=7c75714&passphrase=false",
            self.mock_public_key,
            secrets_handler,
        )
        secrets_handler.assert_not_called()
        mock_tkey_class.assert_called_with(
            SignApp(b"dummy", None, ("test", "app"), 10, 20), "/dev/ttyACM0", None
        )

    @patch.object(TKey, "_get_connection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySign, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch.object(TKeySign, "_find_device", return_value="/dev/ttyACM0")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_import_with_app_already_loaded(  # noqa: PLR0913
        self,
        mock_load_mldsa: MagicMock,
        mock_find_device: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        # Prepare connection mock (needs enough reads for two sequential import calls)
        app_name_payload = b"tk1 " + b"pqsn" + (3).to_bytes(4, byteorder="little")
        app_response = make_response_frame(
            fid=2,
            eid=3,
            status=0,
            rsp=SignRsp.GET_NAMEVERSION,
            data=app_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[b"", app_response, b"", app_response])
        mock_conn_class.return_value = mock_conn

        # Mock keys
        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(TKey, "load_app") as mock_load_app:
            # 1. Explicit path
            uri, key = TKeySigner.import_(digest="7c75714", device_path="/dev/ttyACM0")
            self.assertEqual(uri, "tkey:/dev/ttyACM0?digest=7c75714")
            self.assertEqual(key, mock_key)

            mock_load_app.assert_called_with(b"dummy", None)

            # 2. Auto-detect path
            uri, key = TKeySigner.import_(digest="7c75714")
            self.assertEqual(uri, "tkey:?digest=7c75714")
            self.assertEqual(key, mock_key)

            mock_load_app.assert_called_with(b"dummy", None)

    @patch.object(TKey, "_get_connection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySign, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeySign, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_import_with_app_loaded_mismatched_version(  # noqa: PLR0913
        self,
        mock_load_mldsa: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_find_device: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        # Setup serial response: GET_NAMEVERSION returns version 3
        app_name_payload = b"tk1 " + b"pqsn" + (3).to_bytes(4, byteorder="little")
        app_response = make_response_frame(
            fid=2,
            eid=3,
            status=0,
            rsp=SignRsp.GET_NAMEVERSION,
            data=app_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[b"", app_response])
        mock_conn_class.return_value = mock_conn

        # Request version 5, which is running version 4. Should raise TKeyError.
        with self.assertRaises(TKeyError) as ctx:
            TKeySigner.import_(digest="different_digest")
        self.assertIn("unknown application", str(ctx.exception))

    @patch.object(TKey, "_get_connection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySign, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeySign, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_import_in_firmware_mode_loads_correct_version(  # noqa: PLR0913
        self,
        mock_load_mldsa: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_find_device: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        # Setup serial response: NAME_VERSION FW command succeeds
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=2,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[fw_response])
        mock_conn_class.return_value = mock_conn

        # Mock keys
        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(TKey, "load_app") as mock_load_app:
            uri, key = TKeySigner.import_(digest="7c75714")
            self.assertEqual(uri, "tkey:?digest=7c75714")
            self.assertEqual(key, mock_key)

            # Verify that _load_app was called with the dummy
            mock_load_app.assert_called_once_with(b"dummy", None)

    @patch.object(TKey, "_get_connection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySign, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeySign, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_import_with_passphrase(  # noqa: PLR0913
        self,
        mock_load_mldsa: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_find_device: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        # Setup serial response: NAME_VERSION FW command succeeds
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=2,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[fw_response])
        mock_conn_class.return_value = mock_conn

        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(TKey, "load_app") as mock_load_app:
            uri, key = TKeySigner.import_(digest="7c75714", passphrase="mysecret")
            parsed = parse.urlparse(uri)
            query = parse.parse_qs(parsed.query)
            self.assertEqual(query.get("digest"), ["7c75714"])
            self.assertEqual(query.get("passphrase"), ["true"])
            self.assertEqual(key, mock_key)

            # Verify that _load_app was called with secret and dummy
            mock_load_app.assert_called_once_with(b"dummy", "mysecret")

    @patch.object(TKey, "_get_connection")
    @patch.object(TKeySign, "_find_device", return_value="/dev/ttyACM0")
    def test_load_app_hashes_secret(
        self,
        mock_find_device: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        # Set up responses for:
        # 1. NAME_VERSION (FW mode check)
        # 2. LOAD_APP
        # 3. LOAD_APP_DATA (only one chunk because file size is small)
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=2,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )

        load_app_response = make_response_frame(
            fid=2,
            eid=2,
            status=0,
            rsp=FwRsp.LOAD_APP,
            data=b"\x00",
        )

        file_digest = hashlib.blake2s(b"mock_app_data", digest_size=32).digest()
        load_app_data_response = make_response_frame(
            fid=3,
            eid=2,
            status=0,
            rsp=FwRsp.LOAD_APP_DATA_READY,
            data=b"\x00" + file_digest,
        )

        mock_conn = MockStreamConnection(
            reads=[fw_response, load_app_response, load_app_data_response]
        )
        mock_conn_class.return_value = mock_conn

        secret = "my_super_secret_passphrase"
        # We instantiate _TKey which should call _ensure_app_loaded -> _load_app
        tk = TKeySign(app=SignApp(b"mock_app_data", 3, ("test", "app"), 10, 20), device=None, secret=secret)
        tk.disconnect()

        # Now, let's inspect the written data for the LOAD_APP command.
        written_bytes = bytes(mock_conn.written)

        # First frame (NAME_VERSION): header + 1 byte data (FwCmd.NAME_VERSION) -> PROTO_DATA_LENGTH[0] is 1.
        # So total frame size: 1 + 1 = 2 bytes.
        # Second frame (LOAD_APP): header + 128 bytes (FwCmd.LOAD_APP + 127 bytes payload).
        # PROTO_DATA_LENGTH[3] is 128.
        # So total frame size: 1 + 128 = 129 bytes.
        # Let's extract this frame: it starts at index 2, length 129.
        load_app_frame = written_bytes[2 : 2 + 129]

        self.assertEqual(load_app_frame[0], 0x53)
        self.assertEqual(load_app_frame[1], FwCmd.LOAD_APP.id)

        # Let's check the data payload.
        expected_hashed_secret = hashlib.blake2s(
            secret.encode("utf-8"), digest_size=32
        ).digest()

        payload = load_app_frame[2:]
        self.assertEqual(payload[0:4], (13).to_bytes(4, byteorder="little"))
        self.assertEqual(payload[4], 1)
        self.assertEqual(payload[5 : 5 + 32], expected_hashed_secret)

    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch("securesystemslib.signer._tkey_signer.serialization.load_pem_public_key")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_sign_with_passphrase(
        self,
        mock_load_mldsa: MagicMock,
        mock_load_pem: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        mock_key = MagicMock(spec=SSlibKey)
        mock_key.keyval = self.mock_public_key.keyval
        mock_from_crypto.return_value = mock_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tk_inst.sign.return_value = b"dummy_signature"
        mock_tkey_class.return_value = mock_tk_inst

        # mock serialization.load_pem_public_key
        mock_pk = MagicMock()
        mock_pk.public_bytes.return_value = b"raw_pk_bytes"
        mock_load_pem.return_value = mock_pk

        secrets_handler = MagicMock(return_value="mysecret")
        signer = TKeySigner(
            device_path="/dev/ttyACM0",
            public_key=self.mock_public_key,
            secrets_handler=secrets_handler,
            digest="7c75714",
        )

        signature = signer.sign(b"mypayload")
        self.assertEqual(signature.keyid, "mock_keyid")
        self.assertEqual(signature.signature, b"dummy_signature".hex())

        # secrets_handler should have been called with "uss" during construction
        secrets_handler.assert_called_once_with("Passphrase")
        mock_tkey_class.assert_called_once_with(
            SignApp(b"dummy", None, ("test", "app"), 10, 20), "/dev/ttyACM0", "mysecret"
        )

        # _TKey.sign should have been called with expected tuf formatted message and pk_bytes
        digest = hashlib.sha512(b"mypayload").digest()
        expected_tuf_msg = b"tuf" + bytes([1]) + digest
        mock_tk_inst.sign.assert_called_once_with(expected_tuf_msg, b"raw_pk_bytes")

    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch("securesystemslib.signer._tkey_signer.serialization.load_pem_public_key")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_sign_without_passphrase(
        self,
        mock_load_mldsa: MagicMock,
        mock_load_pem: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        mock_key = MagicMock(spec=SSlibKey)
        mock_key.keyval = self.mock_public_key.keyval
        mock_from_crypto.return_value = mock_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tk_inst.sign.return_value = b"dummy_signature"
        mock_tkey_class.return_value = mock_tk_inst

        # mock serialization.load_pem_public_key
        mock_pk = MagicMock()
        mock_pk.public_bytes.return_value = b"raw_pk_bytes"
        mock_load_pem.return_value = mock_pk

        signer = TKeySigner(
            device_path="/dev/ttyACM0",
            public_key=self.mock_public_key,
            digest="7c75714",
        )

        signature = signer.sign(b"mypayload")
        self.assertEqual(signature.keyid, "mock_keyid")
        self.assertEqual(signature.signature, b"dummy_signature".hex())

        # _TKey constructor should have been called with secret=None and expected app
        mock_tkey_class.assert_called_once_with(
            SignApp(b"dummy", None, ("test", "app"), 10, 20), "/dev/ttyACM0", None
        )

        # _TKey.sign should have been called with expected tuf formatted message and pk_bytes
        digest = hashlib.sha512(b"mypayload").digest()
        expected_tuf_msg = b"tuf" + bytes([1]) + digest
        mock_tk_inst.sign.assert_called_once_with(expected_tuf_msg, b"raw_pk_bytes")

    @patch("securesystemslib.signer._tkey_signer.TKeySign")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch("securesystemslib.signer._tkey_signer.SignApp.load_mldsa")
    def test_init_public_key_mismatch(
        self,
        mock_load_mldsa: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_load_mldsa.side_effect = lambda version=None, digest=None: SignApp(
            b"dummy", version, ("test", "app"), 10, 20
        )
        # Mock the derived key to have a mismatched keyval
        mock_derived_key = MagicMock(spec=SSlibKey)
        mock_derived_key.keyval = "mismatched_keyval"
        mock_from_crypto.return_value = mock_derived_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tkey_class.return_value = mock_tk_inst

        # The signer public key has a different keyval
        self.mock_public_key.keyval = "expected_keyval"

        with self.assertRaises(RuntimeError) as ctx:
            TKeySigner(
                device_path="/dev/ttyACM0",
                public_key=self.mock_public_key,
                digest="7c75714",
            )
        self.assertIn("TKey public key does not match", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
