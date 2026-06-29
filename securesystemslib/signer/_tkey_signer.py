"""ML-DSA-44 Signer for Tillitis TKey"""

from __future__ import annotations

import hashlib
import logging
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

TKEY_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey
    from keylet import SignApp, TKeySign
except ImportError as e:
    TKEY_IMPORT_ERROR = f"TKeySigner: {e}"


logger = logging.getLogger(__name__)


class TKeySigner(Signer):
    """Tillitis TKey Signer.

    Supports signing scheme "ml-dsa-44/1".

    The private key URI is
        tkey:[device_path]?digest=<hex_prefix>&[passphrase=true]

    digest is required in the URI: The device binary (identified by its
    digest hash prefix) is part of the private key seed. A key can only
    be used with the same exact binary.

    device_path is not required and is not typically useful as the device association
    may be dynamic.

    Examples:
        tkey:?digest=7c75714
        tkey:?digest=7c75714&passphrase=true
        tkey:/dev/ttyACM0?digest=7c75714&passphrase=true
    """

    SCHEME = "tkey"

    def __init__(
        self,
        device_path: str | None,
        public_key: SSlibKey,
        secrets_handler: SecretsHandler | None = None,
        digest: str | None = None,
    ) -> None:
        if TKEY_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEY_IMPORT_ERROR)

        self._public_key = public_key

        passphrase = secrets_handler("Passphrase") if secrets_handler else None
        app = SignApp.load_mldsa(digest=digest)
        self._tkey = TKeySign(app, device_path, passphrase)

        # key derivation depends on passphrase: compare keys to make sure
        raw_pubkey = self._tkey.get_pubkey()
        if public_key.scheme == "ml-dsa-44/1":
            key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))
        else:
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        if key.keyval != self.public_key.keyval:
            raise RuntimeError(
                "TKey public key does not match: This could mean incorrect Passphrase."
            )

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> TKeySigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)
        if uri.scheme != cls.SCHEME:
            raise ValueError(f"TKeySigner does not support {priv_key_uri}")

        # Extract device path (empty or "/" triggers auto-detect)
        device_path = uri.path if uri.path not in ("", "/") else None

        # Extract query parameters
        query_params = parse.parse_qs(uri.query)

        digest = None
        if "digest" in query_params:
            digest = query_params["digest"][0]

        if digest is None:
            raise ValueError("TKey URI must include 'digest'")

        pass_str = query_params.get("passphrase", ["false"])[0]
        if pass_str.lower() != "true":
            secrets_handler = None
        elif secrets_handler is None:
            raise ValueError(
                "TKey URI has 'passphrase' but no secrets_handler was given"
            )

        return cls(
            device_path,
            public_key=public_key,
            secrets_handler=secrets_handler,
            digest=digest,
        )

    @classmethod
    def import_(
        cls,
        digest: str | None = None,
        device_path: str | None = None,
        passphrase: str | None = None,
    ) -> tuple[str, SSlibKey]:
        """Import public key and signer details from a TKey device.

        Args:
            digest: Optional digest or digest prefix of device binary.
            device_path: Optional COM port path. Typically not useful as the port may
                be dynamic
            passphrase: Optional "User Supplied Secret". Will be used as part of the
                seed for the private key
        """
        if TKEY_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEY_IMPORT_ERROR)

        app = SignApp.load_mldsa(digest=digest)
        with TKeySign(app, device_path, passphrase) as tk:
            raw_pubkey = tk.get_pubkey()

        # Build URI with digest prefix and optional passphrase boolean
        query = {"digest": app.digest[:7]}

        if passphrase is not None:
            query["passphrase"] = "true"  # noqa: S105

        key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))

        # Only encode path if it was explicitly passed as argument
        path = device_path if device_path is not None else ""
        uri = f"{cls.SCHEME}:{path}?{parse.urlencode(query)}"

        return uri, key

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Tillitis TKey."""

        # Use TUF-specific message prefix and digest as payload
        digest = hashlib.sha512(payload).digest()
        msg = b"tuf" + bytes([1]) + digest

        # Provide the pub key bytes for mu calculation
        pk_pem = self.public_key.keyval["public"].encode("utf-8")
        public_key = serialization.load_pem_public_key(pk_pem)
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        sig_bytes = self._tkey.sign(msg, key_bytes)
        return Signature(self.public_key.keyid, sig_bytes.hex())
