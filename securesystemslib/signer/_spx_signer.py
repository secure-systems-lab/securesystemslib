"""Signer implementation for project SPHINCS+ post-quantum signature support.

"""
import logging
import os
from typing import Any, Dict, Optional

from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer._key import Key
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

SPX_IMPORT_ERROR = None
try:
    from pyspx import shake_128s
except ImportError:
    SPX_IMPORT_ERROR = "spinhcs+ key support requires the pyspx library"

_SHAKE_SEED_LEN = 48

logger = logging.getLogger(__name__)


class SpxKey(Key):
    """SPHINCS+ verifier."""

    DEFAULT_KEY_TYPE = "sphincs"
    DEFAULT_SCHEME = "sphincs-shake-128s"

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "SpxKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        valid = None
        try:
            if SPX_IMPORT_ERROR:
                raise UnsupportedLibraryError(SPX_IMPORT_ERROR)

            key = bytes.fromhex(self.keyval["public"])
            sig = bytes.fromhex(signature.signature)

            valid = shake_128s.verify(data, sig, key)

        except Exception as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e

        if not valid:
            raise UnverifiedSignatureError(
                f"Failed to verify signature by {self.keyid}"
            )


class SpxSigner(Signer):
    """SPHINCS+ signer.

    Usage::

        signer = SpxSigner.new_()
        signature = signer.sign(b"payload")

        # Use public_key.to_dict() / Key.from_dict() to transport public key data
        public_key = signer.public_key
        public_key.verify_signature(signature, b"payload")

    """

    def __init__(self, private: bytes, public: SpxKey):
        self.private_key = private
        self.public_key = public

    @classmethod
    def new_(cls) -> "SpxSigner":
        """Generate new SPHINCS+ key pair and return as SpxSigner.

        NOTE: The Signer API is still experimental and key generation in
        particular (see #466).
        """
        if SPX_IMPORT_ERROR:
            raise UnsupportedLibraryError(SPX_IMPORT_ERROR)

        seed = os.urandom(_SHAKE_SEED_LEN)
        public, private = shake_128s.generate_keypair(seed)

        keytype = SpxKey.DEFAULT_KEY_TYPE
        scheme = SpxKey.DEFAULT_SCHEME
        keyval = {"public": public.hex()}

        keyid = cls._get_keyid(keytype, scheme, keyval)
        public_key = SpxKey(keyid, keytype, scheme, keyval)

        return cls(private, public_key)

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "SpxSigner":
        raise NotImplementedError

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with SPHINCS+ private key on the instance.

        Arguments:
            payload: bytes to be signed.

        Raises:
            UnsupportedLibraryError: PySPX is not available.

        Returns:
            Signature.

        """
        if SPX_IMPORT_ERROR:
            raise UnsupportedLibraryError(SPX_IMPORT_ERROR)

        raw = shake_128s.sign(payload, self.private_key)
        return Signature(self.public_key.keyid, raw.hex())
