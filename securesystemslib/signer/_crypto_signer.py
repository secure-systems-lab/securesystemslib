"""Signer implementation for pyca/cryptography signing. """

import logging
from abc import ABCMeta
from typing import Any, Dict, Optional, cast
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        EllipticCurvePrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key as generate_ec_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import (
        MGF1,
        PSS,
        AsymmetricPadding,
        PKCS1v15,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        AsymmetricPadding,
        RSAPrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        generate_private_key as generate_rsa_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
    from cryptography.hazmat.primitives.hashes import (
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        HashAlgorithm,
    )
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )
except ImportError:
    CRYPTO_IMPORT_ERROR = "'pyca/cryptography' library required"

logger = logging.getLogger(__name__)


class CryptoSigner(Signer, metaclass=ABCMeta):
    """Base class for PYCA/cryptography Signer implementations."""

    FILE_URI_SCHEME = "file"

    def __init__(self, public_key: SSlibKey):
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        self.public_key = public_key

    @classmethod
    def from_securesystemslib_key(
        cls, key_dict: Dict[str, Any]
    ) -> "CryptoSigner":
        """Factory to create CryptoSigner from securesystemslib private key dict."""
        private = key_dict["keyval"]["private"]
        public_key = SSlibKey.from_securesystemslib_key(key_dict)

        private_key: PrivateKeyTypes
        if public_key.keytype == "rsa":
            private_key = cast(
                RSAPrivateKey,
                load_pem_private_key(private.encode(), password=None),
            )
            return _RSASigner(public_key, private_key)

        if public_key.keytype == "ecdsa":
            private_key = cast(
                EllipticCurvePrivateKey,
                load_pem_private_key(private.encode(), password=None),
            )
            return _ECDSASigner(public_key, private_key)

        if public_key.keytype == "ed25519":
            private_key = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(private)
            )
            return _Ed25519Signer(public_key, private_key)

        raise ValueError(f"unsupported keytype: {public_key.keytype}")

    @classmethod
    def _from_pem(
        cls, private_pem: bytes, secret: Optional[bytes], public_key: SSlibKey
    ):
        """Helper factory to create CryptoSigner from private PEM."""
        private_key = load_pem_private_key(private_pem, secret)

        if public_key.keytype == "rsa":
            return _RSASigner(public_key, cast(RSAPrivateKey, private_key))

        if public_key.keytype == "ecdsa":
            return _ECDSASigner(
                public_key, cast(EllipticCurvePrivateKey, private_key)
            )

        if public_key.keytype == "ed25519":
            return _Ed25519Signer(
                public_key, cast(Ed25519PrivateKey, private_key)
            )

        raise ValueError(f"unsupported keytype: {public_key.keytype}")

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "CryptoSigner":
        """Constructor for Signer to call

        Please refer to Signer.from_priv_key_uri() documentation.

        NOTE: pyca/cryptography is used to deserialize the key data. The
        expected (and tested) encoding/format is PEM/PKCS8. Other formats may
        but are not guaranteed to work.

        Additionally raises:
            UnsupportedLibraryError: pyca/cryptography not installed
            OSError: file cannot be read
            ValueError: various errors passed arguments
            ValueError, TypeError, \
                    cryptography.exceptions.UnsupportedAlgorithm:
                pyca/cryptography deserialization failed

        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.FILE_URI_SCHEME:
            raise ValueError(f"CryptoSigner does not support {priv_key_uri}")

        params = dict(parse.parse_qsl(uri.query))

        if "encrypted" not in params:
            raise ValueError(f"{uri.scheme} requires 'encrypted' parameter")

        secret = None
        if params["encrypted"] != "false":
            if not secrets_handler:
                raise ValueError("encrypted key requires a secrets handler")

            secret = secrets_handler("passphrase").encode()

        with open(uri.path, "rb") as f:
            private_pem = f.read()

        return cls._from_pem(private_pem, secret, public_key)

    @staticmethod
    def generate_ed25519(
        keyid: Optional[str] = None,
    ) -> "CryptoSigner":
        """Generate new key pair as "ed25519" signer.

        Args:
            keyid: Key identifier. If not passed, a default keyid is computed.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed

        Returns:
            ED25519Signer
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        private_key = Ed25519PrivateKey.generate()
        public_key = SSlibKey._from_crypto_public_key(  # pylint: disable=protected-access
            private_key.public_key(), keyid, "ed25519"
        )
        return _Ed25519Signer(public_key, private_key)

    @staticmethod
    def generate_rsa(
        keyid: Optional[str] = None,
        scheme: Optional[str] = "rsassa-pss-sha256",
        size: int = 3072,
    ) -> "CryptoSigner":
        """Generate new key pair as rsa signer.

        Args:
            keyid: Key identifier. If not passed, a default keyid is computed.
            scheme: RSA signing scheme. Default is "rsassa-pss-sha256".
            size: RSA key size in bits. Default is 3072.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed

        Returns:
            RSASigner
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        private_key = generate_rsa_private_key(
            public_exponent=65537,
            key_size=size,
        )
        public_key = SSlibKey._from_crypto_public_key(  # pylint: disable=protected-access
            private_key.public_key(), keyid, scheme
        )
        return _RSASigner(public_key, private_key)

    @staticmethod
    def generate_ecdsa(
        keyid: Optional[str] = None,
    ) -> "CryptoSigner":
        """Generate new key pair as "ecdsa-sha2-nistp256" signer.

        Args:
            keyid: Key identifier. If not passed, a default keyid is computed.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed

        Returns:
            ECDSASigner
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        private_key = generate_ec_private_key(SECP256R1())
        public_key = SSlibKey._from_crypto_public_key(  # pylint: disable=protected-access
            private_key.public_key(), keyid, "ecdsa-sha2-nistp256"
        )
        return _ECDSASigner(public_key, private_key)


class _RSASigner(CryptoSigner):
    """Internal pyca/cryptography rsa signer implementation"""

    def __init__(self, public_key: SSlibKey, private_key: "RSAPrivateKey"):
        if public_key.scheme not in [
            "rsassa-pss-sha224",
            "rsassa-pss-sha256",
            "rsassa-pss-sha384",
            "rsassa-pss-sha512",
            "rsa-pkcs1v15-sha224",
            "rsa-pkcs1v15-sha256",
            "rsa-pkcs1v15-sha384",
            "rsa-pkcs1v15-sha512",
        ]:
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        super().__init__(public_key)
        self._private_key = private_key
        padding_name, hash_name = public_key.scheme.split("-")[1:]
        self._algorithm = self._get_hash_algorithm(hash_name)
        self._padding = self._get_rsa_padding(padding_name, self._algorithm)

    @staticmethod
    def _get_hash_algorithm(name: str) -> "HashAlgorithm":
        """Helper to return hash algorithm for name."""
        algorithm: HashAlgorithm
        if name == "sha224":
            algorithm = SHA224()
        if name == "sha256":
            algorithm = SHA256()
        if name == "sha384":
            algorithm = SHA384()
        if name == "sha512":
            algorithm = SHA512()

        return algorithm

    @staticmethod
    def _get_rsa_padding(
        name: str, hash_algorithm: "HashAlgorithm"
    ) -> "AsymmetricPadding":
        """Helper to return rsa signature padding for name."""
        padding: AsymmetricPadding
        if name == "pss":
            padding = PSS(
                mgf=MGF1(hash_algorithm), salt_length=PSS.DIGEST_LENGTH
            )

        if name == "pkcs1v15":
            padding = PKCS1v15()

        return padding

    def sign(self, payload: bytes) -> Signature:
        sig = self._private_key.sign(payload, self._padding, self._algorithm)
        return Signature(self.public_key.keyid, sig.hex())


class _ECDSASigner(CryptoSigner):
    """Internal pyca/cryptography ecdsa signer implementation"""

    def __init__(
        self, public_key: SSlibKey, private_key: "EllipticCurvePrivateKey"
    ):
        if public_key.scheme != "ecdsa-sha2-nistp256":
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        super().__init__(public_key)
        self._private_key = private_key
        self._signature_algorithm = ECDSA(SHA256())

    def sign(self, payload: bytes) -> Signature:
        sig = self._private_key.sign(payload, self._signature_algorithm)
        return Signature(self.public_key.keyid, sig.hex())


class _Ed25519Signer(CryptoSigner):
    """Internal pyca/cryptography ecdsa signer implementation"""

    def __init__(self, public_key: SSlibKey, private_key: "Ed25519PrivateKey"):
        if public_key.scheme != "ed25519":
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        super().__init__(public_key)
        self._private_key = private_key

    def sign(self, payload: bytes) -> Signature:
        sig = self._private_key.sign(payload)
        return Signature(self.public_key.keyid, sig.hex())
