"""Signer implementation for pyca/cryptography signing. """

import logging
from dataclasses import astuple, dataclass
from typing import Any, Dict, Optional, Union
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


@dataclass
class _RSASignArgs:
    padding: "AsymmetricPadding"
    hash_algo: "HashAlgorithm"


@dataclass
class _ECDSASignArgs:
    sig_algo: "ECDSA"


@dataclass
class _NoSignArgs:
    pass


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


def _get_rsa_padding(
    name: str, hash_algorithm: "HashAlgorithm"
) -> "AsymmetricPadding":
    """Helper to return rsa signature padding for name."""
    padding: AsymmetricPadding
    if name == "pss":
        padding = PSS(mgf=MGF1(hash_algorithm), salt_length=PSS.DIGEST_LENGTH)

    if name == "pkcs1v15":
        padding = PKCS1v15()

    return padding


class CryptoSigner(Signer):
    """PYCA/cryptography Signer implementations.

    A CryptoSigner can be created from:

        a. private key file -- ``Signer.from_priv_key_uri()``

          URI has the format "file:<PATH>?encrypted=[true|false]", where
          PATH is the path to a file with private key data in a standard
          PEM/PKCS8 format.

          A related public key must be passed.

          If  ``encrypted=true``, the optional secrets handler is expected to
          return a decryption password.

        b. newly generated key pair -- ``CryptoSigner.generate_*()``

        c. existing pyca/cryptography private key object -- ``CryptoSigner()``

    """

    FILE_URI_SCHEME = "file"

    def __init__(
        self,
        private_key: "PrivateKeyTypes",
        public_key: Optional[SSlibKey] = None,
    ):
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if public_key is None:
            public_key = SSlibKey.from_crypto(private_key.public_key())

        self._private_key: PrivateKeyTypes
        self._sign_args: Union[_RSASignArgs, _ECDSASignArgs, _NoSignArgs]

        if public_key.keytype == "rsa" and public_key.scheme in [
            "rsassa-pss-sha224",
            "rsassa-pss-sha256",
            "rsassa-pss-sha384",
            "rsassa-pss-sha512",
            "rsa-pkcs1v15-sha224",
            "rsa-pkcs1v15-sha256",
            "rsa-pkcs1v15-sha384",
            "rsa-pkcs1v15-sha512",
        ]:
            if not isinstance(private_key, RSAPrivateKey):
                raise ValueError(f"invalid rsa key: {type(private_key)}")

            padding_name, hash_name = public_key.scheme.split("-")[1:]
            hash_algo = _get_hash_algorithm(hash_name)
            padding = _get_rsa_padding(padding_name, hash_algo)
            self._sign_args = _RSASignArgs(padding, hash_algo)
            self._private_key = private_key

        elif (
            public_key.keytype == "ecdsa"
            and public_key.scheme == "ecdsa-sha2-nistp256"
        ):
            if not isinstance(private_key, EllipticCurvePrivateKey):
                raise ValueError(f"invalid ecdsa key: {type(private_key)}")

            signature_algorithm = ECDSA(SHA256())
            self._sign_args = _ECDSASignArgs(signature_algorithm)
            self._private_key = private_key

        elif public_key.keytype == "ed25519" and public_key.scheme == "ed25519":
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError(f"invalid ed25519 key: {type(private_key)}")

            self._sign_args = _NoSignArgs()
            self._private_key = private_key

        else:
            raise ValueError(
                f"unsupported public key {public_key.keytype}/{public_key.scheme}"
            )

        self.public_key = public_key

    @classmethod
    def from_securesystemslib_key(
        cls, key_dict: Dict[str, Any]
    ) -> "CryptoSigner":
        """Factory to create CryptoSigner from securesystemslib private key dict."""
        private = key_dict["keyval"]["private"]
        public_key = SSlibKey.from_securesystemslib_key(key_dict)

        private_key: PrivateKeyTypes
        if public_key.keytype in ["rsa", "ecdsa"]:
            private_key = load_pem_private_key(private.encode(), password=None)

        elif public_key.keytype == "ed25519":
            private_key = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(private)
            )

        else:
            raise ValueError(f"unsupported keytype: {public_key.keytype}")

        return CryptoSigner(private_key, public_key)

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

        private_key = load_pem_private_key(private_pem, secret)
        return CryptoSigner(private_key, public_key)

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
        public_key = SSlibKey.from_crypto(
            private_key.public_key(), keyid, "ed25519"
        )
        return CryptoSigner(private_key, public_key)

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
        public_key = SSlibKey.from_crypto(
            private_key.public_key(), keyid, scheme
        )
        return CryptoSigner(private_key, public_key)

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
        public_key = SSlibKey.from_crypto(
            private_key.public_key(), keyid, "ecdsa-sha2-nistp256"
        )
        return CryptoSigner(private_key, public_key)

    def sign(self, payload: bytes) -> Signature:
        sig = self._private_key.sign(payload, *astuple(self._sign_args))  # type: ignore
        return Signature(self.public_key.keyid, sig.hex())
