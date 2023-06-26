"""Signer interface and the default implementations"""

import logging
import os
from abc import ABCMeta, abstractmethod
from typing import Any, Callable, Dict, Optional, Type, cast
from urllib import parse

import securesystemslib.keys as sslib_keys
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature

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

# NOTE Signer dispatch table is defined here so it's usable by Signer,
# but is populated in __init__.py (and can be appended by users).
SIGNER_FOR_URI_SCHEME: Dict[str, Type] = {}


# SecretsHandler is a function the calling code can provide to Signer:
# SecretsHandler will be called if Signer needs additional secrets.
# The argument is the name of the secret ("PIN", "passphrase", etc).
# Return value is the secret string.
SecretsHandler = Callable[[str], str]


class Signer(metaclass=ABCMeta):
    """Signer interface that supports multiple signing implementations.

    Usage example:

        signer = Signer.from_priv_key_uri("envvar:MYPRIVKEY", pub_key)
        sig = signer.sign(b"data")

    Note that signer implementations may raise errors (during both
    Signer.from_priv_key_uri() and Signer.sign()) that are not documented here:
    examples could include network errors or file read errors. Applications
    should use generic try-except here if unexpected raises are not an option.

    See SIGNER_FOR_URI_SCHEME for supported private key URI schemes. The
    currently supported default schemes are:
    * envvar: see SSlibSigner for details
    * file: see SSlibSigner for details

    Interactive applications may also define a secrets handler that allows
    asking for user secrets if they are needed:

        from getpass import getpass

        def sec_handler(secret_name:str) -> str:
            return getpass(f"Enter {secret_name}: ")

        # user will not be asked for a passphrase for unencrypted key
        uri = "file:keys/mykey?encrypted=false"
        signer = Signer.from_priv_key_uri(uri, pub_key, sec_handler)

        # user will be asked for a passphrase for encrypted key
        uri2 = "file:keys/myenckey?encrypted=true"
        signer2 = Signer.from_priv_key_uri(uri2, pub_key2, sec_handler)

    Applications can provide their own Signer and Key implementations:

        from securesystemslib.signer import Signer, SIGNER_FOR_URI_SCHEME
        from mylib import MySigner

        SIGNER_FOR_URI_SCHEME[MySigner.MY_SCHEME] = MySigner

    This way the application code using signer API continues to work with
    default signers but now also uses the custom signer when the proper URI is
    used.
    """

    @abstractmethod
    def sign(self, payload: bytes) -> Signature:
        """Signs a given payload by the key assigned to the Signer instance.

        Arguments:
            payload: The bytes to be signed.

        Returns:
            Returns a "Signature" class instance.
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    @abstractmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "Signer":
        """Factory constructor for a given private key URI

        Returns a specific Signer instance based on the private key URI and the
        supported uri schemes listed in SIGNER_FOR_URI_SCHEME.

        Args:
            priv_key_uri: URI that identifies the private key
            public_key: Key that is the public portion of this private key
            secrets_handler: Optional function that may be called if the
                signer needs additional secrets (like a PIN or passphrase).
                secrets_handler should return the requested secret string.

        Raises:
            ValueError: Incorrect arguments
            Other Signer-specific errors: These could include OSErrors for
                reading files or network errors for connecting to a KMS.
        """

        scheme, _, _ = priv_key_uri.partition(":")
        if scheme not in SIGNER_FOR_URI_SCHEME:
            raise ValueError(f"Unsupported private key scheme {scheme}")

        signer = SIGNER_FOR_URI_SCHEME[scheme]
        return signer.from_priv_key_uri(
            priv_key_uri, public_key, secrets_handler
        )


class SSlibSigner(Signer):
    """A securesystemslib signer implementation.

    Provides a sign method to generate a cryptographic signature with a
    securesystemslib-style rsa, ed25519 or ecdsa key. See keys module
    for the supported types, schemes and hash algorithms.

    SSlibSigners should be instantiated with Signer.from_priv_key_uri().
    These private key URI schemes are supported:
    * "envvar:<VAR>":
        VAR is an environment variable with unencrypted private key content.
           envvar:MYPRIVKEY
    * "file:<PATH>?encrypted=[true|false]":
        PATH is a file path to a file with private key content. If
        encrypted=true, the file is expected to have been created with
        securesystemslib.keys.encrypt_key().
           file:path/to/file?encrypted=true
           file:/abs/path/to/file?encrypted=false

    Attributes:
        key_dict:
            A securesystemslib-style key dictionary. This is an implementation
            detail, not part of public API
    """

    ENVVAR_URI_SCHEME = "envvar"
    FILE_URI_SCHEME = "file"

    def __init__(self, key_dict: Dict):
        self.key_dict = key_dict
        self._crypto_signer = CryptoSigner.from_securesystemslib_key(key_dict)

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "SSlibSigner":
        """Constructor for Signer to call

        Please refer to Signer.from_priv_key_uri() documentation.

        Additionally raises:
            OSError: Reading the file failed with "file:" URI
        """
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme == cls.ENVVAR_URI_SCHEME:
            # read private key from environment variable
            private = os.getenv(uri.path)
            if private is None:
                raise ValueError(f"Unset env var for {priv_key_uri}")

        elif uri.scheme == cls.FILE_URI_SCHEME:
            params = dict(parse.parse_qsl(uri.query))
            if "encrypted" not in params:
                raise ValueError(f"{uri.scheme} requires 'encrypted' parameter")

            # read private key (may be encrypted or not) from file
            with open(uri.path, "rb") as f:
                private = f.read().decode()

            if params["encrypted"] != "false":
                if not secrets_handler:
                    raise ValueError("encrypted key requires a secrets handler")

                secret = secrets_handler("passphrase")
                decrypted = sslib_keys.decrypt_key(private, secret)
                private = decrypted["keyval"]["private"]

        else:
            raise ValueError(f"SSlibSigner does not support {priv_key_uri}")

        keydict = public_key.to_securesystemslib_key()
        keydict["keyval"]["private"] = private

        return cls(keydict)

    def sign(self, payload: bytes) -> Signature:
        """Signs a given payload by the key assigned to the SSlibSigner instance.

        Please see Signer.sign() documentation.

        Additionally raises:
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            securesystemslib.exceptions.CryptoError, \
                securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.
        """
        return self._crypto_signer.sign(payload)


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
            return RSASigner(public_key, private_key)

        if public_key.keytype == "ecdsa":
            private_key = cast(
                EllipticCurvePrivateKey,
                load_pem_private_key(private.encode(), password=None),
            )
            return ECDSASigner(public_key, private_key)

        if public_key.keytype == "ed25519":
            private_key = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(private)
            )
            return Ed25519Signer(public_key, private_key)

        raise ValueError(f"unsupported keytype: {public_key.keytype}")

    @classmethod
    def _from_pem(
        cls, private_pem: bytes, secret: Optional[bytes], public_key: SSlibKey
    ):
        """Helper factory to create CryptoSigner from private PEM."""
        private_key = load_pem_private_key(private_pem, secret)

        if public_key.keytype == "rsa":
            return RSASigner(public_key, cast(RSAPrivateKey, private_key))

        if public_key.keytype == "ecdsa":
            return ECDSASigner(
                public_key, cast(EllipticCurvePrivateKey, private_key)
            )

        if public_key.keytype == "ed25519":
            return Ed25519Signer(
                public_key, cast(Ed25519PrivateKey, private_key)
            )

        raise ValueError(f"unsupported keytype: {public_key.keytype}")

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "SSlibSigner":
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
            raise ValueError(f"SSlibSigner does not support {priv_key_uri}")

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


class RSASigner(CryptoSigner):
    """pyca/cryptography rsa signer implementation"""

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

    @classmethod
    def generate(
        cls,
        keyid: Optional[str] = None,
        scheme: Optional[str] = "rsassa-pss-sha256",
        size: int = 3072,
    ) -> "RSASigner":
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
        return cls(public_key, private_key)

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


class ECDSASigner(CryptoSigner):
    """pyca/cryptography ecdsa signer implementation"""

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

    @classmethod
    def generate(
        cls,
        keyid: Optional[str] = None,
    ) -> "ECDSASigner":
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
        return cls(public_key, private_key)


class Ed25519Signer(CryptoSigner):
    """pyca/cryptography ecdsa signer implementation"""

    def __init__(self, public_key: SSlibKey, private_key: "Ed25519PrivateKey"):
        if public_key.scheme != "ed25519":
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        super().__init__(public_key)
        self._private_key = private_key

    def sign(self, payload: bytes) -> Signature:
        sig = self._private_key.sign(payload)
        return Signature(self.public_key.keyid, sig.hex())

    @classmethod
    def generate(
        cls,
        keyid: Optional[str] = None,
    ) -> "Ed25519Signer":
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
        return cls(public_key, private_key)
