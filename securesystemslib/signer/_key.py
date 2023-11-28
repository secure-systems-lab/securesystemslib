"""Key interface and the default implementations"""
import logging
from abc import ABCMeta, abstractmethod
from typing import Any, Dict, Optional, Tuple, Type, cast

from securesystemslib._vendor.ed25519.ed25519 import (
    SignatureMismatch,
    checkvalid,
)
from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._utils import compute_default_keyid

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import (
        MGF1,
        PSS,
        PKCS1v15,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        AsymmetricPadding,
        RSAPublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
    from cryptography.hazmat.primitives.hashes import (
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        HashAlgorithm,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )
except ImportError:
    CRYPTO_IMPORT_ERROR = "'pyca/cryptography' library required"


logger = logging.getLogger(__name__)

# NOTE Key dispatch table is defined here so it's usable by Key,
# but is populated in __init__.py (and can be appended by users).
KEY_FOR_TYPE_AND_SCHEME: Dict[Tuple[str, str], Type] = {}
"""Key dispatch table for ``Key.from_dict()``

See ``securesystemslib.signer.KEY_FOR_TYPE_AND_SCHEME`` for default key types
and schemes, and how to register custom implementations.
"""


class Key(metaclass=ABCMeta):
    """Abstract class representing the public portion of a key.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        keyid: Key identifier that is unique within the metadata it is used in.
            Keyid is not verified to be the hash of a specific representation
            of the key.
        keytype: Key type, e.g. "rsa", "ed25519" or "ecdsa-sha2-nistp256".
        scheme: Signature scheme. For example:
            "rsassa-pss-sha256", "ed25519", and "ecdsa-sha2-nistp256".
        keyval: Opaque key content
        unrecognized_fields: Dictionary of all attributes that are not managed
            by Securesystemslib

    Raises:
        TypeError: Invalid type for an argument.
    """

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: Dict[str, Any],
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        if not all(
            isinstance(at, str) for at in [keyid, keytype, scheme]
        ) or not isinstance(keyval, dict):
            raise TypeError("Unexpected Key attributes types!")
        self.keyid = keyid
        self.keytype = keytype
        self.scheme = scheme
        self.keyval = keyval

        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Key):
            return False

        return (
            self.keyid == other.keyid
            and self.keytype == other.keytype
            and self.scheme == other.scheme
            and self.keyval == other.keyval
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @classmethod
    @abstractmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "Key":
        """Creates ``Key`` object from a serialization dict

        Key implementations must override this factory constructor that is used
        as a deserialization helper.

        Users should call ``Key.from_dict()``: it dispatches to the actual
        subclass implementation based on supported keys in
        ``KEY_FOR_TYPE_AND_SCHEME``.

        Raises:
            KeyError, TypeError: Invalid arguments.
        """
        keytype = key_dict.get("keytype")
        scheme = key_dict.get("scheme")
        if (keytype, scheme) not in KEY_FOR_TYPE_AND_SCHEME:
            raise ValueError(f"Unsupported public key {keytype}/{scheme}")

        # NOTE: Explicitly not checking the keytype and scheme types to allow
        # intoto to use (None,None) to lookup GPGKey, see issue #450
        key_impl = KEY_FOR_TYPE_AND_SCHEME[(keytype, scheme)]  # type: ignore
        return key_impl.from_dict(keyid, key_dict)

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Returns a serialization dict.

        Key implementations must override this serialization helper.
        """
        raise NotImplementedError

    def _to_dict(self) -> Dict[str, Any]:
        """Serialization helper to add base Key fields to a dict.

        Key implementations may call this in their to_dict, which they must
        still provide, in order to avoid unnoticed serialization accidents.
        """
        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

    @staticmethod
    def _from_dict(key_dict: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """Deserialization helper to pop base Key fields off the dict.

        Key implementations may call this in their from_dict, in order to parse
        out common fields. But they have to create the Key instance themselves.
        """
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")

        return keytype, scheme, keyval

    @abstractmethod
    def verify_signature(self, signature: Signature, data: bytes) -> None:
        """Raises if verification of signature over data fails.

        Args:
            signature: Signature object.
            data: Payload bytes.

        Raises:
            UnverifiedSignatureError: Failed to verify signature.
            VerificationError: Signature verification process error. If you
                are only interested in the verify result, just handle
                UnverifiedSignatureError: it contains VerificationError as well
        """
        raise NotImplementedError


class SSlibKey(Key):
    """Key implementation for RSA, Ed25519, ECDSA keys"""

    def to_securesystemslib_key(self) -> Dict[str, Any]:
        """Internal helper, returns a classic securesystemslib keydict.

        .. deprecated:: 0.28.0
            Please use ``CryptoSigner`` instead of securesystemslib keydicts.
        """
        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
        }

    @classmethod
    def from_securesystemslib_key(cls, key_dict: Dict[str, Any]) -> "SSlibKey":
        """Constructor from classic securesystemslib keydict

        .. deprecated:: 0.28.0
            Please use ``CryptoSigner`` instead of securesystemslib keydicts.
        """
        # ensure possible private keys are not included in keyval
        return SSlibKey(
            key_dict["keyid"],
            key_dict["keytype"],
            key_dict["scheme"],
            {"public": key_dict["keyval"]["public"]},
        )

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "SSlibKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)

        if "public" not in keyval or not isinstance(keyval["public"], str):
            raise ValueError(f"public key string required for scheme {scheme}")

        # All fields left in the key_dict are unrecognized.
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        return self._to_dict()

    def _from_pem(self) -> "PublicKeyTypes":
        """Helper to load public key instance from PEM-formatted keyval.

        # FIXME: Sounds like it's an SSlibKey factory, but isn't. Should think
        of a better name or refactor _verify!
        """
        public_bytes = self.keyval["public"].encode("utf-8")
        return load_pem_public_key(public_bytes)

    @staticmethod
    def _get_keytype_for_crypto_key(public_key: "PublicKeyTypes") -> str:
        """Helper to return keytype for pyca/cryptography public key."""
        if isinstance(public_key, RSAPublicKey):
            return "rsa"

        if isinstance(public_key, EllipticCurvePublicKey):
            return "ecdsa"

        if isinstance(public_key, Ed25519PublicKey):
            return "ed25519"

        raise ValueError(f"unsupported 'public_key' type {type(public_key)}")

    @staticmethod
    def _get_default_scheme(keytype: str) -> str:
        """Helper to return default scheme for keytype."""
        if keytype == "rsa":
            return "rsassa-pss-sha256"

        if keytype == "ecdsa":
            return "ecdsa-sha2-nistp256"

        if keytype == "ed25519":
            return "ed25519"

        raise ValueError(f"unsupported 'keytype' {keytype}")

    @classmethod
    def from_crypto(
        cls,
        public_key: "PublicKeyTypes",
        keyid: Optional[str] = None,
        scheme: Optional[str] = None,
    ) -> "SSlibKey":
        """Create SSlibKey from pyca/cryptography public key.

        Args:
            public_key: pyca/cryptography public key object.
            keyid: Key identifier. If not passed, a default keyid is computed.
            scheme: SSlibKey signing scheme. Defaults are "rsassa-pss-sha256",
                "ecdsa-sha2-nistp256", and "ed25519" according to the keytype

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed
            ValueError: Key type not supported

        Returns:
            SSlibKey

        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        keytype = cls._get_keytype_for_crypto_key(public_key)
        if not scheme:
            scheme = cls._get_default_scheme(keytype)

        if keytype in ["rsa", "ecdsa"]:
            pem: bytes = public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )
            public_key_value = pem.decode()

        else:  # ed25519
            raw: bytes = public_key.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            public_key_value = raw.hex()

        keyval = {"public": public_key_value}

        if not keyid:
            keyid = compute_default_keyid(keytype, scheme, keyval)

        return SSlibKey(keyid, keytype, scheme, keyval)

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
            padding = PSS(mgf=MGF1(hash_algorithm), salt_length=PSS.AUTO)

        if name == "pkcs1v15":
            padding = PKCS1v15()

        return padding

    def _verify_ed25519_fallback(self, signature: bytes, data: bytes) -> None:
        """Helper to verify ed25519 sig if pyca/cryptography is unavailable."""
        try:
            public_bytes = bytes.fromhex(self.keyval["public"])
            checkvalid(signature, data, public_bytes)

        except SignatureMismatch as e:
            raise UnverifiedSignatureError from e

    def _verify(self, signature: bytes, data: bytes) -> None:
        """Helper to verify signature using pyca/cryptography (default)."""
        try:
            key: PublicKeyTypes
            if self.scheme in [
                "rsassa-pss-sha224",
                "rsassa-pss-sha256",
                "rsassa-pss-sha384",
                "rsassa-pss-sha512",
                "rsa-pkcs1v15-sha224",
                "rsa-pkcs1v15-sha256",
                "rsa-pkcs1v15-sha384",
                "rsa-pkcs1v15-sha512",
            ]:
                key = cast(RSAPublicKey, self._from_pem())
                padding_name, hash_name = self.scheme.split("-")[1:]
                hash_algorithm = self._get_hash_algorithm(hash_name)
                padding = self._get_rsa_padding(padding_name, hash_algorithm)
                key.verify(signature, data, padding, hash_algorithm)

            elif self.scheme in [
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
            ]:
                key = cast(EllipticCurvePublicKey, self._from_pem())
                hash_name = f"sha{self.scheme[-3:]}"
                hash_algorithm = self._get_hash_algorithm(hash_name)
                signature_algorithm = ECDSA(hash_algorithm)
                key.verify(signature, data, signature_algorithm)

            elif self.scheme in ["ed25519"]:
                public_bytes = bytes.fromhex(self.keyval["public"])
                key = Ed25519PublicKey.from_public_bytes(public_bytes)
                key.verify(signature, data)

            else:
                raise ValueError(f"unknown scheme '{self.scheme}'")

        except InvalidSignature as e:
            raise UnverifiedSignatureError from e

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            if signature.keyid != self.keyid:
                raise ValueError(
                    f"keyid mismatch: 'key id: {self.keyid}"
                    f" != signature keyid: {signature.keyid}'"
                )

            signature_bytes = bytes.fromhex(signature.signature)

            if CRYPTO_IMPORT_ERROR:
                if self.scheme != "ed25519":
                    raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

                return self._verify_ed25519_fallback(signature_bytes, data)

            return self._verify(signature_bytes, data)

        except UnverifiedSignatureError as e:
            raise UnverifiedSignatureError(
                f"Failed to verify signature by {self.keyid}"
            ) from e

        except Exception as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, e)
            raise VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e
