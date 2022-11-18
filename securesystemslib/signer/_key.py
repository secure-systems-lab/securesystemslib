"""Key interface and the default implementations"""
import abc
import logging
from typing import Any, Dict, Optional, Tuple

import securesystemslib.keys as sslib_keys
from securesystemslib import exceptions
from securesystemslib.signer._signature import Signature

logger = logging.getLogger(__name__)

# NOTE dict for Key dispatch defined here, but filled at end of file when
# subclass definitions are available. Users can add Key implementations.
KEY_FOR_TYPE_AND_SCHEME: Dict[Tuple[str, str], "Key"] = {}


class Key:
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

    __metaclass__ = abc.ABCMeta

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
    @abc.abstractmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "Key":
        """Creates ``Key`` object from TUF serialization dict.

        Key implementations must override this factory constructor.

        Raises:
            KeyError, TypeError: Invalid arguments.
        """
        keytype = key_dict.get("keytype")
        scheme = key_dict.get("scheme")
        if (keytype, scheme) not in KEY_FOR_TYPE_AND_SCHEME:
            raise ValueError(f"Unsupported public key {keytype}/{scheme}")

        key_impl = KEY_FOR_TYPE_AND_SCHEME[(keytype, scheme)]
        return key_impl.from_dict(keyid, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns a dict for TUF serialization.

        Key implementations may override this method.
        """
        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

    @abc.abstractmethod
    def verify_signature(self, signature: Signature, data: bytes) -> None:
        """Verifies the signature over data.

        Args:
            signature: Signature object.
            data: Payload bytes.

        Raises:
            UnverifiedSignatureError: Failed to verify signature.
            VerificationError: Signature verification process failed. If you
                are only interested in the verify result, just handle
                UnverifiedSignatureError: it contains VerificationError as well
        """
        raise NotImplementedError


class SSlibKey(Key):
    """Key implementation for RSA, Ed25519, ECDSA and Sphincs keys"""

    def to_securesystemslib_key(self) -> Dict[str, Any]:
        """Internal helper function"""
        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
        }

    @classmethod
    def from_securesystemslib_key(cls, key_dict: Dict[str, Any]) -> "SSlibKey":
        """Constructor from classic securesystemslib keydict"""
        return SSlibKey(
            key_dict["keyid"],
            key_dict["keytype"],
            key_dict["scheme"],
            key_dict["keyval"],
        )

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "SSlibKey":
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")
        # All fields left in the key_dict are unrecognized.
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            if not sslib_keys.verify_signature(
                self.to_securesystemslib_key(),
                signature.to_dict(),
                data,
            ):
                raise exceptions.UnverifiedSignatureError(
                    f"Failed to verify signature by {self.keyid}"
                )
        except (
            exceptions.CryptoError,
            exceptions.FormatError,
            exceptions.UnsupportedAlgorithmError,
        ) as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise exceptions.VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e


# Supported key types and schemes, and the Keys implementing them
KEY_FOR_TYPE_AND_SCHEME = {
    ("ecdsa", "ecdsa-sha2-nistp256"): SSlibKey,
    ("ecdsa", "ecdsa-sha2-nistp384"): SSlibKey,
    ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"): SSlibKey,
    ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"): SSlibKey,
    ("ed25519", "ed25519"): SSlibKey,
    ("rsa", "rsassa-pss-md5"): SSlibKey,
    ("rsa", "rsassa-pss-sha1"): SSlibKey,
    ("rsa", "rsassa-pss-sha224"): SSlibKey,
    ("rsa", "rsassa-pss-sha256"): SSlibKey,
    ("rsa", "rsassa-pss-sha384"): SSlibKey,
    ("rsa", "rsassa-pss-sha512"): SSlibKey,
    ("rsa", "rsa-pkcs1v15-md5"): SSlibKey,
    ("rsa", "rsa-pkcs1v15-sha1"): SSlibKey,
    ("rsa", "rsa-pkcs1v15-sha224"): SSlibKey,
    ("rsa", "rsa-pkcs1v15-sha256"): SSlibKey,
    ("rsa", "rsa-pkcs1v15-sha384"): SSlibKey,
    ("rsa", "rsa-pkcs1v15-sha512"): SSlibKey,
    ("sphincs", "sphincs-shake-128s"): SSlibKey,
}
