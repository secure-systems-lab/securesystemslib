"""Key interface and the default implementations"""
import logging
from abc import ABCMeta, abstractmethod
from typing import Any, Dict, Optional, Tuple, Type

import securesystemslib.keys as sslib_keys
from securesystemslib import KEY_TYPE_ECDSA, exceptions
from securesystemslib.signer._signature import Signature

# pylint: disable=wrong-import-position
CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        SECP384R1,
        EllipticCurvePublicKey,
        ObjectIdentifier,
        get_curve_for_oid,
    )

except ImportError:  # pragma: no cover
    CRYPTO_IMPORT_ERROR = "'cryptography' required"

PYKCS11_IMPORT_ERROR = None
try:
    from PyKCS11 import PyKCS11

except ImportError:  # pragma: no cover
    PYKCS11_IMPORT_ERROR = "'PyKCS11' required"

ASN1CRYPTO_IMPORT_ERROR = None
try:
    from asn1crypto.keys import ECDomainParameters, ECPoint

except ImportError:  # pragma: no cover
    ASN1CRYPTO_IMPORT_ERROR = "'asn1crypto' required"
# pylint: enable=wrong-import-position

logger = logging.getLogger(__name__)

# NOTE Key dispatch table is defined here so it's usable by Key,
# but is populated in __init__.py (and can be appended by users).
KEY_FOR_TYPE_AND_SCHEME: Dict[Tuple[str, str], Type] = {}


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

        Users should call Key.from_dict(): it dispatches to the actual subclass
        implementation based on supported keys in KEY_FOR_TYPE_AND_SCHEME.

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
    """Key implementation for RSA, Ed25519, ECDSA and Sphincs keys"""

    def to_securesystemslib_key(self) -> Dict[str, Any]:
        """Internal helper, returns a classic securesystemslib keydict"""
        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
        }

    @classmethod
    def from_securesystemslib_key(cls, key_dict: Dict[str, Any]) -> "SSlibKey":
        """Constructor from classic securesystemslib keydict"""
        # ensure possible private keys are not included in keyval
        return SSlibKey(
            key_dict["keyid"],
            key_dict["keytype"],
            key_dict["scheme"],
            {"public": key_dict["keyval"]["public"]},
        )

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "SSlibKey":
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")

        if "public" not in keyval or not isinstance(keyval["public"], str):
            raise ValueError(f"public key string required for scheme {scheme}")

        # All fields left in the key_dict are unrecognized.
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

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


class HSMKey(SSlibKey):
    """Hardware Security Module (HSM) Key

    HSMKey is a regular SSlibKey with an additional `from_hsm` method to
    export public keys from hardware security modules.
    """

    @classmethod
    def from_hsm(
        cls,
        hsm_session: "PyKCS11.Session",
        hsm_keyid: Tuple[int, ...],
        keyid: str,
    ):
        """Export public key from HSM

        Supports ecdsa on SECG curves secp256r1 (NIST P-256) or secp384r1 (NIST P-384).

        Arguments:
            hsm_session: An open ``PyKCS11.Session`` to the token with the public key.
            hsm_keyid: Key identifier on the token.
            keyid: Key identifier that is unique within the metadata it is used in.

        Raises:
            ValueError: No compatible key for ``hsm_keyid`` found on HSM.
            PyKCS11.PyKCS11Error: Various HSM communication errors.

        """
        if CRYPTO_IMPORT_ERROR:
            raise exceptions.UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if PYKCS11_IMPORT_ERROR:
            raise exceptions.UnsupportedLibraryError(PYKCS11_IMPORT_ERROR)

        # Search for ecdsa public keys with passed keyid on HSM
        keys = hsm_session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_ID, hsm_keyid),
            ]
        )

        if len(keys) != 1:
            raise ValueError(
                f"hsm_keyid must identify one {KEY_TYPE_ECDSA} key, found {len(keys)}"
            )

        # Extract public key domain parameters and point from HSM
        hsm_params, hsm_point = hsm_session.getAttributeValue(
            keys[0], [PyKCS11.CKA_EC_PARAMS, PyKCS11.CKA_EC_POINT]
        )

        params = ECDomainParameters.load(bytes(hsm_params))

        # TODO: Define as module level constant and don't hardcode scheme strings
        scheme_for_curve = {
            SECP256R1: "ecdsa-sha2-nistp256",
            SECP384R1: "ecdsa-sha2-nistp384",
        }
        curve_names = [curve.name for curve in scheme_for_curve]

        if params.chosen.native not in curve_names:
            raise ValueError(
                f"found key on {params.chosen.native}, should be on one of {curve_names}"
            )

        # Create PEM from key
        curve = get_curve_for_oid(ObjectIdentifier(params.chosen.dotted))
        public_pem = (
            EllipticCurvePublicKey.from_encoded_point(
                curve(), ECPoint().load(bytes(hsm_point)).native
            )
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

        return HSMKey(
            keyid,
            KEY_TYPE_ECDSA,
            scheme_for_curve[curve],
            {"public": public_pem},
        )
