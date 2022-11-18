"""Signature container class"""

import logging
from typing import Any, Dict, Mapping, Optional

logger = logging.getLogger(__name__)


class Signature:
    """A container class containing information about a signature.

    Contains a signature and the keyid uniquely identifying the key used
    to generate the signature.

    Provides utility methods to easily create an object from a dictionary
    and return the dictionary representation of the object.

    Attributes:
        keyid: HEX string used as a unique identifier of the key.
        signature: HEX string representing the signature.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by securesystemslib.

    """

    def __init__(
        self,
        keyid: str,
        sig: str,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        self.keyid = keyid
        self.signature = sig
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Signature):
            return False

        return (
            self.keyid == other.keyid
            and self.signature == other.signature
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @classmethod
    def from_dict(cls, signature_dict: Dict) -> "Signature":
        """Creates a Signature object from its JSON/dict representation.

        Arguments:
            signature_dict:
                A dict containing a valid keyid and a signature.
                Note that the fields in it should be named "keyid" and "sig"
                respectively.

        Raises:
            KeyError: If any of the "keyid" and "sig" fields are missing from
                the signature_dict.

        Side Effect:
            Destroys the metadata dict passed by reference.

        Returns:
            A "Signature" instance.
        """

        keyid = signature_dict.pop("keyid")
        sig = signature_dict.pop("sig")
        # All fields left in the signature_dict are unrecognized.
        return cls(keyid, sig, signature_dict)

    def to_dict(self) -> Dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "keyid": self.keyid,
            "sig": self.signature,
            **self.unrecognized_fields,
        }


class GPGSignature(Signature):
    """A container class containing information about a gpg signature.

    Besides the signature, it also contains other meta information
    needed to uniquely identify the key used to generate the signature.

    Attributes:
        keyid: HEX string used as a unique identifier of the key.
        signature: HEX string representing the signature.
        other_headers: HEX representation of additional GPG headers.
    """

    def __init__(
        self,
        keyid: str,
        signature: str,
        other_headers: str,
    ):
        super().__init__(keyid, signature)
        self.other_headers = other_headers

    @classmethod
    def from_dict(cls, signature_dict: Dict) -> "GPGSignature":
        """Creates a GPGSignature object from its JSON/dict representation.

        Args:
            signature_dict: Dict containing valid "keyid", "signature" and
                "other_fields" fields.

        Raises:
            KeyError: If any of the "keyid", "sig" or "other_headers" fields
                are missing from the signature_dict.

        Returns:
            GPGSignature instance.
        """

        return cls(
            signature_dict["keyid"],
            signature_dict["signature"],
            signature_dict["other_headers"],
        )

    def to_dict(self) -> Dict:
        """Returns the JSON-serializable dictionary representation of self."""
        return {
            "keyid": self.keyid,
            "signature": self.signature,
            "other_headers": self.other_headers,
        }
