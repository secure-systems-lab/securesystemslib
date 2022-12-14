"""Dead Simple Signing Envelope
"""

from typing import Any, List

from securesystemslib import formats
from securesystemslib.signer import Signature
from securesystemslib.util import b64dec, b64enc


class Envelope:
    """
    DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body
        payload_type: string that identifies how to interpret payload
        signatures: List of Signature

    Methods:
        from_dict(cls, data):
            Creates a Signature object from its JSON/dict representation.

        to_dict(self):
            Returns the JSON-serializable dictionary representation of self.

    """

    payload: bytes
    payload_type: str
    signatures: List[Signature]

    def __init__(self, payload, payload_type, signatures):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Envelope":
        """Creates a Signature object from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        formats.SIGNATURES_SCHEMA.check_match(data["signatures"])
        signatures = [
            Signature.from_dict(signature) for signature in data["signatures"]
        ]

        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": [
                signature.to_dict() for signature in self.signatures
            ],
        }

    @property
    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        return b"DSSEv1 %d %b %d %b" % (
            len(self.payload_type),
            self.payload_type.encode("utf-8"),
            len(self.payload),
            self.payload,
        )
