"""Dead Simple Signing Envelope
"""

import base64
from typing import Any, List

from securesystemslib import exceptions
from securesystemslib import formats
from securesystemslib.signer import Signature


class Envelope:
    """DSSE Envelope.

    Attributes:
        payload: Arbitrary byte sequence of Serialized Body
        payloadType: string that identifies how to interpret payload
        signatures: List of Signature and GPG Signature

    """

    payload: bytes
    payloadType: str
    signatures: List[Signature]

    def __init__(self, payload, payloadType, signatures):
        self.payload = payload
        self.payloadType = payloadType
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payloadType == other.payloadType
            and self.signatures == other.signatures
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Envelope":
        """Creates a Signature object from its JSON/dict representation.
        
        Arguments:
            data:
                A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

        Returns:
            A "Envelope" instance.
        """
        payload = base64.b64decode(data['payload'].encode())
        payloadType = data['payloadType']

        signatures = []
        for signature in data['signatures']:
            if formats.SIGNATURE_SCHEMA.matches(signature):
                signatures.append(Signature.from_dict(signature))

            elif formats.GPG_SIGNATURE_SCHEMA.matches(signature):
                raise NotImplementedError

            else:
                raise exceptions.FormatError('Invalid signature')

        return cls(payload, payloadType, signatures)

    def to_dict(self):
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "payload": base64.b64encode(self.payload).decode(),
            "payloadType": self.payloadType,
            "signatures": [
                signature.to_dict() for signature in self.signatures
            ],
        }
