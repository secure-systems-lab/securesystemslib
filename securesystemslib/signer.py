"""Signer interface and example interface implementations.

The goal of this module is to provide a signing interface supporting multiple
signing implementations and a couple of example implementations.

"""

import abc
import securesystemslib.keys as sslib_keys
from typing import Dict


class Signature:
    """A container class containing information about a signature.

    Contains a signature and the keyid uniquely identifying the key used
    to generate the signature.

    Provides utility methods to easily create an object from a dictionary
    and return the dictionary representation of the object.

    Attributes:
        keyid: HEX string used as a unique identifier of the key.
        signature: HEX string representing the signature.

    """
    def __init__(self, keyid: str, sig: str):
        self.keyid = keyid
        self.signature = sig


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

        Returns:
            A "Signature" instance.
        """

        return cls(signature_dict["keyid"], signature_dict["sig"])


    def to_dict(self) -> Dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "keyid": self.keyid,
            "sig": self.signature
        }



class Signer:
    """Signer interface created to support multiple signing implementations."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def sign(payload: bytes) -> "Signature":
        """Signs a given payload by the key assigned to the Signer instance.

        Arguments:
            payload: The bytes to be signed.

        Returns:
            Returns a "Signature" class instance.
        """
        raise NotImplementedError # pragma: no cover



class SSlibSigner(Signer):
    """A securesystemslib signer implementation.

    Provides a sign method to generate a cryptographic signature with a
    securesystemslib-style rsa, ed25519 or ecdsa private key on the instance.
    The signature scheme is determined by the key and must be one of:

    - rsa(ssa-pss|pkcs1v15)-(md5|sha1|sha224|sha256|sha384|sha512) (12 schemes)
    - ed25519
    - ecdsa-sha2-nistp256

    See "securesystemslib.interface" for functions to generate and load keys.

    Attributes:
        key_dict:
            A securesystemslib-style key dictionary, which includes a keyid,
            key type, signature scheme, and the public and private key values,
            e.g.::

                {
                    "keytype": "rsa",
                    "scheme": "rsassa-pss-sha256",
                    "keyid": "f30a0870d026980100c0573bd557394f8c1bbd6...",
                    "keyval": {
                        "public": "-----BEGIN RSA PUBLIC KEY----- ...",
                        "private": "-----BEGIN RSA PRIVATE KEY----- ..."
                    }
                }

            The public and private keys are strings in PEM format.
    """
    def __init__(self, key_dict: Dict):
        self.key_dict = key_dict


    def sign(self, payload: bytes) -> "Signature":
        """Signs a given payload by the key assigned to the SSlibSigner instance.

        Arguments:
            payload: The bytes to be signed.

        Raises:
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            securesystemslib.exceptions.CryptoError, \
                securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            Returns a "Signature" class instance.
        """

        sig_dict = sslib_keys.create_signature(self.key_dict, payload)
        return Signature(**sig_dict)
