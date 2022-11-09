"""Signer interface and example interface implementations.

The goal of this module is to provide a signing interface supporting multiple
signing implementations and a couple of example implementations.

"""

import abc
import logging
import os
from typing import Any, Callable, Dict, Mapping, Optional, Tuple
from urllib import parse

import securesystemslib.gpg.functions as gpg
import securesystemslib.keys as sslib_keys
from securesystemslib import exceptions

logger = logging.getLogger(__name__)

# NOTE dicts for Key and Signer dispatch are defined here, but
# filled at end of file when subclass definitions are available.
# Users can add their own implementations into these dictionaries
SIGNER_FOR_URI_SCHEME: Dict[str, "Signer"] = {}
KEY_FOR_TYPE_AND_SCHEME: Dict[Tuple[str, str], "Key"] = {}


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
        keytype = key_dict["keytype"]
        scheme = key_dict["scheme"]

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
            UnverifiedSignatureError: Failed to verify signature, either
                because it was incorrect or because of a verification problem.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_payload_hash_algorithm(self) -> str:
        """Return the payload hash algorithm
        
        This is used by Signers where the actual signing system only accepts
        hashes of payloads: e.g. HSM and KMS
        
        """
        # TODO Do all signing systems support payload prehash? like ed25519?
        raise NotImplementedError

    @abc.abstractmethod
    def match_keyid(self, keyid: str) -> bool:
        """Does given keyid match this keys keyid

        This is a workaround for GPSignature design features.
        """
        # TODO is this reeally really needed?
        raise NotImplementedError


# TODO verify_signature software errors should have a error of their own?
# Maybe something deriving from UnverifiedSignature?


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
            # Log unexpected failure, but continue as if there was no signature
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise exceptions.UnverifiedSignatureError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e

    def get_payload_hash_algorithm(self) -> str:
        raise NotImplementedError

    def match_keyid(self, keyid: str) -> bool:
        raise NotImplementedError("TODO -- this seems pointless...")


# SecretsHandler is a function the calling code can provide to Signer:
# If Signer needs secrets from user, the function will be called
SecretsHandler = Callable[[str], str]


class Signer:
    """Signer interface that supports multiple signing implementations.

    Usage example:
        signer = Signer.from_priv_key_uri("envvar:MYPRIVKEY", pub_key)
        sig = signer.sign(b"data")

    See SIGNER_FOR_URI_SCHEME for supported private key URI schemes. The
    currently supported default schemes are:
    * envvar: see SSlibSigner for details
    * file: see SSlibSigner for details
    * encfile: see SSlibSigner for details
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def sign(self, payload: bytes) -> Signature:
        """Signs a given payload by the key assigned to the Signer instance.

        Arguments:
            payload: The bytes to be signed.

        Returns:
            Returns a "Signature" class instance.
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    @abc.abstractmethod
    def new_from_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler,
    ) -> "Signer":
        """Constructor for given private key URI

        This is a semi-private method meant to be called by Signer only.
        Implementation is required if the Signer subclass is in
        SIGNER_FOR_URI_SCHEME.

        Arguments:
            priv_key_uri: URI that identifies the private key and signer
            public_key: Key object
            secrets_handler: Optional function that may be called if the
                signer needs additional secrets (like a PIN or passphrase)
        """
        raise NotImplementedError  # pragma: no cover

    @staticmethod
    def from_priv_key_uri(
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ):
        """Returns a concrete Signer implementation based on private key URI

        Args:
            priv_key_uri: URI that identifies the private key location and signer
            public_key: Key object
        """

        scheme, _, _ = priv_key_uri.partition(":")
        if scheme not in SIGNER_FOR_URI_SCHEME:
            raise ValueError(f"Unsupported private key scheme {scheme}")

        signer = SIGNER_FOR_URI_SCHEME[scheme]
        return signer.new_from_uri(priv_key_uri, public_key, secrets_handler)


class SSlibSigner(Signer):
    """A securesystemslib signer implementation.

    Provides a sign method to generate a cryptographic signature with a
    securesystemslib-style rsa, ed25519 or ecdsa key. See keys module
    for the supported types, schemes and hash algorithms.

    SSlibSigners should be instantiated with Signer.from_priv_key_uri().
    Two private key URI schemes are supported:
    * envvar:<VAR>:
        VAR is an environment variable that contains the private key content.
           envvar:MYPRIVKEY
    * file:<PATH>:
        PATH is a file path to a file that contains private key content.
           file:path/to/file
    * encfile:<PATH>:
        The the private key content in PATH has been encrypted with
        keys.encryot_key(). Application provided SecretsHandler will be
        called to get the passphrase.
           file:/path/to/encrypted/file

    Attributes:
        key_dict:
            A securesystemslib-style key dictionary. This is an implementation
            detail, not part of public API
    """

    ENVVAR_URI_SCHEME = "envvar"
    FILE_URI_SCHEME = "file"
    ENC_FILE_URI_SCHEME = "encfile"

    def __init__(self, key_dict: Dict):
        self.key_dict = key_dict

    @classmethod
    def new_from_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler,
    ) -> "SSlibSigner":
        """Semi-private Constructor for Signer to call

        Arguments:
            priv_key_uri: private key URI described in class doc
            public_key: Key object.

        Raises:
            OSError: Reading the file failed with "file:" URI
            ValueError: URI is unsupported or environment variable was not set
                with "envvar:" URIs

        Returns:
            SSlibSigner for the given private key URI.
        """
        if not isinstance(public_key, SSlibKey):
            raise ValueError(
                f"Expected SSlibKey public key for private key {priv_key_uri}"
            )

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme == cls.ENVVAR_URI_SCHEME:
            # read private key from environment variable
            private = os.getenv(uri.path)
            if private is None:
                raise ValueError(
                    f"Unset private key variable for {priv_key_uri}"
                )

        elif uri.scheme == cls.FILE_URI_SCHEME:
            # read private key from file
            with open(uri.path, "rb") as f:
                private = f.read().decode()

        elif uri.scheme == cls.ENC_FILE_URI_SCHEME:
            # read key from file, ask for passphrase, decrypt
            with open(uri.path, "rb") as f:
                enc = f.read().decode()
            secret = secrets_handler("passphrase")
            decrypted = sslib_keys.decrypt_key(enc, secret)
            private = decrypted["keyval"]["private"]

        else:
            raise ValueError(
                f"SSlibSigner does not support priv key uri {priv_key_uri}"
            )

        keydict = public_key.to_securesystemslib_key()
        keydict["keyval"]["private"] = private
        return cls(keydict)

    def sign(self, payload: bytes) -> Signature:
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


class GPGSigner(Signer):
    """A securesystemslib gpg implementation of the "Signer" interface.

    Provides a sign method to generate a cryptographic signature with gpg, using
    an RSA, DSA or EdDSA private key identified by the keyid on the instance.

    Args:
        keyid: The keyid of the gpg signing keyid. If not passed the default
              key in the keyring is used.

        homedir: Path to the gpg keyring. If not passed the default keyring
            is used.

    """

    def __init__(
        self, keyid: Optional[str] = None, homedir: Optional[str] = None
    ):
        self.keyid = keyid
        self.homedir = homedir

    @classmethod
    def new_from_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler,
    ) -> Signer:
        # GPGSigner uses keys and produces signature dicts that are not
        # compliant with TUF or intoto specifications: not useful here
        raise NotImplementedError()

    def sign(self, payload: bytes) -> GPGSignature:
        """Signs a given payload by the key assigned to the GPGSigner instance.

        Calls the gpg command line utility to sign the passed content with the
        key identified by the passed keyid from the gpg keyring at the passed
        homedir.

        The executed base command is defined in
        securesystemslib.gpg.constants.gpg_sign_command.

        Arguments:
            payload: The bytes to be signed.

        Raises:
            securesystemslib.exceptions.FormatError:
                If the keyid was passed and does not match
                securesystemslib.formats.KEYID_SCHEMA.

            ValueError: the gpg command failed to create a valid signature.
            OSError: the gpg command is not present or non-executable.
            securesystemslib.exceptions.UnsupportedLibraryError: the gpg
                command is not available, or the cryptography library is
                not installed.
            securesystemslib.gpg.exceptions.CommandError: the gpg command
                returned a non-zero exit code.
            securesystemslib.gpg.exceptions.KeyNotFoundError: the used gpg
                version is not fully supported and no public key can be found
                for short keyid.

        Returns:
            Returns a "GPGSignature" class instance.
        """

        sig_dict = gpg.create_signature(payload, self.keyid, self.homedir)
        return GPGSignature(**sig_dict)


# signer and key implementations are now defined: Add them to the lookup table
SIGNER_FOR_URI_SCHEME = {
    SSlibSigner.ENVVAR_URI_SCHEME: SSlibSigner,
    SSlibSigner.FILE_URI_SCHEME: SSlibSigner,
    SSlibSigner.ENC_FILE_URI_SCHEME: SSlibSigner,
}
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
