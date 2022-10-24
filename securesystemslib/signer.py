"""Signer interface and example interface implementations.

The goal of this module is to provide a signing interface supporting multiple
signing implementations and a couple of example implementations.

"""

import abc
import copy
import os
from typing import Any, Callable, Dict, Mapping, Optional
from urllib import parse

import securesystemslib.gpg.functions as gpg
import securesystemslib.keys as sslib_keys
from securesystemslib import formats

# NOTE This dictionary is initialized here so it's available to Signer, but
# filled at end of file when Signer subclass definitions are available.
# Users can add their own Signer implementations into this dictionary
SIGNER_FOR_URI_SCHEME: Dict[str, "Signer"] = {}


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
        public_key: Dict[str, Any],
        secrets_handler: SecretsHandler,
    ) -> "Signer":
        """Constructor for given private key URI

        This is a semi-private method meant to be called by Signer only.
        Implementation is required if the Signer subclass is in
        SIGNER_FOR_URI_SCHEME.

        Arguments:
            priv_key_uri: URI that identifies the private key and signer
            public_key: Public key metadata conforming to PUBLIC_KEY_SCHEMA
            secrets_handler: Optional function that may be called if the
                signer needs additional secrets (like a PIN or passphrase)
        """
        raise NotImplementedError  # pragma: no cover

    @staticmethod
    def from_priv_key_uri(
        priv_key_uri: str,
        public_key: Dict[str, Any],
        secrets_handler: Optional[SecretsHandler] = None,
    ):
        """Returns a concrete Signer implementation based on private key URI

        Args:
            priv_key_uri: URI that identifies the private key location and signer
            public_key: Public key metadata conforming to PUBLIC_KEY_SCHEMA
        """

        formats.PUBLIC_KEY_SCHEMA.check_match(public_key)
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
            A securesystemslib-style key dictionary, which includes a keyid,
            key type, scheme, and keyval with both private and public parts.
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
        public_key: Dict[str, Any],
        secrets_handler: SecretsHandler,
    ) -> "SSlibSigner":
        """Semi-private Constructor for Signer to call

        Arguments:
            priv_key_uri: private key URI described in class doc
            public_key: securesystemslib-style key dict, which includes keyid,
                type, scheme, and keyval the public key.

        Raises:
            OSError: Reading the file failed with "file:" URI
            ValueError: URI is unsupported or environment variable was not set
                with "envvar:" URIs

        Returns:
            SSlibSigner for the given private key URI.
        """
        keydict = copy.deepcopy(public_key)
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
        public_key: Dict[str, Any],
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


# signer implementations are now defined: Add them to the lookup table
SIGNER_FOR_URI_SCHEME = {
    SSlibSigner.ENVVAR_URI_SCHEME: SSlibSigner,
    SSlibSigner.FILE_URI_SCHEME: SSlibSigner,
    SSlibSigner.ENC_FILE_URI_SCHEME: SSlibSigner,
}
