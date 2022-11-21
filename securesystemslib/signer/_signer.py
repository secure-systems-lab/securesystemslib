"""Signer interface and the default implementations"""

import abc
import logging
import os
from typing import Callable, Dict, Optional, Type
from urllib import parse

import securesystemslib.gpg.functions as gpg
import securesystemslib.keys as sslib_keys
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import GPGSignature, Signature

logger = logging.getLogger(__name__)

# NOTE dict for Signer dispatch defined here, but filled at end of file when
# subclass definitions are available. Users can add Signer implementations.
SIGNER_FOR_URI_SCHEME: Dict[str, Type] = {}


# SecretsHandler is a function the calling code can provide to Signer:
# SecretsHandler will be called if Signer needs additional secrets.
# The argument is the name of the secret ("PIN", "passphrase", etc).
# Return value is the secret string.
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
        PATH is a file path to a file with unencrypted private key content.
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

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "SSlibSigner":
        """Constructor for Signer to call

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

    GPGSigners should be instantiated with Signer.from_priv_key_uri().
    Two private key URI schemes are supported:
    * gpg:<HOMEDIR>:
        HOMEDIR: Optional filesystem path to GPG home directory

    """

    def __init__(
        self, keyid: Optional[str] = None, homedir: Optional[str] = None
    ):
        self.keyid = keyid
        self.homedir = homedir

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "GPGSigner":
        raise NotImplementedError("Incompatible with private key URIs")

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


# Supported private key uri schemes and the Signers implementing them
SIGNER_FOR_URI_SCHEME = {
    SSlibSigner.ENVVAR_URI_SCHEME: SSlibSigner,
    SSlibSigner.FILE_URI_SCHEME: SSlibSigner,
}
