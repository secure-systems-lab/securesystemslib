"""Signer interface and the default implementations"""

import binascii
import logging
import os
from abc import ABCMeta, abstractmethod
from typing import Callable, Dict, Optional, Tuple, Type
from urllib import parse

# pylint: disable=wrong-import-position
CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )
except ImportError:  # pragma: no cover
    CRYPTO_IMPORT_ERROR = "'cryptography' required"

PYKCS11_IMPORT_ERROR = None
try:
    from PyKCS11 import PyKCS11

except ImportError:  # pragma: no cover
    PYKCS11_IMPORT_ERROR = "'PyKCS11' required"
# pylint: enable=wrong-import-position

import securesystemslib.gpg.functions as gpg
import securesystemslib.keys as sslib_keys
from securesystemslib import KEY_TYPE_ECDSA
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import GPGSignature, Signature

logger = logging.getLogger(__name__)

# NOTE Signer dispatch table is defined here so it's usable by Signer,
# but is populated in __init__.py (and can be appended by users).
SIGNER_FOR_URI_SCHEME: Dict[str, Type] = {}


# SecretsHandler is a function the calling code can provide to Signer:
# SecretsHandler will be called if Signer needs additional secrets.
# The argument is the name of the secret ("PIN", "passphrase", etc).
# Return value is the secret string.
SecretsHandler = Callable[[str], str]


class Signer(metaclass=ABCMeta):
    """Signer interface that supports multiple signing implementations.

    Usage example:

        signer = Signer.from_priv_key_uri("envvar:MYPRIVKEY", pub_key)
        sig = signer.sign(b"data")

    Note that signer implementations may raise errors (during both
    Signer.from_priv_key_uri() and Signer.sign()) that are not documented here:
    examples could include network errors or file read errors. Applications
    should use generic try-except here if unexpected raises are not an option.

    See SIGNER_FOR_URI_SCHEME for supported private key URI schemes. The
    currently supported default schemes are:
    * envvar: see SSlibSigner for details
    * file: see SSlibSigner for details

    Interactive applications may also define a secrets handler that allows
    asking for user secrets if they are needed:

        from getpass import getpass

        def sec_handler(secret_name:str) -> str:
            return getpass(f"Enter {secret_name}: ")

        # user will not be asked for a passphrase for unencrypted key
        uri = "file:keys/mykey?encrypted=false"
        signer = Signer.from_priv_key_uri(uri, pub_key, sec_handler)

        # user will be asked for a passphrase for encrypted key
        uri2 = "file:keys/myenckey?encrypted=true"
        signer2 = Signer.from_priv_key_uri(uri2, pub_key2, sec_handler)

    Applications can provide their own Signer and Key implementations:

        from securesystemslib.signer import Signer, SIGNER_FOR_URI_SCHEME
        from mylib import MySigner

        SIGNER_FOR_URI_SCHEME[MySigner.MY_SCHEME] = MySigner

    This way the application code using signer API continues to work with
    default signers but now also uses the custom signer when the proper URI is
    used.
    """

    @abstractmethod
    def sign(self, payload: bytes) -> Signature:
        """Signs a given payload by the key assigned to the Signer instance.

        Arguments:
            payload: The bytes to be signed.

        Returns:
            Returns a "Signature" class instance.
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    @abstractmethod
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
        PATH is a file path to a file with private key content. If
        encrypted=true, the file is expected to have been created with
        securesystemslib.keys.encrypt_key().
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

        Please refer to Signer.from_priv_key_uri() documentation.

        Additionally raises:
            OSError: Reading the file failed with "file:" URI
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

        Please see Signer.sign() documentation.

        Additionally raises:
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            securesystemslib.exceptions.CryptoError, \
                securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.
        """
        sig_dict = sslib_keys.create_signature(self.key_dict, payload)
        return Signature(**sig_dict)


class GPGSigner(Signer):
    """A securesystemslib gpg implementation of the "Signer" interface.

    Provides a sign method to generate a cryptographic signature with gpg, using
    an RSA, DSA or EdDSA private key identified by the keyid on the instance.
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


class HSMSigner(Signer):
    """Hardware Security Module (HSM) Signer.

    HSMSigner uses the PKCS#11/Cryptoki API to sign on an HSM (e.g. YubiKey). It
    supports ecdsa on SECG curves secp256r1 (NIST P-256) or secp384r1 (NIST P-384).

    Arguments:
        hsm_session: An open and logged-in ``PyKCS11.Session`` to the token with the
                private key.
        hsm_keyid: Key identifier on the token.
        public_key: The related public key instance.

    Raises:
        UnsupportedLibraryError: ``PyKCS11`` and ``cryptography`` libraries not found.
        ValueError: ``public_key.scheme`` not supported.
    """

    def __init__(
        self,
        hsm_session: "PyKCS11.Session",
        hsm_keyid: Tuple[int, ...],
        public_key: Key,
    ):
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if PYKCS11_IMPORT_ERROR:
            raise UnsupportedLibraryError(PYKCS11_IMPORT_ERROR)

        # TODO: Define as module level constant and don't hardcode scheme strings
        supported_schemes = {
            "ecdsa-sha2-nistp256": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256),
            "ecdsa-sha2-nistp384": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA384),
        }

        if public_key.scheme not in supported_schemes:
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        self._mechanism = supported_schemes[public_key.scheme]
        self.hsm_session = hsm_session
        self.hsm_keyid = hsm_keyid
        self.public_key = public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "HSMSigner":
        raise NotImplementedError("Incompatible with private key URIs")

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Hardware Security Module (HSM).

        Arguments:
            payload: bytes to be signed.

        Raises:
            ValueError: No compatible key for ``hsm_keyid`` found on HSM.
            PyKCS11.PyKCS11Error: Various HSM communication errors.

        Returns:
            Signature.
        """

        # Search for ecdsa public keys with passed keyid on HSM
        keys = self.hsm_session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_ID, self.hsm_keyid),
            ]
        )
        if len(keys) != 1:
            raise ValueError(
                f"hsm_keyid must identify one {KEY_TYPE_ECDSA} key, found {len(keys)}"
            )

        signature = self.hsm_session.sign(keys[0], payload, self._mechanism)

        # The PKCS11 signature octets correspond to the concatenation of the ECDSA
        # values r and s, both represented as an octet string of equal length of at
        # most nLen with the most significant byte first (i.e. big endian)
        # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
        r_s_len = int(len(signature) / 2)
        r = int.from_bytes(signature[:r_s_len], byteorder="big")
        s = int.from_bytes(signature[r_s_len:], byteorder="big")

        # Create an ASN.1 encoded Dss-Sig-Value to be used with pyca/cryptography
        dss_sig_value = binascii.hexlify(encode_dss_signature(r, s)).decode(
            "ascii"
        )

        return Signature(self.public_key.keyid, dss_sig_value)
