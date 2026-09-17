"""Signer interface"""

from __future__ import annotations

import importlib
import logging
from abc import ABCMeta, abstractmethod
from collections.abc import Callable

from securesystemslib.signer._key import Key
from securesystemslib.signer._signature import Signature

logger = logging.getLogger(__name__)

_DEFAULT_SIGNERS = {
    "awskms": ("securesystemslib.signer._aws_signer", "AWSSigner"),
    "azurekms": ("securesystemslib.signer._azure_signer", "AzureSigner"),
    "file2": ("securesystemslib.signer._crypto_signer", "CryptoSigner"),
    "gcpkms": ("securesystemslib.signer._gcp_signer", "GCPSigner"),
    "gnupg": ("securesystemslib.signer._gpg_signer", "GPGSigner"),
    "hsm": ("securesystemslib.signer._hsm_signer", "HSMSigner"),
    "hv": ("securesystemslib.signer._vault_signer", "VaultSigner"),
    "tkey": ("securesystemslib.signer._tkey_signer", "TKeySigner"),
}


SIGNER_FOR_URI_SCHEME: dict[str, type] = {}
"""Custom signers and cached implementations for ``Signer.from_priv_key_uri()``.

Built-in implementations are added on first use through the URI factory.
Entries registered by applications take precedence over built-ins. Iteration
and copies contain only registered or cached entries, not all supported schemes.
Deleting an entry clears its override or cache: a built-in can be loaded again
on the next factory call.
"""

# SecretsHandler is a function the calling code can provide to Signer:
# SecretsHandler will be called if Signer needs additional secrets.
# The argument is the name of the secret ("PIN", "passphrase", etc).
# Return value is the secret string.
SecretsHandler = Callable[[str], str]


class Signer(metaclass=ABCMeta):
    """Signer interface that supports multiple signing implementations.

    Usage example::

        signer = Signer.from_priv_key_uri(uri, pub_key)
        sig = signer.sign(b"data")

    Note that signer implementations may raise errors (during both
    ``Signer.from_priv_key_uri()`` and ``Signer.sign()``) that are not
    documented here: examples could include network errors or file read errors.
    Applications should use generic try-except here if unexpected raises are
    not an option.

    See each signer implementation for its supported private key URI scheme.

    Interactive applications may also define a secrets handler that allows
    asking for user secrets if they are needed::

        from getpass import getpass

        def sec_handler(secret_name:str) -> str:
            return getpass(f"Enter {secret_name}: ")

        signer = Signer.from_priv_key_uri(uri, pub_key, sec_handler)

    Applications can provide their own Signer and Key implementations::

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
        secrets_handler: SecretsHandler | None = None,
    ) -> Signer:
        """Factory constructor for a given private key URI

        Returns a specific Signer instance based on the private key URI and the
        built-in URI schemes or custom entries in ``SIGNER_FOR_URI_SCHEME``.

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
        signer = SIGNER_FOR_URI_SCHEME.get(scheme)
        if signer is None:
            if scheme not in _DEFAULT_SIGNERS:
                raise ValueError(f"Unsupported private key scheme {scheme}")

            module_name, class_name = _DEFAULT_SIGNERS[scheme]
            signer = getattr(importlib.import_module(module_name), class_name)
            SIGNER_FOR_URI_SCHEME[scheme] = signer

        return signer.from_priv_key_uri(priv_key_uri, public_key, secrets_handler)  # type: ignore

    @property
    @abstractmethod
    def public_key(self) -> Key:
        """
        Returns:
            Public key the signer is based off.
        """
        raise NotImplementedError
