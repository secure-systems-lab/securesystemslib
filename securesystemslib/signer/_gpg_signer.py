"""Signer implementation for OpenPGP """
from typing import Dict, Optional

import securesystemslib.gpg.functions as gpg
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer


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

    @staticmethod
    def _to_gpg_sig(sig: Signature) -> Dict:
        """Helper to convert Signature -> internal gpg signature format."""
        sig_dict = sig.to_dict()
        sig_dict["signature"] = sig_dict.pop("sig")
        return sig_dict

    @staticmethod
    def _from_gpg_sig(sig_dict: Dict) -> Signature:
        """Helper to convert internal gpg signature format -> Signature."""
        sig_dict["sig"] = sig_dict.pop("signature")
        return Signature.from_dict(sig_dict)

    def sign(self, payload: bytes) -> Signature:
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
            Signature.
        """
        return self._from_gpg_sig(
            gpg.create_signature(payload, self.keyid, self.homedir)
        )
