"""Signer implementation for OpenPGP """
from typing import Dict, Optional

import securesystemslib.gpg.functions as gpg
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer


class GPGSigner(Signer):
    """OpenPGP Signer

    Runs command in ``GNUPG`` environment variable to sign, fallback commands are
    ``gpg2`` and ``gpg``.

    Supported signing schemes are: "pgp+rsa-pkcsv1.5", "pgp+dsa-fips-180-2" and
    "pgp+eddsa-ed25519", with SHA-256 hashing.


    Arguments:
        keyid: GnuPG local user signing key id. If not passed, the default key is used.
        homedir: GnuPG home directory path. If not passed, the default homedir is used.

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
        """Signs payload with ``gpg``.

        Arguments:
            payload: bytes to be signed.

        Raises:
            ValueError: The gpg command failed to create a valid signature.
            OSError: the gpg command is not present or non-executable.
            securesystemslib.exceptions.UnsupportedLibraryError: The gpg
                command is not available, or the cryptography library is
                not installed.
            securesystemslib.gpg.exceptions.CommandError: The gpg command
                returned a non-zero exit code.
            securesystemslib.gpg.exceptions.KeyNotFoundError: The used gpg
                version is not fully supported.

        Returns:
            Signature.
        """
        return self._from_gpg_sig(
            gpg.create_signature(payload, self.keyid, self.homedir)
        )
