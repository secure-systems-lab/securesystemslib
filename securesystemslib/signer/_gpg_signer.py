"""Signer implementation for OpenPGP """

import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse

from securesystemslib import exceptions
from securesystemslib.gpg import exceptions as gpg_exceptions
from securesystemslib.gpg import functions as gpg
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer

logger = logging.getLogger(__name__)


class GPGKey(Key):
    """OpenPGP Key.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Attributes:
        keyid: Key identifier that is unique within the metadata it is used in.
                It is also used to identify the GnuPG local user signing key.
        ketytype:  Key type, e.g. "rsa", "dsa" or "eddsa".
        scheme: Signing schemes, e.g. "pgp+rsa-pkcsv1.5", "pgp+dsa-fips-180-2",
                "pgp+eddsa-ed25519".
        hashes: Hash algorithm to hash the data to be signed, e.g.  "pgp+SHA2".
        keyval: Opaque key content.
        creation_time: Unix timestamp when key was created.
        validity_period: Validity of key in days.
        subkeys: A dictionary of keyids as keys and GPGKeys as values.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by Securesystemslib
    """

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        hashes: List[str],
        keyval: Dict[str, Any],
        creation_time: Optional[int] = None,
        validity_period: Optional[int] = None,
        subkeys: Optional[Dict[str, "GPGKey"]] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):

        super().__init__(keyid, keytype, scheme, keyval, unrecognized_fields)

        self.hashes = hashes
        self.creation_time = creation_time
        self.validity_period = validity_period
        self.subkeys = subkeys

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, GPGKey):
            return False

        return (
            super().__eq__(other)
            and self.hashes == other.hashes
            and self.creation_time == other.creation_time
            and self.validity_period == other.validity_period
            and self.subkeys == other.subkeys
        )

    @classmethod
    def __from_dict(
        cls,
        keyid: str,
        keytype: str,
        scheme: str,
        subkeys: Optional[Dict[str, "GPGKey"]],
        key_dict: Dict[str, Any],
    ) -> "GPGKey":
        """Helper for common from_*dict operations."""

        hashes = key_dict.pop("hashes")
        keyval = key_dict.pop("keyval")
        creation_time = key_dict.pop("creation_time", None)
        validity_period = key_dict.pop("validity_period", None)

        return cls(
            keyid,
            keytype,
            scheme,
            hashes,
            keyval,
            creation_time,
            validity_period,
            subkeys,
            key_dict,
        )

    @classmethod
    def _from_legacy_dict(cls, key_dict: Dict[str, Any]) -> "GPGKey":
        """Create GPGKey from legacy dictionary representation."""

        keyid = key_dict.pop("keyid")
        keytype = key_dict.pop("type")
        scheme = key_dict.pop("method")
        subkeys = key_dict.pop("subkeys", None)

        if subkeys is not None:
            subkeys = {
                keyid: cls._from_legacy_dict(
                    key
                )  # pylint: disable=protected-access
                for (keyid, key) in subkeys.items()
            }

        return cls.__from_dict(keyid, keytype, scheme, subkeys, key_dict)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "GPGKey":
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        subkeys = key_dict.pop("subkeys", None)

        if subkeys:
            subkeys = {
                keyid: cls.from_dict(keyid, key)
                for (keyid, key) in subkeys.items()
            }

        return cls.__from_dict(keyid, keytype, scheme, subkeys, key_dict)

    def __to_dict(self) -> Dict[str, Any]:
        """Helper for common to_*dict operations."""

        key_dict: Dict[str, Any] = {
            "hashes": self.hashes,
            "keyval": self.keyval,
        }
        if self.creation_time is not None:
            key_dict["creation_time"] = self.creation_time

        if self.validity_period is not None:
            key_dict["validity_period"] = self.validity_period

        return key_dict

    def _to_legacy_dict(self) -> Dict[str, Any]:
        """Returns legacy dictionary representation of self."""

        key_dict = self.__to_dict()
        key_dict.update(
            {
                "keyid": self.keyid,
                "type": self.keytype,
                "method": self.scheme,
            }
        )

        if self.subkeys:
            key_dict["subkeys"] = {
                keyid: key._to_legacy_dict()  # pylint: disable=protected-access
                for (keyid, key) in self.subkeys.items()
            }

        return key_dict

    def to_dict(self) -> Dict[str, Any]:
        key_dict = self.__to_dict()
        key_dict.update(
            {
                "keytype": self.keytype,
                "scheme": self.scheme,
                **self.unrecognized_fields,
            }
        )

        if self.subkeys:
            key_dict["subkeys"] = {
                keyid: key.to_dict() for (keyid, key) in self.subkeys.items()
            }

        return key_dict

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            if not gpg.verify_signature(
                GPGSigner._sig_to_legacy_dict(  # pylint: disable=protected-access
                    signature
                ),
                self._to_legacy_dict(),
                data,
            ):
                raise exceptions.UnverifiedSignatureError(
                    f"Failed to verify signature by {self.keyid}"
                )
        except (
            exceptions.FormatError,
            exceptions.UnsupportedLibraryError,
            gpg_exceptions.KeyExpirationError,
        ) as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise exceptions.VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e


class GPGSigner(Signer):
    """OpenPGP Signer

    Runs command in ``GNUPG`` environment variable to sign. Fallback commands are
    ``gpg2`` and ``gpg``.

    Supported signing schemes are: "pgp+rsa-pkcsv1.5", "pgp+dsa-fips-180-2" and
    "pgp+eddsa-ed25519", with SHA-256 hashing.

    GPGSigner can be instantiated with Signer.from_priv_key_uri(). These private key URI
    schemes are supported:

    * "gnupg:[<GnuPG homedir>]":
        Signs with GnuPG key in keyring in home dir. The signing key is
        identified with the keyid of the passed public key. If homedir is not
        passed, the default homedir is used.

    Arguments:
        public_key: The related public key instance.
        homedir: GnuPG home directory path. If not passed, the default homedir is used.

    """

    SCHEME = "gnupg"

    def __init__(
        self,
        public_key: Key,
        homedir: Optional[str] = None,
    ):
        self.homedir = homedir
        self.public_key = public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "GPGSigner":
        if not isinstance(public_key, GPGKey):
            raise ValueError(f"expected GPGKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"GPGSigner does not support {priv_key_uri}")

        homedir = uri.path or None

        return cls(public_key, homedir)

    @staticmethod
    def _sig_to_legacy_dict(sig: Signature) -> Dict:
        """Helper to convert Signature to internal gpg signature dict format."""
        sig_dict = sig.to_dict()
        sig_dict["signature"] = sig_dict.pop("sig")
        return sig_dict

    @staticmethod
    def _sig_from_legacy_dict(sig_dict: Dict) -> Signature:
        """Helper to convert internal gpg signature format to Signature."""
        sig_dict["sig"] = sig_dict.pop("signature")
        return Signature.from_dict(sig_dict)

    @classmethod
    def import_(
        cls, keyid: str, homedir: Optional[str] = None
    ) -> Tuple[str, Key]:
        """Load key and signer details from GnuPG keyring

        Args:
            keyid: GnuPG local user signing key id.
            homedir: GnuPG home directory path. If not passed, the default homedir is
                    used.

        Returns:
            Tuple of private key uri and the public key.

        """
        uri = f"{cls.SCHEME}:{homedir or ''}"

        public_key = (
            GPGKey._from_legacy_dict(  # pylint: disable=protected-access
                gpg.export_pubkey(keyid, homedir)
            )
        )

        return (uri, public_key)

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with GnuPG.

        Arguments:
            payload: bytes to be signed.

        Raises:
            ValueError: gpg command failed to create a valid signature.
            OSError: gpg command is not present or non-executable.
            securesystemslib.exceptions.UnsupportedLibraryError: gpg command is not
                available, or the cryptography library is not installed.
            securesystemslib.gpg.exceptions.CommandError: gpg command returned a
                non-zero exit code.
            securesystemslib.gpg.exceptions.KeyNotFoundError: gpg version is not fully
                supported.

        Returns:
            Signature.
        """
        return self._sig_from_legacy_dict(
            gpg.create_signature(payload, self.public_key.keyid, self.homedir)
        )
