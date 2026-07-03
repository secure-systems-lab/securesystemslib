"""Hardware Security Module (HSM) Signer

Uses python-pkcs11 API to create signatures with HSMs (e.g. YubiKey) and to export
the related public keys.

"""

from __future__ import annotations

import binascii
import hashlib
import os
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

_KEY_TYPE_ECDSA = "ecdsa"

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        SECP384R1,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    # TODO: Don't hardcode schemes
    _SCHEME_FOR_CURVE = {
        SECP256R1: "ecdsa-sha2-nistp256",
        SECP384R1: "ecdsa-sha2-nistp384",
    }

except ImportError:
    CRYPTO_IMPORT_ERROR = "'cryptography' required"

PKCS11_IMPORT_ERROR = None
try:
    import pkcs11
    from pkcs11.exceptions import NoSuchKey, NoSuchToken
except ImportError:
    PKCS11_IMPORT_ERROR = "'python-pkcs11' required"


class HSMSigner(Signer):
    """Hardware Security Module (HSM) Signer.

    Supports signing schemes "ecdsa-sha2-nistp256" and "ecdsa-sha2-nistp384".

    HSMSigners should be instantiated with Signer.from_priv_key_uri() as in the usage
    example below.

    The private key URI scheme is: "hsm:<KEYID>?<FILTERS>" where both KEYID and
    FILTERS are optional. Example URIs:
    * "hsm:":
      Sign with a key with default keyid 2 (PIV digital signature slot 9c) on the
      only token/smartcard available.
    * "hsm:2?label=YubiKey+PIV+%2315835999":
      Sign with key with keyid 2 (PIV slot 9c) on a token with label
      "YubiKey+PIV+%2315835999"

    Requires environment variable PYKCS11LIB to contain path to PKCS#11 module.

    Usage::

        # Store public key and URI for your HSM device for later use. By default
        # slot 9c is selected.
        uri, pubkey = HSMSigner.import_()

        # later, use the uri and pubkey to sign
        def pin_handler(secret: str) -> str:
            return getpass(f"Enter {secret}: ")

        signer = Signer.from_priv_key_uri(uri, pubkey, pin_handler)
        sig = signer.sign(b"DATA")
        pubkey.verify_signature(sig, b"DATA")

    Arguments:
        hsm_keyid: Key identifier on the token.
        public_key: The related public key instance.
        pin_handler: A function that returns the HSM user login pin, needed for
                signing. It receives the string argument "pin".
        token_label: Optional token label to filter by.

    Raises:
        UnsupportedLibraryError: ``python-pkcs11`` and ``cryptography``
            libraries not found.
        ValueError: ``public_key.scheme`` not supported.
    """

    SCHEME_KEYID = 2
    SCHEME = "hsm"
    SECRETS_HANDLER_MSG = "pin"

    def __init__(
        self,
        hsm_keyid: int,
        public_key: SSlibKey,
        pin_handler: SecretsHandler,
        token_label: str | None = None,
    ):
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if PKCS11_IMPORT_ERROR:
            raise UnsupportedLibraryError(PKCS11_IMPORT_ERROR)

        if public_key.scheme not in ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"]:
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        self.hsm_keyid = hsm_keyid
        self.token_label = token_label
        self._public_key = public_key
        self.pin_handler = pin_handler

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @staticmethod
    def _find_token(token_label: str | None = None) -> pkcs11.Token:
        """Return the PKCS#11 token that matches token_label."""
        lib_path = os.environ.get("PYKCS11LIB")
        if not lib_path:
            raise ValueError("PYKCS11LIB environment variable must be set")
        try:
            return pkcs11.lib(lib_path).get_token(
                token_label=token_label, token_flags=pkcs11.TokenFlag.TOKEN_INITIALIZED
            )
        except NoSuchToken:
            label_str = f" for label {token_label}" if token_label else ""
            raise ValueError(f"No PKCS#11 token found{label_str}")

    @staticmethod
    def _find_key(
        session: pkcs11.Session, keyid: int, private: bool = False
    ) -> pkcs11.Key:
        """Find ecdsa key on HSM."""
        cka_id_filter = pkcs11.util.biginteger(keyid)
        if private:
            object_class = pkcs11.ObjectClass.PRIVATE_KEY
        else:
            object_class = pkcs11.ObjectClass.PUBLIC_KEY

        try:
            return session.get_key(object_class, pkcs11.KeyType.EC, id=cka_id_filter)
        except NoSuchKey:
            raise ValueError("could not find ECDSA key on the PKCS#11 token")

    @classmethod
    def import_(
        cls,
        hsm_keyid: int | None = None,
        token_label: str | None = None,
        secrets_handler: SecretsHandler | None = None,
    ) -> tuple[str, SSlibKey]:
        """Import public key and signer details from HSM.

        Either only one cryptographic token must be present when importing or a
        token_label that matches a single token must be provided.

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. import_() should be called once and the returned URI and public
        key should be stored for later use.

        Arguments:
            hsm_keyid: Key identifier on the token.
                Default is 2 (meaning PIV key slot 9c).
            token_label: Token label to filter the correct cryptographic token.
                If no label is provided one is built from the token found.

        Raises:
            UnsupportedLibraryError: ``python-pkcs11`` and ``cryptography``
                libraries not found.
            ValueError: A matching HSM device or key could not be found.
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if PKCS11_IMPORT_ERROR:
            raise UnsupportedLibraryError(PKCS11_IMPORT_ERROR)

        hsm_keyid = hsm_keyid if hsm_keyid is not None else cls.SCHEME_KEYID
        token = cls._find_token(token_label)
        uri = f"{cls.SCHEME}:{hsm_keyid}"
        if token.label:
            uri = f"{uri}?{parse.urlencode({'label': token.label})}"

        def _get_pubkey_der(session: pkcs11.Session) -> bytes:
            pkcs11_key = cls._find_key(session, hsm_keyid)
            if not isinstance(pkcs11_key, pkcs11.PublicKey):
                raise AssertionError("PKCS key is not a public key")
            return pkcs11.util.ec.encode_ec_public_key(pkcs11_key)

        try:
            with token.open() as session:
                pubkey_der = _get_pubkey_der(session)
        except ValueError:
            # key not found while unauthenticated: it may be set to CKA_PRIVATE
            if secrets_handler is None:
                raise ValueError(
                    "No keys found unauthenticated and no secrets handler provided"
                )
            pin = secrets_handler(cls.SECRETS_HANDLER_MSG)
            with token.open(user_pin=pin) as session:
                pubkey_der = _get_pubkey_der(session)

        pubkey = load_der_public_key(pubkey_der)
        if not isinstance(pubkey, EllipticCurvePublicKey):
            raise ValueError("expected EllipticCurvePublicKey")
        if type(pubkey.curve) not in _SCHEME_FOR_CURVE:
            raise ValueError(f"{pubkey.curve.name} is not a supported EC curve")

        scheme = _SCHEME_FOR_CURVE[type(pubkey.curve)]
        key = SSlibKey.from_crypto(pubkey, scheme=scheme)
        return uri, key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> HSMSigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"HSMSigner does not support {priv_key_uri}")

        keyid = int(uri.path) if uri.path else cls.SCHEME_KEYID
        token_label = dict(parse.parse_qsl(uri.query)).get("label")

        if secrets_handler is None:
            raise ValueError("HSMSigner requires a secrets handler")

        return cls(keyid, public_key, secrets_handler, token_label)

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Hardware Security Module (HSM).

        Arguments:
            payload: bytes to be signed.

        Raises:
            ValueError: No compatible key for ``hsm_keyid`` found on HSM.

        Returns:
            Signature.
        """

        hasher = hashlib.new(name=f"sha{self.public_key.scheme[-3:]}")
        hasher.update(payload)

        pin = self.pin_handler(self.SECRETS_HANDLER_MSG)
        token = self._find_token(self.token_label)

        with token.open(rw=True, user_pin=pin) as session:
            key = self._find_key(session, self.hsm_keyid, private=True)
            if not isinstance(key, pkcs11.SignMixin):
                raise AssertionError("Signing key is not a SignMixin")
            signature = key.sign(hasher.digest(), mechanism=pkcs11.Mechanism.ECDSA)

        # Convert the PKCS#11 raw signature to ASN.1 DER
        asn_sig = pkcs11.util.ec.encode_ecdsa_signature(signature)
        hex_asn_sig = binascii.hexlify(asn_sig).decode("ascii")

        return Signature(self.public_key.keyid, hex_asn_sig)
