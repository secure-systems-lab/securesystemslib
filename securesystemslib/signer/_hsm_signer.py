"""Hardware Security Module (HSM) Signer

Uses PKCS#11/Cryptoki API to create signatures with HSMs (e.g. YubiKey) and to export
the related public keys.

"""

from __future__ import annotations

import binascii
from collections.abc import Iterator
from contextlib import contextmanager
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.hash import digest
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer
from securesystemslib.signer._utils import compute_default_keyid

_KEY_TYPE_ECDSA = "ecdsa"

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        SECP384R1,
        EllipticCurvePublicKey,
        ObjectIdentifier,
        get_curve_for_oid,
    )
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )

    # TODO: Don't hardcode schemes
    _SCHEME_FOR_CURVE = {
        SECP256R1: "ecdsa-sha2-nistp256",
        SECP384R1: "ecdsa-sha2-nistp384",
    }
    _CURVE_NAMES = [curve.name for curve in _SCHEME_FOR_CURVE]

except ImportError:
    CRYPTO_IMPORT_ERROR = "'cryptography' required"

PYKCS11_IMPORT_ERROR = None
try:
    from PyKCS11 import PyKCS11
except ImportError:
    PYKCS11_IMPORT_ERROR = "'PyKCS11' required"

ASN1_IMPORT_ERROR = None
try:
    from asn1crypto.keys import (
        ECDomainParameters,
        ECPoint,
    )
except ImportError:
    ASN1_IMPORT_ERROR = "'asn1crypto' required"


_PYKCS11LIB = None


def PYKCS11LIB():  # noqa: N802
    """Pseudo-singleton to load shared library using PYKCS11LIB envvar only once."""
    global _PYKCS11LIB  # noqa: PLW0603
    if _PYKCS11LIB is None:
        _PYKCS11LIB = PyKCS11.PyKCS11Lib()
        _PYKCS11LIB.load()

    return _PYKCS11LIB


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
        token_filter: Dictionary of token field names and values
        public_key: The related public key instance.
        pin_handler: A function that returns the HSM user login pin, needed for
                signing. It receives the string argument "pin".

    Raises:
        UnsupportedLibraryError: ``PyKCS11`` and ``cryptography`` libraries not found.
        ValueError: ``public_key.scheme`` not supported.
    """

    # See Yubico docs for PKCS keyid to PIV slot mapping
    # https://developers.yubico.com/PIV/Introduction/Certificate_slots.html
    # https://developers.yubico.com/yubico-piv-tool/YKCS11/
    SCHEME_KEYID = 2
    SCHEME = "hsm"
    SECRETS_HANDLER_MSG = "pin"

    def __init__(
        self,
        hsm_keyid: int,
        token_filter: dict[str, str],
        public_key: Key,
        pin_handler: SecretsHandler,
    ):
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if PYKCS11_IMPORT_ERROR:
            raise UnsupportedLibraryError(PYKCS11_IMPORT_ERROR)

        if public_key.scheme not in [
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
        ]:
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        self.hsm_keyid = hsm_keyid
        self.token_filter = token_filter
        self._public_key = public_key
        self.pin_handler = pin_handler

    @property
    def public_key(self) -> Key:
        return self._public_key

    @staticmethod
    def _find_pkcs_slot(filters: dict[str, str]) -> int:
        """Return the PKCS slot with initialized token that matches filter

        Raises ValueError if more or less than 1 PKCS slot is found.
        """
        lib = PYKCS11LIB()
        slots: list[int] = []
        for slot in lib.getSlotList(tokenPresent=True):
            tokeninfo = lib.getTokenInfo(slot)
            if not tokeninfo.flags & PyKCS11.CKF_TOKEN_INITIALIZED:
                # useful for tests (softhsm always has an unitialized token)
                continue

            match = True
            # all values in filters must match token fields
            for key, value in filters.items():
                tokenvalue: str = getattr(tokeninfo, key, "").strip()
                if tokenvalue != value:
                    match = False

            if match:
                slots.append(slot)

        if len(slots) != 1:
            raise ValueError(
                f"Found {len(slots)} cryptographic tokens matching filter {filters}"
            )

        return slots[0]

    @staticmethod
    @contextmanager
    def _get_session(filters: dict[str, str]) -> Iterator[PyKCS11.Session]:
        """Context manager to handle a HSM session.

        The cryptographic token is selected by filtering by token info fields.
        ValueError is raised if matching token is not found, or if more
        than one are found.
        """
        slot = HSMSigner._find_pkcs_slot(filters)
        session = PYKCS11LIB().openSession(slot)
        try:
            yield session
        finally:
            session.closeSession()

    @classmethod
    def _find_key(
        cls,
        session: PyKCS11.Session,
        keyid: int,
        key_type: int | None = None,
    ) -> int:
        """Find ecdsa key on HSM."""
        if key_type is None:
            key_type = PyKCS11.CKO_PUBLIC_KEY

        keys = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, key_type),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_ID, (keyid,)),
            ]
        )
        if not keys:
            raise ValueError(f"could not find {_KEY_TYPE_ECDSA} key for {keyid}")

        if len(keys) > 1:
            raise ValueError(f"found more than one {_KEY_TYPE_ECDSA} key for {keyid}")

        return keys[0]

    @classmethod
    def _find_key_values(
        cls, session: PyKCS11.Session, keyid: int
    ) -> tuple[ECDomainParameters, bytes]:
        """Find ecdsa public key values on HSM."""
        key = cls._find_key(session, keyid)
        params, point = session.getAttributeValue(
            key, [PyKCS11.CKA_EC_PARAMS, PyKCS11.CKA_EC_POINT]
        )
        return ECDomainParameters.load(bytes(params)), bytes(point)

    @classmethod
    def _build_token_filter(cls) -> dict[str, str]:
        """Builds a token filter for the found cryptographic token.

        The filter will include 'label' if one is found on token.

        raises ValueError if less or more than 1 token is found
        """

        lib = PYKCS11LIB()
        slot = cls._find_pkcs_slot({})
        tokeninfo = lib.getTokenInfo(slot)

        filters = {}
        # other possible fields include manufacturerID, model and serialNumber
        for key in ["label"]:
            try:
                filters[key] = getattr(tokeninfo, key).strip()
            except AttributeError:
                pass

        return filters

    @classmethod
    def import_(
        cls,
        hsm_keyid: int | None = None,
        token_filter: dict[str, str] | None = None,
    ) -> tuple[str, SSlibKey]:
        """Import public key and signer details from HSM.

        Either only one cryptographic token must be present when importing or a
        token_filter that matches a single token must be provided.

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. import_() should be called once and the returned URI and public
        key should be stored for later use.

        Arguments:
            hsm_keyid: Key identifier on the token.
                Default is 2 (meaning PIV key slot 9c).
            token_filter: Dictionary of token field names and values used to
                filter the correct cryptographic token. If no filter is
                provided one is built from the fields found on the token.

        Raises:
            UnsupportedLibraryError: ``PyKCS11``, ``cryptography`` or ``asn1crypto``
                    libraries not found.
            ValueError: A matching HSM device could not be found.
            PyKCS11.PyKCS11Error: Various HSM communication errors.
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if PYKCS11_IMPORT_ERROR:
            raise UnsupportedLibraryError(PYKCS11_IMPORT_ERROR)

        if ASN1_IMPORT_ERROR:
            raise UnsupportedLibraryError(ASN1_IMPORT_ERROR)

        if hsm_keyid is None:
            hsm_keyid = cls.SCHEME_KEYID

        if token_filter is None:
            token_filter = cls._build_token_filter()

        uri = f"{cls.SCHEME}:{hsm_keyid}?{parse.urlencode(token_filter)}"

        with cls._get_session(token_filter) as session:
            params, point = cls._find_key_values(session, hsm_keyid)

        if params.chosen.native not in _CURVE_NAMES:
            raise ValueError(
                f"found key on {params.chosen.native}, "
                f"should be on one of {_CURVE_NAMES}"
            )

        # Create PEM from key
        curve = get_curve_for_oid(ObjectIdentifier(params.chosen.dotted))
        public_pem = (
            EllipticCurvePublicKey.from_encoded_point(
                curve(), ECPoint().load(point).native
            )
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

        keyval = {"public": public_pem}
        scheme = _SCHEME_FOR_CURVE[curve]
        keyid = compute_default_keyid(_KEY_TYPE_ECDSA, scheme, keyval)
        key = SSlibKey(keyid, _KEY_TYPE_ECDSA, scheme, keyval)

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
        token_filter = dict(parse.parse_qsl(uri.query))

        if secrets_handler is None:
            raise ValueError("HSMSigner requires a secrets handler")

        return cls(keyid, token_filter, public_key, secrets_handler)

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

        hasher = digest(algorithm=f"sha{self.public_key.scheme[-3:]}")
        hasher.update(payload)

        pin = self.pin_handler(self.SECRETS_HANDLER_MSG)
        with self._get_session(self.token_filter) as session:
            session.login(pin)
            key = self._find_key(session, self.hsm_keyid, PyKCS11.CKO_PRIVATE_KEY)
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)
            signature = session.sign(key, hasher.digest(), mechanism)
            session.logout()

        # The PKCS11 signature octets correspond to the concatenation of the ECDSA
        # values r and s, both represented as an octet string of equal length of at
        # most nLen with the most significant byte first (i.e. big endian)
        # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
        r_s_len = int(len(signature) / 2)
        r = int.from_bytes(signature[:r_s_len], byteorder="big")
        s = int.from_bytes(signature[r_s_len:], byteorder="big")

        # Create an ASN.1 encoded Dss-Sig-Value to be used with pyca/cryptography
        dss_sig_value = binascii.hexlify(encode_dss_signature(r, s)).decode("ascii")

        return Signature(self.public_key.keyid, dss_sig_value)
