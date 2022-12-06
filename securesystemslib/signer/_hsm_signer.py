"""Hardware Security Module (HSM) Signer

Uses PKCS#11/Cryptoki API to create signatures with HSMs (e.g. YubiKey) and to export
the related public keys.

"""
import binascii
from contextlib import contextmanager
from typing import Optional, Tuple
from urllib import parse

from securesystemslib import KEY_TYPE_ECDSA
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

# pylint: disable=wrong-import-position
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

    # TODO: Don't hardcode schemes
    _MECHANISM_FOR_SCHEME = {
        "ecdsa-sha2-nistp256": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256),
        "ecdsa-sha2-nistp384": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA384),
    }

except ImportError:
    PYKCS11_IMPORT_ERROR = "'PyKCS11' required"

ASN1_IMPORT_ERROR = None
try:
    from asn1crypto.keys import (  # pylint: disable=import-error
        ECDomainParameters,
        ECPoint,
    )
except ImportError:
    ASN1_IMPORT_ERROR = "'asn1crypto' required"
# pylint: enable=wrong-import-position


_PYKCS11LIB = None


def PYKCS11LIB():
    """Pseudo-singleton to load shared library using PYKCS11LIB envvar only once."""
    global _PYKCS11LIB  # pylint: disable=global-statement
    if _PYKCS11LIB is None:
        _PYKCS11LIB = PyKCS11.PyKCS11Lib()
        _PYKCS11LIB.load()

    return _PYKCS11LIB


class HSMSigner(Signer):
    """Hardware Security Module (HSM) Signer.

    Supports signing schemes "ecdsa-sha2-nistp256" and "ecdsa-sha2-nistp384".

    HSMSigner uses the first token it finds, if multiple tokens are available. They can
    be instantiated with Signer.from_priv_key_uri(). These private key URI schemes are
    supported:

    * "hsm:":
      Sign with key on PIV digital signature slot 9c.

    Usage (w/o URI)::

        key = HSMSigner.pubkey_from_hsm(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        signer = HSMSigner(2, key, lambda sec: "USER PIN")
        sig = signer.sign(b"DATA")
        key.verify_signature(sig, b"DATA")

    Arguments:
        hsm_keyid: Key identifier on the token.
        public_key: The related public key instance.
        secrets_handler: A function that returns the HSM user bin. The function
                is passed the string "pin".

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
        self, hsm_keyid: int, public_key: Key, secrets_handler: SecretsHandler
    ):
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if PYKCS11_IMPORT_ERROR:
            raise UnsupportedLibraryError(PYKCS11_IMPORT_ERROR)

        if public_key.scheme not in _MECHANISM_FOR_SCHEME:
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        self._mechanism = _MECHANISM_FOR_SCHEME[public_key.scheme]
        self.hsm_keyid = hsm_keyid
        self.public_key = public_key
        self.secrets_handler = secrets_handler

    @staticmethod
    @contextmanager
    def _default_session():
        """Context manager to handle default HSM session on reader slot 1."""
        lib = PYKCS11LIB()
        slots = lib.getSlotList(tokenPresent=True)
        if not slots:
            raise ValueError("could not find token")

        session = lib.openSession(slots[0])
        try:
            yield session

        finally:
            session.closeSession()

    @classmethod
    def _find_key(
        cls,
        session: "PyKCS11.Session",
        keyid: int,
        key_type: Optional[int] = None,
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
            raise ValueError(f"could not find {KEY_TYPE_ECDSA} key for {keyid}")

        if len(keys) > 1:
            raise ValueError(
                f"found more than one {KEY_TYPE_ECDSA} key for {keyid}"
            )

        return keys[0]

    @classmethod
    def _find_key_values(
        cls, session: "PyKCS11.Session", keyid: int
    ) -> Tuple["ECDomainParameters", bytes]:
        """Find ecdsa public key values on HSM."""
        key = cls._find_key(session, keyid)
        params, point = session.getAttributeValue(
            key, [PyKCS11.CKA_EC_PARAMS, PyKCS11.CKA_EC_POINT]
        )
        return ECDomainParameters.load(bytes(params)), bytes(point)

    @classmethod
    def pubkey_from_hsm(
        cls, sslib_keyid: str, hsm_keyid: Optional[int] = None
    ) -> SSlibKey:
        """Export public key from HSM.

        Arguments:
            sslib_keyid: Key identifier that is unique within the metadata it is used in.
            hsm_keyid: Key identifier on the token. Default is PIV key slot 9c.

        Raises:
            UnsupportedLibraryError: ``PyKCS11``, ``cryptography`` or ``asn1crypto``
                    libraries not found.
            ValueError: No compatible key for ``hsm_keyid`` found on HSM.
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

        with cls._default_session() as session:
            params, point = cls._find_key_values(session, hsm_keyid)

        if params.chosen.native not in _CURVE_NAMES:
            raise ValueError(
                f"found key on {params.chosen.native}, should be on one of {_CURVE_NAMES}"
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

        return SSlibKey(
            sslib_keyid,
            KEY_TYPE_ECDSA,
            _SCHEME_FOR_CURVE[curve],
            {"public": public_pem},
        )

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "HSMSigner":
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"HSMSigner does not support {priv_key_uri}")

        if secrets_handler is None:
            raise ValueError("HSMSigner requires a secrets handler")

        return cls(cls.SCHEME_KEYID, public_key, secrets_handler)

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

        with self._default_session() as session:
            session.login(self.secrets_handler(self.SECRETS_HANDLER_MSG))
            key = self._find_key(
                session, self.hsm_keyid, PyKCS11.CKO_PRIVATE_KEY
            )
            signature = session.sign(key, payload, self._mechanism)
            session.logout()

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
