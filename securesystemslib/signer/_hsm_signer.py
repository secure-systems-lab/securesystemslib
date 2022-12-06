"""Hardware Security Module (HSM) Signer

"""
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
except ImportError:  # pragma: no cover
    CRYPTO_IMPORT_ERROR = "'cryptography' required"

PYKCS11_IMPORT_ERROR = None
try:
    from PyKCS11 import PyKCS11

except ImportError:  # pragma: no cover
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


import binascii
from typing import Optional
from urllib import parse

from securesystemslib import KEY_TYPE_ECDSA
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

_PYKCS11LIB = None


def PYKCS11LIB():
    global _PYKCS11LIB  # pylint: disable=global-statement
    if _PYKCS11LIB is None:
        _PYKCS11LIB = PyKCS11.PyKCS11Lib()
        _PYKCS11LIB.load()

    return _PYKCS11LIB


class HSMSigner(Signer):
    """Hardware Security Module (HSM) Signer.

    HSMSigner uses the PKCS#11/Cryptoki API to sign on an HSM (e.g. YubiKey). It
    supports ecdsa on SECG curves secp256r1 (NIST P-256) or secp384r1 (NIST P-384).

    Arguments:
        hsm_keyid: Key identifier on the token.
        public_key: The related public key instance.

    Raises:
        UnsupportedLibraryError: ``PyKCS11`` and ``cryptography`` libraries not found.
        ValueError: ``public_key.scheme`` not supported.
    """

    SCHEME = "hsm"
    # For now, we only support keyid 2, i.e. PIV slot 9c (Digital Signature)
    # https://developers.yubico.com/PIV/Introduction/Certificate_slots.html
    # https://developers.yubico.com/yubico-piv-tool/YKCS11/
    PIV_9C_KEYID = 2

    def __init__(
        self, hsm_keyid: int, public_key: Key, secrets_handler: SecretsHandler
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
        self.hsm_keyid = hsm_keyid
        self.public_key = public_key
        self.secrets_handler = secrets_handler

    @staticmethod
    def pubkey_from_hsm(hsm_keyid: int, sslib_keyid: str) -> SSlibKey:
        """Export public key from HSM

        Supports ecdsa on SECG curves secp256r1 (NIST P-256) or secp384r1 (NIST P-384).

        Arguments:
            hsm_keyid: Key identifier on the token.
            sslib_keyid: Key identifier that is unique within the metadata it is used in.

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

        lib = PYKCS11LIB()
        hsm_slot_id = lib.getSlotList(tokenPresent=True)[0]
        session = lib.openSession(hsm_slot_id)

        # Search for ecdsa public keys with passed keyid on HSM
        keys = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_ID, (hsm_keyid,)),
            ]
        )

        if len(keys) != 1:
            raise ValueError(
                f"hsm_keyid must identify one {KEY_TYPE_ECDSA} key, found {len(keys)}"
            )

        # Extract public key domain parameters and point from HSM
        hsm_params, hsm_point = session.getAttributeValue(
            keys[0], [PyKCS11.CKA_EC_PARAMS, PyKCS11.CKA_EC_POINT]
        )

        params = ECDomainParameters.load(bytes(hsm_params))

        session.closeSession()

        # TODO: Define as module level constant and don't hardcode scheme strings
        scheme_for_curve = {
            SECP256R1: "ecdsa-sha2-nistp256",
            SECP384R1: "ecdsa-sha2-nistp384",
        }
        curve_names = [curve.name for curve in scheme_for_curve]

        if params.chosen.native not in curve_names:
            raise ValueError(
                f"found key on {params.chosen.native}, should be on one of {curve_names}"
            )

        # Create PEM from key
        curve = get_curve_for_oid(ObjectIdentifier(params.chosen.dotted))
        public_pem = (
            EllipticCurvePublicKey.from_encoded_point(
                curve(), ECPoint().load(bytes(hsm_point)).native
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
            scheme_for_curve[curve],
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
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"HSMSigner does not support {priv_key_uri}")

        if secrets_handler is None:
            raise ValueError("HSMSigner requires a secrets handler")

        return cls(cls.PIV_9C_KEYID, public_key, secrets_handler)

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
        lib = PYKCS11LIB()
        slot_id = lib.getSlotList(tokenPresent=True)[0]
        session = lib.openSession(slot_id, PyKCS11.CKF_RW_SESSION)
        session.login(self.secrets_handler("pin"))

        # Search for ecdsa public keys with passed keyid on HSM
        keys = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_ID, (self.hsm_keyid,)),
            ]
        )
        if len(keys) != 1:
            raise ValueError(
                f"hsm_keyid must identify one {KEY_TYPE_ECDSA} key, found {len(keys)}"
            )

        signature = session.sign(keys[0], payload, self._mechanism)
        session.logout()
        session.closeSession()

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
