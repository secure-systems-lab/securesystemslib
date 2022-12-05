"""Hardware Security Module (HSM) Signer

"""
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

import binascii
from typing import Optional

from securesystemslib import KEY_TYPE_ECDSA
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer


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
        hsm_keyid: int,
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
                (PyKCS11.CKA_ID, (self.hsm_keyid,)),
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
