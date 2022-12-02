#!/usr/bin/env python
"""Test HSMSigner
"""
import os
import shutil
import tempfile
import unittest

from asn1crypto.keys import (  # pylint: disable=import-error
    ECDomainParameters,
    ECPoint,
    NamedCurve,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    EllipticCurvePublicKey,
    ObjectIdentifier,
    get_curve_for_oid,
)
from PyKCS11 import PyKCS11

import securesystemslib.hash
from securesystemslib import KEY_TYPE_ECDSA
from securesystemslib.signer import HSMSigner, SSlibKey


class TestHSM(unittest.TestCase):
    """Test HSMSigner with SoftHSM

    Requirements:
    - install SoftHSM2
    - set environment variable ``PYKCS11LIB`` to SoftHSM library path

    See .github/workflows/hsm.yml for how this can be done on Linux, macOS and Windows.
    """

    hsm_user_pin = "1234"

    @classmethod
    def setUpClass(cls):
        """Initialize SoftHSM token and generate ecdsa test keys"""

        # Configure SoftHSM to create test token in temporary test directory
        cls.original_cwd = os.getcwd()
        cls.test_dir = os.path.realpath(tempfile.mkdtemp())
        os.chdir(cls.test_dir)

        with open("softhsm2.conf", "w", encoding="utf-8") as f:
            f.write("directories.tokendir = " + os.path.join(cls.test_dir, ""))

        os.environ["SOFTHSM2_CONF"] = os.path.join(
            cls.test_dir, "softhsm2.conf"
        )

        # Initialize test token
        cls.pkcs11 = PyKCS11.PyKCS11Lib()
        cls.pkcs11.load()
        hsm_token_label = "Test SoftHSM"
        hsm_so_pin = "abcd"

        hsm_slot_id = cls.pkcs11.getSlotList(tokenPresent=True)[0]
        cls.pkcs11.initToken(hsm_slot_id, hsm_so_pin, hsm_token_label)

        session = cls.pkcs11.openSession(hsm_slot_id, PyKCS11.CKF_RW_SESSION)
        session.login(hsm_so_pin, PyKCS11.CKU_SO)
        session.initPin(cls.hsm_user_pin)
        session.logout()

        session.login(cls.hsm_user_pin)

        # Generate test ecdsa key pairs for curves secp256r1 and secp384r1 on test token
        cls.hsm_keyids = []
        for keyid, curve in (
            ((0,), SECP256R1),
            ((1,), SECP384R1),
        ):

            params = ECDomainParameters(
                name="named", value=NamedCurve(curve.name)
            ).dump()

            public_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_WRAP, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_EC_PARAMS, params),
                (PyKCS11.CKA_LABEL, curve.name),
                (PyKCS11.CKA_ID, keyid),
            ]
            private_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_DECRYPT, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_UNWRAP, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_LABEL, curve.name),
                (PyKCS11.CKA_ID, keyid),
            ]

            session.generateKeyPair(
                public_template,
                private_template,
                mecha=PyKCS11.MechanismECGENERATEKEYPAIR,
            )

            cls.hsm_keyids.append(keyid)

        session.logout()
        session.closeSession()

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        shutil.rmtree(cls.test_dir)
        del os.environ["SOFTHSM2_CONF"]

    @staticmethod
    def _from_hsm(
        hsm_session,
        hsm_keyid,
        keyid,
    ):
        """Export public key from HSM

        Supports ecdsa on SECG curves secp256r1 (NIST P-256) or secp384r1 (NIST P-384).

        Arguments:
            hsm_session: An open ``PyKCS11.Session`` to the token with the public key.
            hsm_keyid: Key identifier on the token.
            keyid: Key identifier that is unique within the metadata it is used in.

        Raises:
            ValueError: No compatible key for ``hsm_keyid`` found on HSM.
            PyKCS11.PyKCS11Error: Various HSM communication errors.

        """
        # if CRYPTO_IMPORT_ERROR:
        #     raise exceptions.UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        # if PYKCS11_IMPORT_ERROR:
        #     raise exceptions.UnsupportedLibraryError(PYKCS11_IMPORT_ERROR)

        # Search for ecdsa public keys with passed keyid on HSM
        keys = hsm_session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_ID, hsm_keyid),
            ]
        )

        # if len(keys) != 1:
        #     raise ValueError(
        #         f"hsm_keyid must identify one {KEY_TYPE_ECDSA} key, found {len(keys)}"
        #     )

        # Extract public key domain parameters and point from HSM
        hsm_params, hsm_point = hsm_session.getAttributeValue(
            keys[0], [PyKCS11.CKA_EC_PARAMS, PyKCS11.CKA_EC_POINT]
        )

        params = ECDomainParameters.load(bytes(hsm_params))

        # TODO: Define as module level constant and don't hardcode scheme strings
        scheme_for_curve = {
            SECP256R1: "ecdsa-sha2-nistp256",
            SECP384R1: "ecdsa-sha2-nistp384",
        }
        # curve_names = [curve.name for curve in scheme_for_curve]

        # if params.chosen.native not in curve_names:
        #     raise ValueError(
        #         f"found key on {params.chosen.native}, should be on one of {curve_names}"
        #     )

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
            keyid,
            KEY_TYPE_ECDSA,
            scheme_for_curve[curve],
            {"public": public_pem},
        )

    def test_hsm(self):
        """Test public key export, HSM signing, and verification w/o HSM"""

        def _pre_hash(data, scheme):
            """Generate hash for scheme (test hack)"""
            hasher = securesystemslib.hash.digest(algorithm=f"sha{scheme[-3:]}")
            hasher.update(data)
            return hasher.digest()

        hsm_slot_id = self.pkcs11.getSlotList(tokenPresent=True)[0]
        session = self.pkcs11.openSession(hsm_slot_id)

        keyid = (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        data = b"deadbeef"

        for hsm_keyid in self.hsm_keyids:
            public_key = self._from_hsm(session, hsm_keyid, keyid)

            session.login(self.hsm_user_pin)  # Login for signing
            signer = HSMSigner(session, hsm_keyid, public_key)

            # NOTE: HSMSigner supports CKM_ECDSA_SHA256 and CKM_ECDSA_SHA384
            # mechanisms. But SoftHSM only supports CKM_ECDSA. During testing we
            # patch the HSMSigner mechanisms and pre-hash the data ourselves.
            signer._mechanism = (  # pylint: disable=protected-access
                PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)
            )
            sig = signer.sign(_pre_hash(data, public_key.scheme))

            session.logout()  # Logout after signing

            public_key.verify_signature(sig, data)

        session.closeSession()


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
