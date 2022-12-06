#!/usr/bin/env python
"""Test HSMSigner
"""
import os
import shutil
import tempfile
import unittest

from asn1crypto.keys import (  # pylint: disable=import-error
    ECDomainParameters,
    NamedCurve,
)
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1
from PyKCS11 import PyKCS11

import securesystemslib.hash
from securesystemslib.signer import HSMSigner, Signer
from securesystemslib.signer._hsm_signer import PYKCS11LIB


@unittest.skipUnless(
    os.environ.get("PYKCS11LIB"), "set PYKCS11LIB to SoftHSM lib path"
)
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

        hsm_token_label = "Test SoftHSM"
        hsm_so_pin = "abcd"

        lib = PYKCS11LIB()
        hsm_slot_id = lib.getSlotList(tokenPresent=True)[0]
        lib.initToken(hsm_slot_id, hsm_so_pin, hsm_token_label)

        session = PYKCS11LIB().openSession(hsm_slot_id, PyKCS11.CKF_RW_SESSION)
        session.login(hsm_so_pin, PyKCS11.CKU_SO)
        session.initPin(cls.hsm_user_pin)
        session.logout()

        session.login(cls.hsm_user_pin)

        # Generate test ecdsa key pairs for curves secp256r1 and secp384r1 on test token
        cls.hsm_keyids = []
        for keyid, curve in (
            (1, SECP256R1),
            (2, SECP384R1),
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
                (PyKCS11.CKA_ID, (keyid,)),
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
                (PyKCS11.CKA_ID, (keyid,)),
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

    def test_hsm(self):
        """Test public key export, HSM signing, and verification w/o HSM"""

        def _pre_hash(data, scheme):
            """Generate hash for scheme (test hack)"""
            hasher = securesystemslib.hash.digest(algorithm=f"sha{scheme[-3:]}")
            hasher.update(data)
            return hasher.digest()

        keyid = (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        data = b"deadbeef"

        for hsm_keyid in [1, 2]:
            public_key = HSMSigner.pubkey_from_hsm(hsm_keyid, keyid)

            if hsm_keyid == 2:
                signer = Signer.from_priv_key_uri(
                    "hsm:", public_key, lambda sec: self.hsm_user_pin
                )
            else:
                signer = HSMSigner(
                    hsm_keyid, public_key, lambda sec: self.hsm_user_pin
                )

            # NOTE: HSMSigner supports CKM_ECDSA_SHA256 and CKM_ECDSA_SHA384
            # mechanisms. But SoftHSM only supports CKM_ECDSA. During testing we
            # patch the HSMSigner mechanisms and pre-hash the data ourselves.
            signer._mechanism = (  # pylint: disable=protected-access
                PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)
            )
            sig = signer.sign(_pre_hash(data, public_key.scheme))

            public_key.verify_signature(sig, data)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
