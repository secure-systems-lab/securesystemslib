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

from securesystemslib.exceptions import UnverifiedSignatureError
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

    hsm_keyid = 1
    hsm_keyid_default = 2
    hsm_user_pin = "123456"

    @staticmethod
    def _generate_key_pair(session, keyid, curve):
        "Create ecdsa key pair on hsm"
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

    @classmethod
    def setUpClass(cls):
        """Initialize SoftHSM token and generate ecdsa test keys"""
        so_pin = "abcd"
        token_label = "Test SoftHSM"

        # Configure SoftHSM to create test token in temporary test directory
        cls.original_cwd = os.getcwd()
        cls.test_dir = os.path.realpath(tempfile.mkdtemp())
        os.chdir(cls.test_dir)

        with open("softhsm2.conf", "w", encoding="utf-8") as f:
            f.write("directories.tokendir = " + os.path.join(cls.test_dir, ""))
        os.environ["SOFTHSM2_CONF"] = os.path.join(
            cls.test_dir, "softhsm2.conf"
        )

        # Only load shared library after above config
        lib = PYKCS11LIB()
        slot = lib.getSlotList(tokenPresent=True)[0]
        lib.initToken(slot, so_pin, token_label)

        tokeninfo = lib.getTokenInfo(slot)
        cls.token_filter = {"label": getattr(tokeninfo, "label")}

        session = PYKCS11LIB().openSession(slot, PyKCS11.CKF_RW_SESSION)
        session.login(so_pin, PyKCS11.CKU_SO)
        session.initPin(cls.hsm_user_pin)
        session.logout()

        session.login(cls.hsm_user_pin)

        # Generate test ecdsa key pairs for curves secp256r1 and secp384r1 on test token
        cls._generate_key_pair(session, cls.hsm_keyid, SECP256R1)
        cls._generate_key_pair(session, cls.hsm_keyid_default, SECP384R1)

        session.logout()
        session.closeSession()

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        shutil.rmtree(cls.test_dir)
        del os.environ["SOFTHSM2_CONF"]

    def test_hsm(self):
        """Test HSM key export and signing."""

        for hsm_keyid in [self.hsm_keyid, self.hsm_keyid_default]:
            _, key = HSMSigner.import_(hsm_keyid, self.token_filter)
            signer = HSMSigner(
                hsm_keyid, self.token_filter, key, lambda sec: self.hsm_user_pin
            )
            sig = signer.sign(b"DATA")
            key.verify_signature(sig, b"DATA")

            with self.assertRaises(UnverifiedSignatureError):
                key.verify_signature(sig, b"NOT DATA")

    def test_hsm_uri(self):
        """Test HSM default key export and signing from URI."""

        # default import
        uri, key = HSMSigner.import_()
        signer = Signer.from_priv_key_uri(
            uri, key, lambda sec: self.hsm_user_pin
        )
        sig = signer.sign(b"DATA")
        key.verify_signature(sig, b"DATA")
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")

        # Import with specified values
        uri, key = HSMSigner.import_(self.hsm_keyid_default, self.token_filter)
        signer = Signer.from_priv_key_uri(
            uri, key, lambda sec: self.hsm_user_pin
        )
        sig = signer.sign(b"DATA")
        key.verify_signature(sig, b"DATA")
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
