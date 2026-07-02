"""Test HSMSigner"""

import os
import shutil
import subprocess
import tempfile
import unittest

import pkcs11
from asn1crypto.keys import (
    ECDomainParameters,
    NamedCurve,
)
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import HSMSigner, Signer


@unittest.skipUnless(os.environ.get("PYKCS11LIB"), "set PYKCS11LIB to SoftHSM lib path")
class TestHSM(unittest.TestCase):
    """Test HSMSigner with SoftHSM

    Requirements:
    - install SoftHSM2
    - set environment variable ``PYKCS11LIB`` to SoftHSM library path

    See .github/workflows/hsm.yml for how this can be done on Linux, macOS and Windows.
    """

    hsm_keyid = 1
    hsm_keyid_default = 2
    hsm_keyid_odd = 258
    hsm_user_pin = "123456"
    token_label = "Test SoftHSM"

    @staticmethod
    def _generate_key_pair(session, keyid, curve):
        "Create ecdsa key pair on hsm"
        params = ECDomainParameters(name="named", value=NamedCurve(curve.name)).dump()
        cka_id = pkcs11.util.biginteger(keyid)

        public_template = {
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
            pkcs11.Attribute.PRIVATE: False,
            pkcs11.Attribute.TOKEN: True,
            pkcs11.Attribute.ENCRYPT: False,
            pkcs11.Attribute.VERIFY: True,
            pkcs11.Attribute.WRAP: False,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
            pkcs11.Attribute.EC_PARAMS: params,
            pkcs11.Attribute.LABEL: curve.name,
            pkcs11.Attribute.ID: cka_id,
        }
        private_template = {
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
            pkcs11.Attribute.TOKEN: True,
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.DECRYPT: False,
            pkcs11.Attribute.SIGN: True,
            pkcs11.Attribute.UNWRAP: False,
            pkcs11.Attribute.LABEL: curve.name,
            pkcs11.Attribute.ID: cka_id,
        }

        session.generate_keypair(
            pkcs11.KeyType.EC,
            256,
            store=True,
            mechanism=pkcs11.Mechanism.EC_KEY_PAIR_GEN,
            public_template=public_template,
            private_template=private_template,
        )

    @classmethod
    def setUpClass(cls):
        """Initialize SoftHSM token and generate ecdsa test keys"""

        # Configure SoftHSM to create test token in temporary test directory
        cls.original_cwd = os.getcwd()
        cls.test_dir = os.path.realpath(tempfile.mkdtemp())
        os.chdir(cls.test_dir)

        with open("softhsm2.conf", "w", encoding="utf-8") as f:
            f.write("directories.tokendir = " + os.path.join(cls.test_dir, ""))
        os.environ["SOFTHSM2_CONF"] = os.path.join(cls.test_dir, "softhsm2.conf")

        # Initialize the token using softhsm2-util
        subprocess.run(
            [
                "softhsm2-util",
                "--init-token",
                "--slot",
                "0",
                "--label",
                cls.token_label,
                "--so-pin",
                "abcd",
                "--pin",
                cls.hsm_user_pin,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )

        lib = pkcs11.lib(os.environ["PYKCS11LIB"])
        token = lib.get_token(token_label=cls.token_label)

        with token.open(rw=True, user_pin=cls.hsm_user_pin) as session:
            # Generate test ecdsa key pairs for curves secp256r1 and secp384r1 on test token
            cls._generate_key_pair(session, cls.hsm_keyid, SECP256R1)
            cls._generate_key_pair(session, cls.hsm_keyid_default, SECP384R1)
            cls._generate_key_pair(session, cls.hsm_keyid_odd, SECP256R1)

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        shutil.rmtree(cls.test_dir)
        del os.environ["SOFTHSM2_CONF"]

    def test_hsm(self):
        """Test HSM key export and signing."""

        for hsm_keyid in [self.hsm_keyid, self.hsm_keyid_default, self.hsm_keyid_odd]:
            _, key = HSMSigner.import_(hsm_keyid, self.token_label)
            signer = HSMSigner(
                hsm_keyid, key, lambda sec: self.hsm_user_pin, self.token_label
            )
            sig = signer.sign(b"DATA")
            key.verify_signature(sig, b"DATA")

            with self.assertRaises(UnverifiedSignatureError):
                key.verify_signature(sig, b"NOT DATA")

    def test_hsm_uri(self):
        """Test HSM default key export and signing from URI."""

        # default import
        uri, key = HSMSigner.import_()
        signer = Signer.from_priv_key_uri(uri, key, lambda sec: self.hsm_user_pin)
        sig = signer.sign(b"DATA")
        key.verify_signature(sig, b"DATA")
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")

        # import using arguments
        uri, key = HSMSigner.import_(self.hsm_keyid_default, self.token_label)
        signer = Signer.from_priv_key_uri(uri, key, lambda sec: self.hsm_user_pin)
        sig = signer.sign(b"DATA")
        key.verify_signature(sig, b"DATA")
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
