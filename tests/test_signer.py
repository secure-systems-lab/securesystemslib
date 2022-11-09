#!/usr/bin/env python

"""Test cases for "signer.py". """

import copy
import os
import shutil
import tempfile
import unittest

import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    CryptoError,
    FormatError,
    UnsupportedAlgorithmError,
    UnverifiedSignatureError,
)
from securesystemslib.gpg.constants import have_gpg
from securesystemslib.gpg.functions import export_pubkey
from securesystemslib.gpg.functions import verify_signature as verify_sig
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    SIGNER_FOR_URI_SCHEME,
    GPGKey,
    GPGSignature,
    GPGSigner,
    Key,
    Signature,
    Signer,
    SSlibKey,
    SSlibSigner,
)


class TestKey(unittest.TestCase):
    """Key tests. See many more tests in python-tuf test suite"""

    def test_key_from_to_dict(self):
        """Test to/from_dict for known keytype/scheme combos"""
        for (keytype, scheme), key_impl in KEY_FOR_TYPE_AND_SCHEME.items():
            keydict = {
                "keytype": keytype,
                "scheme": scheme,
                "extra": "somedata",
                "keyval": {
                    "public": "pubkeyval",
                    "foo": "bar",
                },
            }

            key = Key.from_dict("aa", copy.deepcopy(keydict))
            self.assertIsInstance(key, key_impl)
            self.assertDictEqual(keydict, key.to_dict())

        # test GPG as a special non-default case
        keydict = {
            "hashes": ["pgp+SHA2"],
            "keyid": "7b3abb26b97b655ab9296bd15b0bd02e1c768c43",
            "keyval": {
                "private": "",
                "public": {
                    "e": "010001",
                    "n": "e9ad391502ae32bd4fcc41a0f9970f8901ed6ad1c5c128c02add22721cdc22318b64bec9f9467b6949b19fc2e98ce41906125ad45d0b138f1ad6c5da7bde38092d9e3e697ce8b8373b150b57342dd921d634b873f258f5c15559b52921fa4bb7f482ec43a1c85c3385bd520cedbdc16b2524a64aecf32ac5690e6dd4ee0210a975e1b6c5af164ea69ca64533422432070511068730594793885567bb8f7cffacf6eb5ffdc640e898e599579b21b15e497f5c052112c5fdf7974e7056cd1564fe84f207cb946d1efc521e5031299e6275936e6f9464a735bd4edc8e0cde3fe5b1bf6d3bc1ed12993b865d8fcb9d9a2b2ef2df30cb7f0ab4c0dea819ea017ff195",
                },
            },
            "method": "pgp+rsa-pkcsv1.5",
            "type": "rsa",
        }

        # Add non-default keytype
        KEY_FOR_TYPE_AND_SCHEME[(None, None)] = GPGKey
        key = Key.from_dict(
            "7b3abb26b97b655ab9296bd15b0bd02e1c768c43", copy.deepcopy(keydict)
        )
        del KEY_FOR_TYPE_AND_SCHEME[(None, None)]

        self.assertIsInstance(key, GPGKey)
        self.assertDictEqual(keydict, key.to_dict())

    def test_key_verify_signature(self):
        sigdict = {
            "keyid": "e33221e745d40465d1efc0215d6db83e5fdb83ea16e1fb894d09d6d96c456f3b",
            "sig": "3fc91f5411a567d6a7f28b7fbb9ba6d60b1e2a1b64d8af0b119650015d86bb5a55e57c0e2c995a9b4a332b8f435703e934c0e6ce69fe6674a8ce68719394a40b",
        }
        keydict = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {
                "public": "8ae43d22b8e0fbf4a48fa3490d31b4d389114f5dc1039c918f075427f4100759",
            },
        }
        key = Key.from_dict(
            "e33221e745d40465d1efc0215d6db83e5fdb83ea16e1fb894d09d6d96c456f3b",
            keydict,
        )
        sig = Signature.from_dict(sigdict)

        key.verify_signature(sig, b"DATA")
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")


class TestSigner(unittest.TestCase):
    """Test Signer and SSlibSigner functionality"""

    @classmethod
    def setUpClass(cls):
        cls.keys = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
            KEYS.generate_sphincs_key(),
        ]
        cls.DATA = b"DATA"

        # pylint: disable=consider-using-with
        cls.testdir = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.testdir.cleanup()

    def test_signer_sign_with_envvar_uri(self):
        for key in self.keys:
            # setup
            pubkey = SSlibKey.from_securesystemslib_key(key)
            os.environ["PRIVKEY"] = key["keyval"]["private"]

            # test signing
            signer = Signer.from_priv_key_uri("envvar:PRIVKEY", pubkey)
            sig = signer.sign(self.DATA)

            pubkey.verify_signature(sig, self.DATA)
            with self.assertRaises(UnverifiedSignatureError):
                pubkey.verify_signature(sig, b"NOT DATA")

    def test_signer_sign_with_file_uri(self):
        for key in self.keys:
            # setup
            pubkey = SSlibKey.from_securesystemslib_key(key)
            # let teardownclass handle the file removal
            with tempfile.NamedTemporaryFile(
                dir=self.testdir.name, delete=False
            ) as f:
                f.write(key["keyval"]["private"].encode())

            # test signing
            signer = Signer.from_priv_key_uri(f"file:{f.name}", pubkey)
            sig = signer.sign(self.DATA)

            pubkey.verify_signature(sig, self.DATA)
            with self.assertRaises(UnverifiedSignatureError):
                pubkey.verify_signature(sig, b"NOT DATA")

    def test_signer_sign_with_enc_file_uri(self):
        for key in self.keys:
            # setup
            pubkey = SSlibKey.from_securesystemslib_key(key)
            privkey = KEYS.encrypt_key(key, "hunter2")
            # let teardownclass handle the file removal
            with tempfile.NamedTemporaryFile(
                dir=self.testdir.name, delete=False
            ) as f:
                f.write(privkey.encode())

            # test signing
            def secrets_handler(secret: str) -> str:
                return "hunter2" if secret == "passphrase" else "???"

            uri = f"encfile:{f.name}"

            signer = Signer.from_priv_key_uri(uri, pubkey, secrets_handler)
            sig = signer.sign(self.DATA)

            pubkey.verify_signature(sig, self.DATA)
            with self.assertRaises(UnverifiedSignatureError):
                pubkey.verify_signature(sig, b"NOT DATA")

            # test wrong passphrase
            def fake_handler(_) -> str:
                return "12345"

            with self.assertRaises(CryptoError):
                signer = Signer.from_priv_key_uri(uri, pubkey, fake_handler)

    def test_sslib_signer_sign(self):
        for scheme_dict in self.keys:
            # Test generation of signatures.
            sslib_signer = SSlibSigner(scheme_dict)
            sig_obj = sslib_signer.sign(self.DATA)

            # Verify signature
            verified = KEYS.verify_signature(
                scheme_dict, sig_obj.to_dict(), self.DATA
            )
            self.assertTrue(verified, "Incorrect signature.")

            # Removing private key from "scheme_dict".
            private = scheme_dict["keyval"]["private"]
            scheme_dict["keyval"]["private"] = ""
            sslib_signer.key_dict = scheme_dict

            with self.assertRaises((ValueError, FormatError)):
                sslib_signer.sign(self.DATA)

            scheme_dict["keyval"]["private"] = private

            # Test for invalid signature scheme.
            valid_scheme = scheme_dict["scheme"]
            scheme_dict["scheme"] = "invalid_scheme"
            sslib_signer = SSlibSigner(scheme_dict)

            with self.assertRaises((UnsupportedAlgorithmError, FormatError)):
                sslib_signer.sign(self.DATA)

            scheme_dict["scheme"] = valid_scheme

    def test_signature_from_to_dict(self):
        signature_dict = {
            "sig": "30460221009342e4566528fcecf6a7a5d53ebacdb1df151e242f55f8775883469cb01dbc6602210086b426cc826709acfa2c3f9214610cb0a832db94bbd266fd7c5939a48064a851",
            "keyid": "11fa391a0ed7a447cbfeb4b2667e286fc248f64d5e6d0eeed2e5e23f97f9f714",
            "foo": "bar",  # unrecognized_field
        }
        sig_obj = Signature.from_dict(copy.copy(signature_dict))

        # Verify that unrecognized fields are stored correctly.
        self.assertEqual(sig_obj.unrecognized_fields, {"foo": "bar"})

        self.assertDictEqual(signature_dict, sig_obj.to_dict())

    def test_signature_eq_(self):
        signature_dict = {
            "sig": "30460221009342e4566528fcecf6a7a5d53ebacdb1df151e242f55f8775883469cb01dbc6602210086b426cc826709acfa2c3f9214610cb0a832db94bbd266fd7c5939a48064a851",
            "keyid": "11fa391a0ed7a447cbfeb4b2667e286fc248f64d5e6d0eeed2e5e23f97f9f714",
        }
        sig_obj = Signature.from_dict(signature_dict)
        sig_obj_2 = copy.deepcopy(sig_obj)

        self.assertEqual(sig_obj, sig_obj_2)

        # Assert that changing the keyid will make the objects not equal.
        sig_obj_2.keyid = None
        self.assertNotEqual(sig_obj, sig_obj_2)
        sig_obj_2.keyid = sig_obj.keyid

        # Assert that changing the signature will make the objects not equal.
        sig_obj_2.signature = None
        self.assertNotEqual(sig_obj, sig_obj_2)

        # Assert that making sig_obj_2 None will make the objects not equal.
        sig_obj_2 = None
        self.assertNotEqual(sig_obj, sig_obj_2)


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestGPGRSA(unittest.TestCase):
    """Test RSA gpg signature creation and verification."""

    @classmethod
    def setUpClass(cls):
        cls.default_keyid = "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
        cls.signing_subkey_keyid = "C5A0ABE6EC19D0D65F85E2C39BE9DF5131D924E9"

        # Create directory to run the tests without having everything blow up.
        cls.working_dir = os.getcwd()
        cls.test_data = b"test_data"
        cls.wrong_data = b"something malicious"

        # Find demo files.
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa"
        )

        cls.test_dir = os.path.realpath(tempfile.mkdtemp())
        cls.gnupg_home = os.path.join(cls.test_dir, "rsa")
        shutil.copytree(gpg_keyring_path, cls.gnupg_home)
        os.chdir(cls.test_dir)

        # add signer that is by default not supported
        SIGNER_FOR_URI_SCHEME[GPGSigner.GPG_SCHEME] = GPGSigner

    @classmethod
    def tearDownClass(cls):
        """Change back to initial working dir and remove temp test directory."""

        del SIGNER_FOR_URI_SCHEME[GPGSigner.GPG_SCHEME]

        os.chdir(cls.working_dir)
        shutil.rmtree(cls.test_dir)

    def test_gpg_sign_and_verify_object_with_default_key(self):
        """Create a signature using the default key on the keyring."""

        signer = GPGSigner(homedir=self.gnupg_home)
        signature = signer.sign(self.test_data)

        signature_dict = signature.to_dict()
        key_data = export_pubkey(self.default_keyid, self.gnupg_home)

        self.assertTrue(verify_sig(signature_dict, key_data, self.test_data))
        self.assertFalse(verify_sig(signature_dict, key_data, self.wrong_data))

    def test_gpg_sign_and_verify_object(self):
        """Create a signature using a specific key on the keyring."""

        signer = GPGSigner(self.signing_subkey_keyid, self.gnupg_home)
        signature = signer.sign(self.test_data)

        signature_dict = signature.to_dict()
        key_data = export_pubkey(self.signing_subkey_keyid, self.gnupg_home)

        self.assertTrue(verify_sig(signature_dict, key_data, self.test_data))
        self.assertFalse(verify_sig(signature_dict, key_data, self.wrong_data))

    def test_gpg_serialization(self):
        """Tests from_dict and to_dict methods of GPGSignature."""

        sig_dict = {
            "keyid": "f4f90403af58eef6",
            "signature": "c39f86e70e12e70e11d87eb7e3ab7d3b",
            "other_headers": "d8f8a89b5d71f07b842a",
        }

        signature = GPGSignature.from_dict(sig_dict)
        self.assertEqual(sig_dict, signature.to_dict())

    def test_signer_dispatch_with_gpg_signer(self):

        key_data = export_pubkey(self.signing_subkey_keyid, self.gnupg_home)
        pubkey = GPGKey.from_dict(key_data["keyid"], key_data)

        signer = Signer.from_priv_key_uri(f"gpg:{self.gnupg_home}", pubkey)

        signature = signer.sign(self.test_data)
        signature_dict = signature.to_dict()

        self.assertTrue(verify_sig(signature_dict, key_data, self.test_data))
        self.assertFalse(verify_sig(signature_dict, key_data, self.wrong_data))


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
