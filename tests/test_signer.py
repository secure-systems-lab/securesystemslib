#!/usr/bin/env python

"""Test cases for "signer.py". """

import sys
import unittest

import unittest
import securesystemslib.formats
import securesystemslib.keys as KEYS
from securesystemslib.exceptions import FormatError, UnsupportedAlgorithmError

# TODO: Remove case handling when fully dropping support for versions < 3.6
IS_PY_VERSION_SUPPORTED = sys.version_info >= (3, 6)

# Use setUpModule to tell unittest runner to skip this test module gracefully.
def setUpModule():
    if not IS_PY_VERSION_SUPPORTED:
        raise unittest.SkipTest("requires Python 3.6 or higher")

# Since setUpModule is called after imports we need to import conditionally.
if IS_PY_VERSION_SUPPORTED:
    from securesystemslib.signer import Signature, SSlibSigner


class TestSSlibSigner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsakey_dict = KEYS.generate_rsa_key()
        cls.ed25519key_dict = KEYS.generate_ed25519_key()
        cls.ecdsakey_dict = KEYS.generate_ecdsa_key()
        cls.DATA_STR = "SOME DATA REQUIRING AUTHENTICITY."
        cls.DATA = securesystemslib.formats.encode_canonical(
                cls.DATA_STR).encode("utf-8")


    def test_sslib_sign(self):
        dicts = [self.rsakey_dict, self.ecdsakey_dict, self.ed25519key_dict]
        for scheme_dict in dicts:
            # Test generation of signatures.
            sslib_signer = SSlibSigner(scheme_dict)
            sig_obj = sslib_signer.sign(self.DATA)

            # Verify signature
            verified = KEYS.verify_signature(scheme_dict, sig_obj.to_dict(),
                    self.DATA)
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
            "keyid": "11fa391a0ed7a447cbfeb4b2667e286fc248f64d5e6d0eeed2e5e23f97f9f714"
        }
        sig_obj = Signature.from_dict(signature_dict)

        self.assertDictEqual(signature_dict, sig_obj.to_dict())


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
