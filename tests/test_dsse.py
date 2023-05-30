"""Test cases for "metadata.py". """

import copy
import unittest

import securesystemslib.keys as KEYS
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import VerificationError
from securesystemslib.signer import Signature, SSlibKey, SSlibSigner


class TestEnvelope(unittest.TestCase):
    """Test metadata interface provided by DSSE envelope."""

    @classmethod
    def setUpClass(cls):
        cls.key_dicts = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
        ]

        cls.signature_dict = {
            "keyid": "11fa391a0ed7a447",
            "sig": "MEYCIQCTQuRWZSj87PanpQ==",
        }
        cls.envelope_dict = {
            "payload": "aGVsbG8gd29ybGQ=",
            "payloadType": "http://example.com/HelloWorld",
            "signatures": [cls.signature_dict],
        }
        cls.pae = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"

    def test_envelope_from_to_dict(self):
        """Test envelope to_dict and from_dict methods."""

        envelope_dict = copy.deepcopy(self.envelope_dict)

        # create envelope object from its dict.
        envelope_obj = Envelope.from_dict(envelope_dict)
        for signature in envelope_obj.signatures:
            self.assertIsInstance(signature, Signature)

        # Assert envelope dict created by to_dict will be equal.
        self.assertDictEqual(self.envelope_dict, envelope_obj.to_dict())

    def test_envelope_eq_(self):
        """Test envelope equality."""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Assert that object and None will not be equal.
        self.assertNotEqual(None, envelope_obj)

        # Assert a copy of envelope_obj will be equal to envelope_obj.
        envelope_obj_2 = copy.deepcopy(envelope_obj)
        self.assertEqual(envelope_obj, envelope_obj_2)

        # Assert that changing the "payload" will make the objects not equal.
        envelope_obj_2.payload = b"wrong_payload"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "payload_type" will make the objects not equal.
        envelope_obj_2.payload_type = "wrong_payload_type"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "signatures" will make the objects not equal.
        sig_obg = Signature("", self.signature_dict["sig"])
        envelope_obj_2.signatures = [sig_obg]
        self.assertNotEqual(envelope_obj, envelope_obj_2)

    def test_preauthencoding(self):
        """Test envelope Pre-Auth-Encoding."""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Checking for Pre-Auth-Encoding generated is correct.
        self.assertEqual(self.pae, envelope_obj.pae())

    def test_sign_and_verify(self):
        """Test for creating and verifying DSSE signatures."""

        # Create an Envelope with no signatures.
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        key_list = []
        for key_dict in self.key_dicts:
            # Test for invalid scheme.
            valid_scheme = key_dict["scheme"]
            key_dict["scheme"] = "invalid_scheme"
            with self.assertRaises(ValueError):
                signer = SSlibSigner(key_dict)

            # Sign the payload.
            key_dict["scheme"] = valid_scheme
            signer = SSlibSigner(key_dict)
            envelope_obj.sign(signer)

            # Create a List of "Key" from key_dict.
            key_list.append(SSlibKey.from_securesystemslib_key(key_dict))

        # Check for signatures of Envelope.
        self.assertEqual(len(self.key_dicts), len(envelope_obj.signatures))
        for signature in envelope_obj.signatures:
            self.assertIsInstance(signature, Signature)

        # Test for invalid threshold value for keys_list.
        # threshold is 0.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 0)

        # threshold is greater than no of keys.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 4)

        # Test with valid keylist and threshold.
        verified_keys = envelope_obj.verify(key_list, len(key_list))
        self.assertEqual(len(verified_keys), len(key_list))

        # Test for unknown keys and threshold of 1.
        new_key_dicts = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
        ]
        new_key_list = []
        for key_dict in new_key_dicts:
            new_key_list.append(SSlibKey.from_securesystemslib_key(key_dict))

        with self.assertRaises(VerificationError):
            envelope_obj.verify(new_key_list, 1)

        all_keys = key_list + new_key_list
        envelope_obj.verify(all_keys, 3)

        # Test with duplicate keys.
        duplicate_keys = key_list + key_list
        with self.assertRaises(VerificationError):
            envelope_obj.verify(
                duplicate_keys, 4
            )  # 3 unique keys, threshold 4.


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
