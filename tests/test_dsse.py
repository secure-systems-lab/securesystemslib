"""Test cases for native DSSE envelopes and cross-language signing bytes."""

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import VerificationError
from securesystemslib.signer import CryptoSigner, Signature, SSlibKey

PEMS_DIR = Path(__file__).parent / "data" / "pems"
DSSE_VECTORS = Path(__file__).parent / "data" / "dsse" / "cross_lang_signing.json"
DSSE_VECTORS_SHA256 = "f5f6c8e991ecb452d73b6289eef8632666dbb50c7f1ef25827b28e869e16152c"
DSSE_VECTOR_COUNT = 11


class TestEnvelope(unittest.TestCase):
    """Test metadata interface provided by DSSE envelope."""

    @classmethod
    def setUpClass(cls):
        cls.signers: list[CryptoSigner] = []
        for keytype in ["rsa", "ecdsa", "ed25519"]:
            path = PEMS_DIR / f"{keytype}_private.pem"

            with open(path, "rb") as f:
                data = f.read()

            private_key = load_pem_private_key(data, None)
            signer = CryptoSigner(private_key)

            cls.signers.append(signer)

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

    def test_envelope_from_dict_with_duplicate_signatures(self):
        """Test envelope from_dict generates error with duplicate signature keyids"""
        envelope_dict = copy.deepcopy(self.envelope_dict)

        # add duplicate keyid.
        envelope_dict["signatures"].append(copy.deepcopy(self.signature_dict))

        # assert that calling from_dict will raise an error.
        expected_error_message = (
            f"Multiple signatures found for keyid {self.signature_dict['keyid']}"
        )
        with self.assertRaises(ValueError) as context:
            Envelope.from_dict(envelope_dict)

        self.assertEqual(str(context.exception), expected_error_message)

    def test_envelope_from_to_dict(self):
        """Test envelope to_dict and from_dict methods."""

        envelope_dict = copy.deepcopy(self.envelope_dict)

        # create envelope object from its dict.
        envelope_obj = Envelope.from_dict(envelope_dict)
        for signature in envelope_obj.signatures.values():
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

    def test_envelope_hash(self):
        """Envelopes should be hashable despite the signatures dict."""
        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))
        envelope_obj_2 = copy.deepcopy(envelope_obj)

        # Equal envelopes hash equally and collapse in a set.
        self.assertEqual(hash(envelope_obj), hash(envelope_obj_2))
        self.assertEqual(len({envelope_obj, envelope_obj_2}), 1)

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
        for signer in self.signers:
            envelope_obj.sign(signer)

            # Create a List of "Key" from key_dict.
            key_list.append(signer.public_key)

        # Check for signatures of Envelope.
        self.assertEqual(len(self.signers), len(envelope_obj.signatures))
        for signature in envelope_obj.signatures.values():
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
        new_key_list = []
        for key in key_list:
            new_key = copy.deepcopy(key)
            # if it has a different keyid, it is a different key in sslib
            new_key.keyid = reversed(key.keyid)
            new_key_list.append(new_key)

        with self.assertRaises(VerificationError):
            envelope_obj.verify(new_key_list, 1)

        all_keys = key_list + new_key_list
        envelope_obj.verify(all_keys, 3)

        # Test with duplicate keys.
        duplicate_keys = key_list + key_list
        with self.assertRaises(VerificationError):
            envelope_obj.verify(duplicate_keys, 4)  # 3 unique keys, threshold 4.


class TestCrossLanguageEnvelope(unittest.TestCase):
    """Replay pinned Go signing bytes through the native DSSE public APIs."""

    @classmethod
    def setUpClass(cls):
        raw = DSSE_VECTORS.read_bytes()
        if hashlib.sha256(raw).hexdigest() != DSSE_VECTORS_SHA256:
            raise ValueError("DSSE reference fixture digest does not match")
        cls.vectors = json.loads(raw)
        cls.fixtures = cls.vectors["fixtures"]
        cls.key_id = cls.vectors["key_id"]
        public_key = load_pem_public_key(cls.vectors["public_key_pem"].encode())
        cls.key = SSlibKey.from_crypto(public_key, keyid=cls.key_id)
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(cls.vectors["test_seed_hex"])
        )
        cls.signer = CryptoSigner(private_key, cls.key)

    def test_reference_pae_bytes(self):
        self.assertEqual(len(self.fixtures), DSSE_VECTOR_COUNT)
        for fixture in self.fixtures:
            with self.subTest(case=fixture["name"]):
                envelope = Envelope.from_dict(copy.deepcopy(fixture["envelope"]))
                self.assertEqual(envelope.pae(), base64.b64decode(fixture["pae_b64"]))

    def test_reference_signatures_verify(self):
        for fixture in self.fixtures:
            with self.subTest(case=fixture["name"]):
                envelope = Envelope.from_dict(copy.deepcopy(fixture["envelope"]))
                self.assertEqual(
                    envelope.verify([self.key], 1), {self.key_id: self.key}
                )

    def test_native_signer_reproduces_reference(self):
        for fixture in self.fixtures:
            with self.subTest(case=fixture["name"]):
                envelope = Envelope(
                    base64.b64decode(fixture["canonical_b64"]),
                    fixture["payload_type"],
                    {},
                )
                signature = envelope.sign(self.signer)
                self.assertEqual(
                    bytes.fromhex(signature.signature),
                    base64.b64decode(fixture["signature_b64"]),
                )
                self.assertEqual(envelope.to_dict(), fixture["envelope"])
                self.assertEqual(
                    envelope.verify([self.key], 1), {self.key_id: self.key}
                )

    def test_changed_payload_refused(self):
        for fixture in self.fixtures:
            with self.subTest(case=fixture["name"]):
                envelope = Envelope.from_dict(copy.deepcopy(fixture["envelope"]))
                envelope.payload += b"\x00"
                with self.assertRaises(VerificationError):
                    envelope.verify([self.key], 1)

    def test_changed_payload_type_refused(self):
        for fixture in self.fixtures:
            with self.subTest(case=fixture["name"]):
                envelope = Envelope.from_dict(copy.deepcopy(fixture["envelope"]))
                envelope.payload_type += "\u00e9"
                with self.assertRaises(VerificationError):
                    envelope.verify([self.key], 1)

    def test_changed_signature_refused(self):
        for fixture in self.fixtures:
            with self.subTest(case=fixture["name"]):
                envelope = Envelope.from_dict(copy.deepcopy(fixture["envelope"]))
                signature = bytearray(base64.b64decode(fixture["signature_b64"]))
                signature[0] ^= 1
                envelope.signatures[self.key_id] = Signature(
                    self.key_id, signature.hex()
                )
                with self.assertRaises(VerificationError):
                    envelope.verify([self.key], 1)

    def test_wrong_key_with_same_keyid_refused(self):
        wrong_private_key = Ed25519PrivateKey.from_private_bytes(bytes(32))
        wrong_key = SSlibKey.from_crypto(
            wrong_private_key.public_key(), keyid=self.key_id
        )
        for fixture in self.fixtures:
            with self.subTest(case=fixture["name"]):
                envelope = Envelope.from_dict(copy.deepcopy(fixture["envelope"]))
                with self.assertRaises(VerificationError):
                    envelope.verify([wrong_key], 1)

    def test_character_length_preimage_refused(self):
        fixture = next(
            item for item in self.fixtures if item["name"] == "unicode_payload_type"
        )
        envelope = Envelope.from_dict(copy.deepcopy(fixture["envelope"]))
        character_length_pae = b"DSSEv1 %d %b %d %b" % (
            len(envelope.payload_type),
            envelope.payload_type.encode("utf-8"),
            len(envelope.payload),
            envelope.payload,
        )
        self.assertNotEqual(character_length_pae, base64.b64decode(fixture["pae_b64"]))
        envelope.signatures[self.key_id] = self.signer.sign(character_length_pae)
        with self.assertRaises(VerificationError):
            envelope.verify([self.key], 1)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
