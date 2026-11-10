"""Test cases for "signer.py"."""

import copy
import json
import os
import shutil
import tempfile
import unittest
import warnings
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from securesystemslib._gpg.constants import have_gpg
from securesystemslib.exceptions import (
    FormatError,
    KeyMismatchError,
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    SIGNER_FOR_URI_SCHEME,
    CryptoSigner,
    GPGKey,
    GPGSigner,
    Key,
    SecretsHandler,
    Signature,
    Signer,
    SSlibKey,
)
from securesystemslib.signer._key import MLDSA_IMPORT_ERROR
from securesystemslib.signer._utils import compute_default_keyid

DATA_DIR = Path(__file__).parent / "data"
PEMS_DIR = DATA_DIR / "pems"
SHA224_SCHEMES = ("rsassa-pss-sha224", "rsa-pkcs1v15-sha224")


class TestKey(unittest.TestCase):
    """Key tests. See many more tests in python-tuf test suite"""

    def test_key_from_to_dict(self):
        """Test to/from_dict for known keytype/scheme combos"""
        for (keytype, scheme), key_impl in KEY_FOR_TYPE_AND_SCHEME.items():
            keydict = {
                "keytype": keytype,
                "scheme": scheme,
                "extra": "somedata",
                "hashes": ["only recognized by GPGKey"],
                "keyval": {
                    "public": "pubkeyval",
                    "foo": "bar",
                },
            }

            key = Key.from_dict("aa", copy.deepcopy(keydict))
            self.assertIsInstance(key, key_impl)
            self.assertDictEqual(keydict, key.to_dict())

    def test_key_hash(self):
        """Keys should be hashable, even with dict keyval and extra fields."""
        keydict = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "extra": "somedata",
            "keyval": {"public": "pubkeyval", "foo": "bar"},
        }
        key = Key.from_dict("aa", copy.deepcopy(keydict))
        key_2 = Key.from_dict("aa", copy.deepcopy(keydict))

        # Equal keys hash equally and collapse in a set.
        self.assertEqual(hash(key), hash(key_2))
        self.assertEqual(len({key, key_2}), 1)

    def test_sslib_key_from_dict_invalid(self):
        """Test from_dict for invalid data"""
        invalid_dicts = [
            {"scheme": "ed25519", "keyval": {"public": "abc"}},
            {"keytype": "ed25519", "keyval": {"public": "abc"}},
            {"keytype": "ed25519", "scheme": "ed25519"},
            {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"x": "y"}},
            {
                "keytype": "ed25519",
                "scheme": "ed25519",
                "keyval": {"public": b"abc"},
            },
        ]
        for keydict in invalid_dicts:
            with self.assertRaises((KeyError, ValueError)):
                Key.from_dict("aa", keydict)

    def test_sha224_schemes_require_explicit_registration(self):
        """SHA-224 keys require callers to opt into the registry."""
        for scheme in SHA224_SCHEMES:
            key_type_scheme = ("rsa", scheme)
            key_dict = {
                "keytype": "rsa",
                "scheme": scheme,
                "keyval": {"public": "pubkeyval"},
            }

            self.assertNotIn(key_type_scheme, KEY_FOR_TYPE_AND_SCHEME)
            with self.assertRaisesRegex(
                ValueError, f"Unsupported public key rsa/{scheme}"
            ):
                Key.from_dict("aa", copy.deepcopy(key_dict))

            try:
                KEY_FOR_TYPE_AND_SCHEME[key_type_scheme] = SSlibKey
                key = Key.from_dict("aa", copy.deepcopy(key_dict))
                self.assertIsInstance(key, SSlibKey)
                self.assertDictEqual(key_dict, key.to_dict())
            finally:
                KEY_FOR_TYPE_AND_SCHEME.pop(key_type_scheme, None)

    def test_key_verify_signature(self):
        """Verify known signatures for all supported keytype/scheme combos.

        Signature fixtures are stored outside the sources, in
        tests/data/key_verify_signature.json. Public keys are either
        embedded in the fixture or referenced from tests/data/pems/.
        """
        vectors = json.loads((DATA_DIR / "key_verify_signature.json").read_text())
        for vector in vectors:
            with self.subTest(keytype=vector["keytype"], scheme=vector["scheme"]):
                if vector.get("requires_mldsa") and MLDSA_IMPORT_ERROR is not None:
                    self.skipTest(MLDSA_IMPORT_ERROR)

                public = vector.get("public")
                if public is None:
                    public = (PEMS_DIR / vector["public_file"]).read_text()

                key_dict = {
                    "keytype": vector["keytype"],
                    "scheme": vector["scheme"],
                    "keyval": {
                        "public": public,
                    },
                }
                if vector["scheme"] in SHA224_SCHEMES:
                    key = SSlibKey.from_dict(vector["keyid"], key_dict)
                else:
                    key = Key.from_dict(vector["keyid"], key_dict)

                sig = Signature.from_dict(
                    {
                        "keyid": vector["keyid"],
                        "sig": vector["signature"],
                    }
                )

                key.verify_signature(sig, b"DATA")
                with self.assertRaises(UnverifiedSignatureError, msg=vector["scheme"]):
                    key.verify_signature(sig, b"NOT DATA")

    def test_verify_signature_legacy_ecdsa_keytype_deprecated(self):
        """Legacy ecdsa keytypes (keytype == scheme) verify but warn (#363)."""
        keyid = "985171ff9ee901fbab17aa6f57347933aeae9d194f0f93e83e5c3dbc1755e754"
        pub = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsYJfSlYU3UlYbGOZfE/yOHkayWWq\nLPR/NeCa83szZmnJGc9wwCRPvJS87K+eDGIhhhKueTyrLqXQqmyHioQbOQ==\n-----END PUBLIC KEY-----\n"
        sig = Signature.from_dict(
            {
                "keyid": keyid,
                "sig": "304502207d0058b745b2259501204c2ba287ba3769ec2420e12463a325c59670c24df9b6022100836ca63a1b870f755c1596711a003a505e72e25cb0970e823a331e044adc63ec",
            }
        )

        # Creating a key with the legacy keytype still works
        legacy_key = Key.from_dict(
            keyid,
            {
                "keytype": "ecdsa-sha2-nistp256",
                "scheme": "ecdsa-sha2-nistp256",
                "keyval": {"public": pub},
            },
        )

        # Verifying with the legacy keytype emits a DeprecationWarning
        with self.assertWarns(DeprecationWarning):
            legacy_key.verify_signature(sig, b"DATA")

        # The correct "ecdsa" keytype verifies without a DeprecationWarning
        key = Key.from_dict(
            keyid,
            {
                "keytype": "ecdsa",
                "scheme": "ecdsa-sha2-nistp256",
                "keyval": {"public": pub},
            },
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            key.verify_signature(sig, b"DATA")
        self.assertEqual(
            [w for w in caught if issubclass(w.category, DeprecationWarning)],
            [],
        )

    def test_unsupported_key(self):
        keydict = {
            "keytype": "custom",
            "scheme": "ed25519",
            "keyval": {
                "public": "8ae43d22b8e0fbf4a48fa3490d31b4d389114f5dc1039c918f075427f4100759",
            },
        }
        with self.assertRaises(ValueError):
            Key.from_dict(
                "e33221e745d40465d1efc0215d6db83e5fdb83ea16e1fb894d09d6d96c456f3b",
                keydict,
            )

    def test_custom_key(self):
        class CustomKey(SSlibKey):
            """Fake keytype that actually uses ed25519 under the hood"""

            @classmethod
            def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> "CustomKey":
                assert key_dict.pop("keytype") == "custom"
                keytype = "ed25519"
                scheme = key_dict.pop("scheme")
                keyval = key_dict.pop("keyval")
                return cls(keyid, keytype, scheme, keyval, key_dict)

            def to_dict(self) -> dict[str, Any]:
                return {
                    "keytype": "custom",
                    "scheme": self.scheme,
                    "keyval": self.keyval,
                    **self.unrecognized_fields,
                }

        # register custom key type
        KEY_FOR_TYPE_AND_SCHEME[("custom", "ed25519")] = CustomKey

        # setup
        sig = Signature.from_dict(
            {
                "keyid": "e33221e745d40465d1efc0215d6db83e5fdb83ea16e1fb894d09d6d96c456f3b",
                "sig": "3fc91f5411a567d6a7f28b7fbb9ba6d60b1e2a1b64d8af0b119650015d86bb5a55e57c0e2c995a9b4a332b8f435703e934c0e6ce69fe6674a8ce68719394a40b",
            }
        )

        keydict = {
            "keytype": "custom",
            "scheme": "ed25519",
            "keyval": {
                "public": "8ae43d22b8e0fbf4a48fa3490d31b4d389114f5dc1039c918f075427f4100759",
            },
        }
        key = Key.from_dict(
            "e33221e745d40465d1efc0215d6db83e5fdb83ea16e1fb894d09d6d96c456f3b",
            keydict,
        )

        # test that CustomKey is used and that it works
        self.assertIsInstance(key, CustomKey)
        key.verify_signature(sig, b"DATA")
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")

        del KEY_FOR_TYPE_AND_SCHEME[("custom", "ed25519")]


class TestSSlibKey(unittest.TestCase):
    """SSlibKey tests."""

    def test_from_crypto(self):
        """Test load pyca/cryptography public key for each SSlibKey keytype"""
        test_data = [
            (
                "rsa",
                "rsassa-pss-sha256",
                "2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241",
                "rsa_public.pem",
            ),
            (
                "ecdsa",
                "ecdsa-sha2-nistp256",
                "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
                "ecdsa_public.pem",
            ),
            (
                "ecdsa",
                "ecdsa-sha2-nistp384",
                "0155661bdf705f621a74f55eef36c9ae041e456141eced7a45d4a1f75ded9ac0",
                "ecdsa_secp384r1_public.pem",
            ),
            (
                "ecdsa",
                "ecdsa-sha2-nistp521",
                "3dddef3c311b151c5fe12f5fcfa3d9795e2b5fe1a6746c2691befacb13a6af4a",
                "ecdsa_secp521r1_public.pem",
            ),
            (
                "ed25519",
                "ed25519",
                "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
                "ed25519_public.pem",
            ),
        ]
        if MLDSA_IMPORT_ERROR is None:
            test_data.append(
                (
                    "ml-dsa",
                    "ml-dsa-65/1",
                    "aebf451cd50cf521b4b5accfc70e679ea8d5c18644fb87582e022fbb9c4bb3c4",
                    "mldsa65_public.pem",
                )
            )

        def _from_file(path):
            with open(path, "rb") as f:
                pem = f.read()

            crypto_key = load_pem_public_key(pem)
            return crypto_key

        for keytype, default_scheme, default_keyid, fname in test_data:
            crypto_key = _from_file(PEMS_DIR / fname)
            key = SSlibKey.from_crypto(crypto_key)
            self.assertEqual(key.keytype, keytype)
            self.assertEqual(key.scheme, default_scheme)
            self.assertEqual(key.keyid, default_keyid)
            self.assertEqual(key._crypto_key(), crypto_key)

        # Test with non-default scheme/keyid
        crypto_key = _from_file(PEMS_DIR / "rsa_public.pem")
        key = SSlibKey.from_crypto(
            crypto_key,
            scheme="rsa-pkcs1v15-sha224",
            keyid="abcdef",
        )
        self.assertEqual(key.scheme, "rsa-pkcs1v15-sha224")
        self.assertEqual(key.keyid, "abcdef")

    def test_verify_invalid_keytype_scheme(self):
        rsa = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsDqUoiFJZX+5gm5pyI1l\nVc/N3yjJVOIl9GyiK0mRyzV3IzUQzhjq8nhk0eLfzXw2XwIAYOJC6dR/tGRG4JDx\nJkez5FFH4zLosr/XzT7CG5zxJ3kKICLD1v9rZQr5ZgARQDOpkxzPz46rGnE0sHd7\nMpnpPMScA1pMIzwM1RoPS4ntZipI1cl9M7HMQ6mkBp8/DNKCqaDWixJqaGgWrhhK\nhI/1mzBliMKriNxPKSCGVlOk/QpZft+y1fs42s0DMd5BOFBo+ZcoXLYRncg9S3A2\nxx/jT69Bt3ceiAZqnp7f6M+ZzoUifSelaoL7QIYg/GkEl+0oxTD0yRphGiCKwn9c\npSbn7NgnbjqSgIMeEtlf/5Coyrs26pyFf/9GbusddPSxxxwIJ/7IJuF7P1Yy0WpZ\nkMeY83h9n2IdnEYi+rpdbLJPQd7Fpu2xrdA3Fokj8AvCpcmxn8NIXZuK++r8/xsE\nAUL30HH7dgVn50AvdPaJnqAORT3OlabW0DK9prcwKnyzAgMBAAE=\n-----END PUBLIC KEY-----"
        ed25519 = "50a5768a7a577483c28e57a6742b4d2170b9be628a961355ef127c45f2aefdc5"
        ecdsa_nistp256 = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsYJfSlYU3UlYbGOZfE/yOHkayWWq\nLPR/NeCa83szZmnJGc9wwCRPvJS87K+eDGIhhhKueTyrLqXQqmyHioQbOQ==\n-----END PUBLIC KEY-----\n"
        ecdsa_nistp384 = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEksAG80nLUksODTEUBTPJJPYN0bfxhkrr\n2hlyokfRG4kDYsRRN86vWwxDTW7qhWNZPFhJMJxHmvHsCbLz/IF7hdo8Xv/vRO4M\nVHbwq0fiWznUvkZowHC5fH2EEvNF1R5t\n-----END PUBLIC KEY-----\n"
        ecdsa_nistp521 = "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBXxFGyw9J9C43woa6huZ3IwrEZhku\neHDNZ1UqnHcFhNYFhM7witKxgv6OUpwlwPsPSUjqcBxkkpay4rT4UTwIP94AdsQL\nq3DQ+BuwrEELjAAMxvQGfoMlLJ5fHM4p4KhlKwpk2HiBQp4r1bjuA6MFq7s5yF0C\nnb9TH+ZZwV5/cjCewxY=\n-----END PUBLIC KEY-----"
        mldsa65 = (PEMS_DIR / "mldsa65_public.pem").read_text()

        test_data = [
            # bad keytype / scheme
            ("ed25519", "rsassa-pss-sha256", rsa),
            ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", ecdsa_nistp256),
            ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", ecdsa_nistp384),
            ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521", ecdsa_nistp521),
            ("rsa", "ed25519", ed25519),
            # bad key type (pem formatted keys only)
            ("rsa", "rsassa-pss-sha256", ecdsa_nistp256),
            ("ecdsa", "ecdsa-sha2-nistp256", rsa),
            # bad curve (ecdsa keys only)
            ("ecdsa", "ecdsa-sha2-nistp256", ecdsa_nistp384),
            ("ecdsa", "ecdsa-sha2-nistp384", ecdsa_nistp256),
            ("ecdsa", "ecdsa-sha2-nistp521", ecdsa_nistp256),
        ]
        if MLDSA_IMPORT_ERROR is None:
            test_data.extend(
                [
                    ("ml-dsa", "ed25519", mldsa65),
                    ("ml-dsa", "ml-dsa-65/1", ecdsa_nistp256),
                    ("ml-dsa", "ml-dsa-44/1", mldsa65),
                ]
            )

        for keytype, scheme, val in test_data:
            key = SSlibKey("fake", keytype, scheme, {"public": val})
            with self.assertRaises(ValueError):
                key._verify(b"fakesig", b"fakedata")


class TestSigner(unittest.TestCase):
    """Test Signer and SSlibSigner functionality"""

    def test_signer_sign_with_incorrect_uri(self):
        pubkey = "fake key"
        with self.assertRaises(ValueError) as ctx:
            Signer.from_priv_key_uri("unknownscheme:x", pubkey)

        self.assertEqual(
            "Unsupported private key scheme unknownscheme", str(ctx.exception)
        )

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

    def test_signature_hash(self):
        """Signatures should be hashable, even with unrecognized fields."""
        signature_dict = {
            "sig": "30460221009342e4566528fcecf6a7a5d53ebacdb1df151e242f55f8775883469cb01dbc6602210086b426cc826709acfa2c3f9214610cb0a832db94bbd266fd7c5939a48064a851",
            "keyid": "11fa391a0ed7a447cbfeb4b2667e286fc248f64d5e6d0eeed2e5e23f97f9f714",
            "extra": "unrecognized",
        }
        sig_obj = Signature.from_dict(copy.deepcopy(signature_dict))
        sig_obj_2 = Signature.from_dict(copy.deepcopy(signature_dict))

        # Equal signatures hash equally and collapse in a set.
        self.assertEqual(hash(sig_obj), hash(sig_obj_2))
        self.assertEqual(len({sig_obj, sig_obj_2}), 1)

    def test_signature_hash_equal_for_equal_field_values(self):
        """Values that compare equal must hash equally.

        Python treats 1, 1.0 and True as equal, so unrecognized fields that
        differ only in those types make two equal Signatures, which have to
        share a hash.
        """
        for first, second in [
            ({"extra": 1}, {"extra": True}),
            ({"extra": 1}, {"extra": 1.0}),
            ({"extra": [{"nested": 1}]}, {"extra": [{"nested": True}]}),
        ]:
            with self.subTest(first=first, second=second):
                sig = Signature("aa", "bb", first)
                sig_2 = Signature("aa", "bb", second)

                self.assertEqual(sig, sig_2)
                self.assertEqual(hash(sig), hash(sig_2))

    def test_signature_hash_non_json_field_value(self):
        """Unrecognized field values need not be JSON types."""
        sig = Signature("aa", "bb", {"extra": b"binary"})

        self.assertIsInstance(hash(sig), int)


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestGPGRSA(unittest.TestCase):
    """Test RSA gpg signature creation and verification."""

    @classmethod
    def setUpClass(cls):
        cls.default_keyid = "8465a1e2e0fb2b40adb2478e18fb3f537e0c8a17"
        cls.signing_subkey_keyid = "c5a0abe6ec19d0d65f85e2c39be9df5131d924e9"

        # Create directory to run the tests without having everything blow up.
        cls.working_dir = os.getcwd()
        cls.test_data = b"test_data"
        cls.wrong_data = b"something malicious"

        # Find demo files.
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa"
        )

        cls.test_dir = os.path.realpath(tempfile.mkdtemp())
        cls.gnupg_home = "rsa"
        shutil.copytree(gpg_keyring_path, os.path.join(cls.test_dir, cls.gnupg_home))
        os.chdir(cls.test_dir)

    @classmethod
    def tearDownClass(cls):
        """Change back to initial working dir and remove temp test directory."""

        os.chdir(cls.working_dir)
        shutil.rmtree(cls.test_dir)

    def test_gpg_sign_and_verify_object(self):
        """Create a signature using a specific key on the keyring."""

        uri, public_key = GPGSigner.import_(self.signing_subkey_keyid, self.gnupg_home)

        signer = Signer.from_priv_key_uri(uri, public_key)
        sig = signer.sign(self.test_data)

        public_key.verify_signature(sig, self.test_data)

        with self.assertRaises(UnverifiedSignatureError):
            public_key.verify_signature(sig, self.wrong_data)

    def test_gpg_fail_sign_keyid_match(self):
        """Fail signing because signature keyid does not match public key."""
        uri, public_key = GPGSigner.import_(self.default_keyid, self.gnupg_home)
        signer = Signer.from_priv_key_uri(uri, public_key)

        # Fail because we imported main key, but gpg favors signing subkey
        with self.assertRaises(ValueError):
            signer.sign(self.test_data)

    def test_gpg_fail_import_keyid_match(self):
        """Fail key import because passed keyid does not match returned key."""

        # gpg exports the right key, but we require an exact keyid match
        non_matching_keyid = self.default_keyid.upper()
        with self.assertRaises(ValueError):
            GPGSigner.import_(non_matching_keyid, self.gnupg_home)

    def test_gpg_fail_sign_expired_key(self):
        """Signing fails with non-zero exit code if key is expired."""
        expired_key = "e8ac80c924116dabb51d4b987cb07d6d2c199c7c"

        uri, public_key = GPGSigner.import_(expired_key, self.gnupg_home)
        signer = Signer.from_priv_key_uri(uri, public_key)
        with self.assertRaises(OSError):
            signer.sign(self.test_data)

    def test_gpg_signer_load_with_bad_scheme(self):
        """Load from priv key uri with wrong uri scheme."""
        key = GPGKey("aa", "rsa", "pgp+rsa-pkcsv1.5", {"public": "val"})
        with self.assertRaises(ValueError):
            GPGSigner.from_priv_key_uri("wrong:", key)

    def test_gpg_signer_load_with_bad_key(self):
        """Load from priv key uri with wrong pubkey type."""
        key = SSlibKey("aa", "rsa", "rsassa-pss-sha256", {"public": "val"})
        with self.assertRaises(ValueError):
            GPGSigner.from_priv_key_uri("gnupg:", key)

    def test_gpg_signature_legacy_data_structure(self):
        """Test custom fields and legacy data structure in gpg signatures."""
        _, public_key = GPGSigner.import_(self.signing_subkey_keyid, self.gnupg_home)
        signer = GPGSigner(public_key, homedir=self.gnupg_home)
        sig = signer.sign(self.test_data)
        self.assertIn("other_headers", sig.unrecognized_fields)

        sig_dict = GPGSigner._sig_to_legacy_dict(sig)
        self.assertIn("signature", sig_dict)
        self.assertNotIn("sig", sig_dict)
        sig2 = GPGSigner._sig_from_legacy_dict(sig_dict)
        self.assertEqual(sig, sig2)

    def test_gpg_key_legacy_data_structure(self):
        """Test legacy data structure conversion in gpg keys."""
        _, public_key = GPGSigner.import_(self.signing_subkey_keyid, self.gnupg_home)
        legacy_fields = {"keyid", "type", "method"}
        fields = {"keytype", "scheme"}

        legacy_dict = GPGSigner._key_to_legacy_dict(public_key)
        for field in legacy_fields:
            self.assertIn(field, legacy_dict)

        for field in fields:
            self.assertNotIn(field, legacy_dict)

        self.assertEqual(public_key, GPGSigner._key_from_legacy_dict(legacy_dict))

    def test_gpg_key__eq__(self):
        """Test GPGKey.__eq__() ."""
        key1 = GPGKey("aa", "rsa", "pgp+rsa-pkcsv1.5", {"public": "val"})
        key2 = copy.deepcopy(key1)
        self.assertEqual(key1, key2)

        key2.keyid = "bb"
        self.assertNotEqual(key1, key2)

        other_key = SSlibKey("aa", "rsa", "rsassa-pss-sha256", {"public": "val"})
        self.assertNotEqual(key1, other_key)


class TestUtils(unittest.TestCase):
    """Test utility methods."""

    def test_compute_default_keyid(self):
        self.assertEqual(
            compute_default_keyid("rsa", "rsassa-pss-sha256", {"public": "abcd"}),
            "7b56b88ae790729d4e359d3fc5e889f1e0669a2e71a12d00e87473870c73fbcf",
        )

        # Unsupported keys can have default keyids too
        self.assertEqual(
            compute_default_keyid("foo", "bar", {"baz": "qux"}),
            "e3471be0598305190ba82f6f8043f4df52f3fbe471fdc187223bd9ade92abebb",
        )

        # Invalid keys cannot
        with self.assertRaises(FormatError):
            compute_default_keyid("foo", "bar", {"baz": 1.1})


class TestCryptoSigner(unittest.TestCase):
    """CryptoSigner tests"""

    @classmethod
    def setUpClass(cls):
        cls.keys = {}
        cls.schemes = {}
        cls.expected_keytypes = {}

        key_info = [
            (
                "rsa",
                "rsa",
                [
                    "rsassa-pss-sha224",
                    "rsassa-pss-sha256",
                    "rsassa-pss-sha384",
                    "rsassa-pss-sha512",
                    "rsa-pkcs1v15-sha224",
                    "rsa-pkcs1v15-sha256",
                    "rsa-pkcs1v15-sha384",
                    "rsa-pkcs1v15-sha512",
                ],
            ),
            ("ecdsa", "ecdsa", ["ecdsa-sha2-nistp256"]),
            ("ecdsa_secp384r1", "ecdsa", ["ecdsa-sha2-nistp384"]),
            ("ecdsa_secp521r1", "ecdsa", ["ecdsa-sha2-nistp521"]),
            ("ed25519", "ed25519", ["ed25519"]),
        ]
        if MLDSA_IMPORT_ERROR is None:
            key_info.extend(
                [
                    ("mldsa44", "ml-dsa", ["ml-dsa-44/1"]),
                    ("mldsa65", "ml-dsa", ["ml-dsa-65/1"]),
                    ("mldsa87", "ml-dsa", ["ml-dsa-87/1"]),
                ]
            )

        for name, keytype, schemes in key_info:
            path = PEMS_DIR / f"{name}_private.pem"

            with open(path, "rb") as f:
                data = f.read()

            private_key = load_pem_private_key(data, None)

            cls.keys[name] = private_key
            cls.expected_keytypes[name] = keytype
            cls.schemes[name] = schemes

    def test_init(self):
        """Test CryptoSigner constructor."""
        for name, private_key in self.keys.items():
            keytype = self.expected_keytypes[name]
            # Init w/o public key (public key is created from private key)
            signer = CryptoSigner(private_key)
            self.assertEqual(keytype, signer.public_key.keytype)

            # Re-init with passed public key
            signer2 = CryptoSigner(private_key, signer.public_key)
            self.assertEqual(keytype, signer2.public_key.keytype)

    def test_init_key_mismatch(self):
        """Test that private and public keys must belong to the same key pair."""
        generators = [
            CryptoSigner.generate_rsa,
            CryptoSigner.generate_ecdsa,
            CryptoSigner.generate_ed25519,
        ]
        if MLDSA_IMPORT_ERROR is None:
            generators.append(CryptoSigner.generate_mldsa)

        for generate in generators:
            with self.subTest(generator=generate.__name__):
                signer = generate()
                other_signer = generate()
                with self.assertRaisesRegex(
                    KeyMismatchError,
                    "CryptoSigner private key does not match public key",
                ):
                    CryptoSigner(signer._private_key, other_signer.public_key)

    def test_init_pem_formatting_variations(self):
        """Test that CryptoSigner accepts public keys with PEM formatting variations."""
        names = ["rsa", "ecdsa", "ed25519"]
        if MLDSA_IMPORT_ERROR is None:
            names.append("mldsa65")

        for name in names:
            with self.subTest(key=name):
                private_key = self.keys[name]
                signer = CryptoSigner(private_key)
                pem = signer.public_key.keyval["public"]

                # Test without trailing newline
                pubkey_no_newline = copy.deepcopy(signer.public_key)
                pubkey_no_newline.keyval["public"] = pem.rstrip("\n")
                CryptoSigner(private_key, pubkey_no_newline)

                # Test with CRLF line endings
                pubkey_crlf = copy.deepcopy(signer.public_key)
                pubkey_crlf.keyval["public"] = pem.replace("\n", "\r\n")
                CryptoSigner(private_key, pubkey_crlf)

                # Test with extra surrounding whitespace
                pubkey_whitespace = copy.deepcopy(signer.public_key)
                pubkey_whitespace.keyval["public"] = f"  \n{pem}\n\n"
                CryptoSigner(private_key, pubkey_whitespace)

    def test_sign(self):
        for name, private_key in self.keys.items():
            public_key = SSlibKey.from_crypto(private_key.public_key())
            for scheme in self.schemes[name]:
                public_key.scheme = scheme
                signer = CryptoSigner(private_key, public_key)
                sig = signer.sign(b"DATA")
                self.assertIsNone(signer.public_key.verify_signature(sig, b"DATA"))
                with self.assertRaises(UnverifiedSignatureError):
                    signer.public_key.verify_signature(sig, b"NOT DATA")

    def test_from_priv_key_uri(self):
        """Test load and use PEM/PKCS#8 files for each sslib keytype"""
        test_data = [
            ("rsa_public.pem", "rsa_private.pem", None),
            ("ecdsa_public.pem", "ecdsa_private.pem", None),
            (
                "ecdsa_public.pem",
                "ecdsa_private.pem",
                "ecdsa-sha2-nistp256",  # keytype deprecated in TUF spec, tested for backwards compat with older metadata
            ),
            ("ed25519_public.pem", "ed25519_private.pem", None),
        ]
        if MLDSA_IMPORT_ERROR is None:
            test_data.append(("mldsa65_public.pem", "mldsa65_private.pem", None))

        for pub_fname, priv_fname, keytype_override in test_data:
            pub_crypto_key = load_pem_public_key((PEMS_DIR / pub_fname).read_bytes())
            public_key = SSlibKey.from_crypto(pub_crypto_key)
            if keytype_override:
                public_key.keytype = keytype_override

            for use_prefix in [True, False]:
                if use_prefix:
                    # uri path is relative from CRYPTO_SIGNER_PATH_PREFIX
                    os.environ["CRYPTO_SIGNER_PATH_PREFIX"] = str(PEMS_DIR)
                    uri = f"file2:{priv_fname}"
                else:
                    with suppress(KeyError):
                        del os.environ["CRYPTO_SIGNER_PATH_PREFIX"]
                    uri = f"file2:{PEMS_DIR / priv_fname}"

                signer = Signer.from_priv_key_uri(uri, public_key)
                self.assertIsInstance(signer, CryptoSigner)

                sig = signer.sign(b"DATA")
                self.assertIsNone(signer.public_key.verify_signature(sig, b"DATA"))
                with self.assertRaises(UnverifiedSignatureError):
                    signer.public_key.verify_signature(sig, b"NOT DATA")

        with self.assertRaises(OSError):
            # file not found
            uri = "file2:nonexistentfile"
            Signer.from_priv_key_uri(uri, public_key)

    def test_generate(self):
        """Test generate and use signer (key pair) for each sslib keytype"""
        test_data = [
            (CryptoSigner.generate_rsa, "rsa", "rsassa-pss-sha256"),
            (CryptoSigner.generate_ecdsa, "ecdsa", "ecdsa-sha2-nistp256"),
            (CryptoSigner.generate_ed25519, "ed25519", "ed25519"),
        ]
        if MLDSA_IMPORT_ERROR is None:
            test_data.append((CryptoSigner.generate_mldsa, "ml-dsa", "ml-dsa-65/1"))
        for generate, keytype, default_scheme in test_data:
            signer = generate()
            self.assertEqual(signer.public_key.keytype, keytype)
            self.assertEqual(signer.public_key.scheme, default_scheme)

            sig = signer.sign(b"DATA")
            self.assertIsNone(signer.public_key.verify_signature(sig, b"DATA"))
            with self.assertRaises(UnverifiedSignatureError):
                signer.public_key.verify_signature(sig, b"NOT DATA")

    def test_generate_ecdsa_scheme(self):
        """Test generate ecdsa signer for each ecdsa scheme"""
        for scheme in [
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]:
            signer = CryptoSigner.generate_ecdsa(scheme=scheme)
            self.assertEqual(signer.public_key.keytype, "ecdsa")
            self.assertEqual(signer.public_key.scheme, scheme)

            sig = signer.sign(b"DATA")
            self.assertIsNone(signer.public_key.verify_signature(sig, b"DATA"))

        with self.assertRaises(ValueError):
            CryptoSigner.generate_ecdsa(scheme="ecdsa-sha2-nistp192")

    def test_init_ecdsa_curve_mismatch(self):
        """Test that an ecdsa private key must match the scheme's curve.

        Signing with a mismatched curve produces signatures that can never
        be verified, because SSlibKey._verify() validates the curve.
        """
        signer = CryptoSigner.generate_ecdsa(scheme="ecdsa-sha2-nistp384")
        for scheme in ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521"]:
            public_key = copy.copy(signer.public_key)
            public_key.scheme = scheme
            with self.assertRaises(ValueError):
                CryptoSigner(signer._private_key, public_key)

    def test_private_bytes(self):
        """Test private_bytes -> from_priv_key_uri"""
        with tempfile.TemporaryDirectory() as tempdir:
            priv_key_path = os.path.join(tempdir, "privkey.pem")
            pems = ["rsa", "ecdsa", "ed25519"]
            if MLDSA_IMPORT_ERROR is None:
                pems.append("mldsa65")

            for pem in pems:
                with open(PEMS_DIR / f"{pem}_private.pem", "rb") as f:
                    privkey = load_pem_private_key(f.read(), None)
                    signer = CryptoSigner(privkey)

                with open(priv_key_path, "wb") as f:
                    f.write(signer.private_bytes)

                signer2 = Signer.from_priv_key_uri(
                    f"file2:{priv_key_path}", signer.public_key
                )
                self.assertEqual(signer.private_bytes, signer2.private_bytes)

    def test_custom_crypto_signer(self):
        # setup
        key = self.keys["rsa"]
        pubkey = SSlibKey.from_crypto(key.public_key())

        class CustomSigner(CryptoSigner):
            """Custom signer with a hard coded key"""

            CUSTOM_SCHEME = "custom"

            @classmethod
            def from_priv_key_uri(
                cls,
                priv_key_uri: str,
                public_key: Key,
                secrets_handler: SecretsHandler | None = None,
            ) -> "CustomSigner":
                return cls(key)

        # register custom signer
        SIGNER_FOR_URI_SCHEME[CustomSigner.CUSTOM_SCHEME] = CustomSigner

        # test signing
        signer = Signer.from_priv_key_uri("custom:foo", pubkey)
        self.assertIsInstance(signer, CustomSigner)
        sig = signer.sign(b"DATA")

        pubkey.verify_signature(sig, b"DATA")
        with self.assertRaises(UnverifiedSignatureError):
            pubkey.verify_signature(sig, b"NOT DATA")

    @unittest.skipIf(MLDSA_IMPORT_ERROR is None, "ML-DSA is supported")
    def test_mldsa_unsupported_library(self):
        """Test ML-DSA operations when ML-DSA support is missing in cryptography."""
        with self.assertRaises(UnsupportedLibraryError):
            CryptoSigner.generate_mldsa()

        key = SSlibKey("mldsa_id", "ml-dsa", "ml-dsa-65/1", {"public": "some-pem"})
        sig = Signature("mldsa_id", "1234")
        with self.assertRaises(VerificationError) as ctx:
            key.verify_signature(sig, b"data")
        self.assertIsInstance(ctx.exception.__cause__, UnsupportedLibraryError)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
