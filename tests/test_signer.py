"""Test cases for "signer.py". """

import copy
import os
import shutil
import tempfile
import unittest
from typing import Any, Dict, Optional

import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    CryptoError,
    FormatError,
    UnsupportedAlgorithmError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.gpg.constants import have_gpg
from securesystemslib.gpg.exceptions import CommandError, KeyNotFoundError
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    SIGNER_FOR_URI_SCHEME,
    GPGKey,
    GPGSigner,
    Key,
    SecretsHandler,
    Signature,
    Signer,
    SpxKey,
    SpxSigner,
    SSlibKey,
    SSlibSigner,
    generate_spx_key_pair,
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
                "hashes": ["only recognized by GPGKey"],
                "keyval": {
                    "public": "pubkeyval",
                    "foo": "bar",
                },
            }

            key = Key.from_dict("aa", copy.deepcopy(keydict))
            self.assertIsInstance(key, key_impl)
            self.assertDictEqual(keydict, key.to_dict())

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

    def test_key_verify_signature(self):
        ed25519_keyid = (
            "e33221e745d40465d1efc0215d6db83e5fdb83ea16e1fb894d09d6d96c456f3b"
        )
        ed25519_pub = (
            "8ae43d22b8e0fbf4a48fa3490d31b4d389114f5dc1039c918f075427f4100759"
        )
        rsa_keyid = (
            "42ebff629238b4e82224500e7467f5a1b6b36a924edf08774b8c6f335f9e0558"
        )
        rsa_pub = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqeiMhYUsT8HDG3BgB9A6\nowJxE3bgS0/D5bgoeOIuxWEs4yH0CrXuxjeqaDtkLvGuDIWBWg+EEkGCteFgu5un\nlM8SXHjk7hm/3j8AQDhBURUflHNmjzfdEx7KV7nLsFG9TTQD8u0lP5vU5CUk4gN1\n3erNJSo1ML+gid8MxdYe9joN7y+F2NVLlm8JFM7HraGoeVUnRxQIayUv+8cMkkel\nrAAqLuP0NMbiO2dczkrnxaQ7QOP+MJwnjQTYWUCcNWJZ3iNAmDLvqxiQd3WR1Q/x\nX/wCmx0Kyg1uORzLaWvnY+YWws6kkUNv7wHDqy97XZtvQexNw/X0ASlwSZrUyLGf\nufciColhmSZVfZEzGDpong64CiL3q9GLb9NDMapQAE1OAdm0ljRvroPaaUU/Zd+6\nIOJyy4Q4TbhdG6gimCddNWt2mjCCHZ8EQvNz3d9UphFavPBzG7yuQHcceBhJlIzA\nOpV6+SeusNocVwKJAJgbxScCzfDtzTDPsDtjfx/r4x/ZAgMBAAE=\n-----END PUBLIC KEY-----"
        ecdsa_keyid = (
            "e5a520cfb1a23cd6b782e07433098160c4568eaa168dfed96a5495933f44ac82"
        )
        ecdsa_pub = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy0u6kHCv3K1VHRgjlhqOlsGErHKo\nImWN7eN0zITHimJTiAUYvNEjM8LpGzEwtvNfspWuxVHlqjBM852aDVao3w==\n-----END PUBLIC KEY-----"

        # keyid, keytype, scheme, pub, sig
        key_sig_data = [
            (
                ed25519_keyid,
                "ed25519",
                "ed25519",
                ed25519_pub,
                "3fc91f5411a567d6a7f28b7fbb9ba6d60b1e2a1b64d8af0b119650015d86bb5a55e57c0e2c995a9b4a332b8f435703e934c0e6ce69fe6674a8ce68719394a40b",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha224",
                rsa_pub,
                "50874de0a5557dd0689a6d4bca1811ae4ec7d2c22af91bc66b9474ea0c520f5c9fbe57639dc2ef05fda289cd6595f86444375e811fe54a511100461adb0a579e465a1b372e77ff0774f596d38c94075a507bab427e9eb283ec5227f2c1b569cb8d514a104cd6a72081bf54635a13e966099a4d4d003a876370349334ddea6b0a916b79f509af33f136827b3de1293e17f33763ecad770ac0895a4a89f4c73ab5a8febd41939bca9f1a19076b3c1b9a3bf666b4e8c98e0375586af018e16bbd0d5b0aa3a127f382dc5571484272e79fb74d392f83b83ee72032bb2e9dc494816f5e9598ad9ecfd2f54128bd41684e008296f1d89af20eb6dfe30668fa9aa7c855922108ae10c866ca01cc267a390b4172effddfa7c5f5528da13ef2cb16aeed4baaabfa9824157468d03062185199652494da5440ce0c878311f350f4cfc84d1ae776f3ea0d513c6508244af4cc8d6ddd33bd6bb2a9421b0fffdfb0c0e94eaf603769656762f8e4699955aa947b79a1147aa0943d47373705d8cb31d474d94558",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha256",
                rsa_pub,
                "0d8d2bf80c5fdc1e94579c8f64502448f001c03032e481b56bf3bde08a3de188bdaa6d3cb74522b91e3da7851cb48675ee346aa9d13da53108f3a2033369a67168cbfe865d7a20f24d7f698d49092cbea63709a0041f4097193eacb79ff06c17a2e5c30fb4cad58d94e8f8b70c53e95b17d4f683f8dc0c6cd92d81ac3608c41dd0937062b5871730f41aaa4afe367fb7a41fe9b31ead331952d1cc66b40176ff302107537eeecd21aebcd13d65a120ed8c403892ac4a67bc0eb60574e50040770563cf64bb09156c1ca781c70789666ae42f90565649d6ed8712e8dc6c6f9d8e05d64f935a96b3da19d17033ae34cadb179a4c8bf792340ed2db5a4a8bed3e0f7eec6daf6db6947750b67834f6204decf8df39e5acef448de76125144505208197c50f3c1e5352bdbb7e9259f8d391e52dc6231e00544ddc592c5b4cdcdc91175087a7d77fcee0a802b604adb72794854a5e6eaeeaac8c629666bd13a936581121c9190b001afc4522300ba59323c140ec2b1444f62ea02225df9f721fcce887",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha384",
                rsa_pub,
                "5547ef93f31e20693b67fc5e5e69615ec36dd84c4921618a8892ea8565ffc5297776d7d6f6d1a8947589908f800c24096a6a02fe0c3ae19ac41a7ae5e13ced60b93932c87606a403be9ecab40f17d6a07e31b5a47ad3889ece114300474cb3888eb4e5558f050e78ca671ea2f541f5bb5ecd62622c29c7ba294878f456f7cffcf7c6c7ee266c7432d3d70ca552b09f77938f3b6c14c9222b2abeb4e7ac80b2c4050155ed085572fd536e495ec57e9131be306b814f49d3d4e62e56cd0f26d6e01f56f4d2d780642b2630f68c0593bcbfcb4f406ca565a92b5864fc49a7bc5ff656d9bb7fac69341955285ae55dc52c4697ad66c3d154fe1abae5bbb3e1a158a662b9b40e0227ca92a0f11145f584ac5229e2f6c8d42b2c584344a81c9f76f7064efc1cf0767db93c8d4ced725f5318fe45fbed97c147095fb67facad8eafde349f401d935802cb1c5134392aa358154e8edbe7c7c7c20770fb812503f801ce921bcc0a622ac500faface62fb3cc0e74d77960704f6ed51b83000bac32570dfcf",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha512",
                rsa_pub,
                "42f4cdbcb3d2853992111291f9d477be55ee5222fa3e77741c2065df18fa54287e1ded7dd5aed66db248e855ab24ed3177df40baffdb8e3e3b14bff6fd086d8deab4e0a2005e160ff94c43259594cab1e9a6e14c066bcde3c1c3a3d4b2caf2a31043305fdf066bdfc91d7e5c6f0fee0cb25fa4808af7a58b0e2f38a2867aa26e27dafb4cb4495d0d061185ffce439c2829eba14ace54b3042168bf16f2d970e28d83d565bd4c6d7fd5070c92207d0d4979be34f29d339a01fc179d4a85e7dd14a319f6de7593bd2c1e3e45f785ff4e5085d5ede9b571ce1cc851e9aa2c81851f257a0461a7d47a55b100a3e2ad0a28d1386b5a5e58963758e44099ee198c4e1d9826c71546e2e9eff3710eb8a5d2f847e821d61fadf1447d90885d1bc6e32572306773b0d36a40b470bfec0a27fd5c8e6f2d9fd947e507e4c80156d454880a27f76da0aa20344e19ed1d37d8ee3c8b125bdbd0a779718f3fcf63b5935445e74656060f54289ba00061c21bbc900dc926c447d6c09978f2f28208a8ddfd085bdb",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha224",
                rsa_pub,
                "73f90f9125b3f3c09a39b1085d5fb4bb4fafe1a8831b149c0eb12d0a7fb6d115e45121d1059a321c1628f2e81e78fbac8c72b22e21fb41de35abf8977f68245b97b906f8cc96f770b5667153c73e6bc980b29d1c3a3955ea20e6e3ddf6376055195fee10c3c6230c39929231d8c14a586dadb7dffc4350ffa194b3365d135cf26d0cb07cd09cdc30e05dda60f5529d69795e134039cb722b41825df50699a9e61ecfb6401be8fd3957dd191ad9cdfe3e880468228456f8077b67d9a26a4db0fbebcdfa97a3689ba86930066810a2eaba0433eab9b790522ba5581eb7883f4413374c4f0e4298f771bb16d7593d12db5562e0076e853b4f1ba2286b44ea03f353960311d125b7a1cb3da05800555605ba224d09e1528c30edf4936539cdf161e109a34c8b3403b274c9e279ab0518bfe3c49c6a8c6a60e949b6cd70151f3dd918077df49a3b3a226ec1b7f1c4784588169f09e650c01b5d9f4aae2965b822d509dfaac62c1d98518e8d1a51ad1c7745cb97c25522a6fa759a9f8e7e70b09454e5",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha256",
                rsa_pub,
                "60d0e95c55d34af072b4ebde3733a04abf40f3b1c49cd7824ce7b33379fa7aa774fc9289a053ffeaaadc19ca08df7105c25f28c902c5b0bd8a4ec3d62a1a2da4494875784dd8dc97a02f17816d69aae758e5e390e46461422d8ff185e7ae27ebdebc00617dbe7eafb01afbbda99a8c92dcb6db3d1b50111a25621f20be182f9bba4285ea0b35f0e61271998be18ffaf2163bac03633adfc5950c44623af68f9ec7942962f9c28715124220e560e8e84e419050b208d003776022a7f14716df510b5d702e61e261f446ed9cc48d812293bfdb0b4c2ef6345d699cf39f07233a63940bf51e8db27e4a91b34b1f1ae5c26ba61e85c2ac59bb00cde3efe4eb33a8b1bb50061b1218fc34c844eaf51fc01c3f688725f41c6710c0237ffc3ea88b4aa21cfb3b7c6cafe7c39ba61f2b3d25b1587c9c0695f7bb2ffd20879cc0f0c060282593459ca5977d819a305ce0610ba444517d5164bcb6a2cdbf3170e63bcaaf2d73d13909352fc15ac9394ea1487529c6105c25730cc20103deb254b323a87b6c",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha384",
                rsa_pub,
                "7f40f90509ce82cc41e14ab8acdca473b11bcad2805d08af1e65795e4da95d238409f490e84ca0a5fff517633241096585076b75bfac79f8ae38a225917fc00519b64a0d12ff52a3351642f5a44d61d12281369212b2f77a1db085baad7e1917816a516a1d10c975ae35c5f7e3276df6a9108062e57b997b2e0ce66643c12eb97db310e97b828065afab9609571e6f1ec96be82c556c63a5b01b40f5232f760d9c559a4bf441ca467f9a68c6567bd17afb5d67d0718e2a3f54a7b99e9775266de2b79bb354c22325e9cd26f1e1702080bf4ce361b7d574e5e69485f8e7d10576ce54912a877b663daf2b51eab4200ecb4a80e9702ef4ce75b564ad0dc5adc168f7aa214cbcc76e0972f171623a45c4fbedd4cb1eec395c41a8f65313add6f1867662f4f36b0e49b05effcae0bad20b39511cd4e2b2901808222053e331aa2c45a8388c7bfe7e09df27c79a2689c3a564f22c3eee0354ec73d07d7345c6779e47beca877e10c9b38ac137f62059b2eefa19d6ac091c5e8d16e236754d5602a149",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha512",
                rsa_pub,
                "28f1f467473ac067f1c0582aee76ccbaab65e28bb64d9649d5e39814a897280347aaa36fb10011053e60795e82e2fb11f8c30282b96066e381ba7deb852f32c7f476bf6c91065e898ce28e5e6861296e707b5e292fbce8521b7d7762c7cbed3b9a648379f629c626c40cbf5b65d05bb96239174c69e82bc792d81e58d95af4b6089fdbebf39747c1d32a7bcdf2b259b0e927d8da7b4bc33e9a8de288513f606c46cdb27423df9cf71bfd516da9a688b080233b06ff84d43486c2262255036b38eb8b913b79d48e2f8f2dc98c52c41db24a41105e96f0549d6e8c89016473bde6de99d9905a1831fb3691a481e47a82af3b58cdc3b9485b5115e70f48e2b370be2377b67509a62c36ad30b9d40de01732f7ad389030ae944ad1d7a5f0ede3896faf2e9543ea762cadc2495f6cc2132aad0511c0e7dd0b81d9725fa3f5ad33ddbb6b62323b035e2ceaffb7777ccdd5cbed3443b0c84b21da035c55edb5f337b6f085aa1c5591780b42a0268485d4028e79805337175907ef8b0581d1541584f445",
            ),
            (
                ecdsa_keyid,
                "ecdsa",
                "ecdsa-sha2-nistp256",
                ecdsa_pub,
                "30450220790c990af320a0d4ad95f0a4b81bfaa659bb70967bae67c25bfd29539f81497d022100dec2dfd1119b9b1213a4fdebcfece8c94ee2275f40b59904d0888bcb2db8ea87",
            ),
            (
                ecdsa_keyid,
                "ecdsa",
                "ecdsa-sha2-nistp384",
                ecdsa_pub,
                "3045022075248f7b9fb3b6446a662c73dd220cfbe3c3f1f913cdd5f7568562bfb86506d802210082319199d4a35062c20d8f9dbc619dfb535dd98e81f27e3cbfb2a7302ac14e80",
            ),
            (
                ecdsa_keyid,
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp256",
                ecdsa_pub,
                "3045022100f0ceebf17074f778f8a598fdb351f3303865038b9abe4ac7bb91b31c0f29b1f702201f4a8ab33694560a98fbcf61e73776dd4ae0a743ecbec85feab0c6b1070e5fb3",
            ),
            (
                ecdsa_keyid,
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp384",
                ecdsa_pub,
                "3045022100c697f7c159bab2f1083650d52061508b7d06d9a0504ad6b5f89daba87665346102203f41da0c93f333fcec5e0ac5eb663653998bc5689912f22c89ff53eb89da10c2",
            ),
        ]
        for keyid, keytype, scheme, pub, sig in key_sig_data:
            key = Key.from_dict(
                keyid,
                {
                    "keytype": keytype,
                    "scheme": scheme,
                    "keyval": {
                        "public": pub,
                    },
                },
            )

            sig = Signature.from_dict(
                {
                    "keyid": keyid,
                    "sig": sig,
                }
            )

            key.verify_signature(sig, b"DATA")
            with self.assertRaises(UnverifiedSignatureError, msg=scheme):
                key.verify_signature(sig, b"NOT DATA")

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
            def from_dict(
                cls, keyid: str, key_dict: Dict[str, Any]
            ) -> "CustomKey":
                assert key_dict.pop("keytype") == "custom"
                keytype = "ed25519"
                scheme = key_dict.pop("scheme")
                keyval = key_dict.pop("keyval")
                return cls(keyid, keytype, scheme, keyval, key_dict)

            def to_dict(self) -> Dict[str, Any]:
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


class TestSigner(unittest.TestCase):
    """Test Signer and SSlibSigner functionality"""

    @classmethod
    def setUpClass(cls):
        cls.keys = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
        ]

        cls.DATA = b"DATA"

        # pylint: disable=consider-using-with
        cls.testdir = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.testdir.cleanup()

    def test_signer_sign_with_incorrect_uri(self):
        pubkey = SSlibKey.from_securesystemslib_key(self.keys[0])
        with self.assertRaises(ValueError):
            # unknown uri
            Signer.from_priv_key_uri("unknownscheme:x", pubkey)

        with self.assertRaises(ValueError):
            # env variable not defined
            Signer.from_priv_key_uri("envvar:NONEXISTENTVAR", pubkey)

        with self.assertRaises(ValueError):
            # no "encrypted" param
            Signer.from_priv_key_uri("file:path/to/privkey", pubkey)

        with self.assertRaises(OSError):
            # file not found
            uri = "file:nonexistentfile?encrypted=false"
            Signer.from_priv_key_uri(uri, pubkey)

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

            # test signing with unencrypted key
            uri = f"file:{f.name}?encrypted=false"
            signer = Signer.from_priv_key_uri(uri, pubkey)
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

            # test signing with encrypted key
            def secrets_handler(secret: str) -> str:
                if secret != "passphrase":
                    raise ValueError("Only prepared to return a passphrase")
                return "hunter2"

            uri = f"file:{f.name}?encrypted=true"

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

    def test_custom_signer(self):
        # setup
        key = self.keys[0]
        pubkey = SSlibKey.from_securesystemslib_key(key)

        class CustomSigner(SSlibSigner):
            """Custom signer with a hard coded key"""

            CUSTOM_SCHEME = "custom"

            @classmethod
            def from_priv_key_uri(
                cls,
                priv_key_uri: str,
                public_key: Key,
                secrets_handler: Optional[SecretsHandler] = None,
            ) -> "CustomSigner":
                return cls(key)

        # register custom signer
        SIGNER_FOR_URI_SCHEME[CustomSigner.CUSTOM_SCHEME] = CustomSigner

        # test signing
        signer = Signer.from_priv_key_uri("custom:foo", pubkey)
        self.assertIsInstance(signer, CustomSigner)
        sig = signer.sign(self.DATA)

        pubkey.verify_signature(sig, self.DATA)
        with self.assertRaises(UnverifiedSignatureError):
            pubkey.verify_signature(sig, b"NOT DATA")

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
        shutil.copytree(
            gpg_keyring_path, os.path.join(cls.test_dir, cls.gnupg_home)
        )
        os.chdir(cls.test_dir)

    @classmethod
    def tearDownClass(cls):
        """Change back to initial working dir and remove temp test directory."""

        os.chdir(cls.working_dir)
        shutil.rmtree(cls.test_dir)

    def test_gpg_sign_and_verify_object(self):
        """Create a signature using a specific key on the keyring."""

        uri, public_key = GPGSigner.import_(
            self.signing_subkey_keyid, self.gnupg_home
        )

        signer = Signer.from_priv_key_uri(uri, public_key)
        sig = signer.sign(self.test_data)

        public_key.verify_signature(sig, self.test_data)

        with self.assertRaises(UnverifiedSignatureError):
            public_key.verify_signature(sig, self.wrong_data)

        sig.keyid = 123456
        with self.assertRaises(VerificationError):
            public_key.verify_signature(sig, self.test_data)

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
        with self.assertRaises(KeyNotFoundError):
            GPGSigner.import_(non_matching_keyid, self.gnupg_home)

    def test_gpg_fail_sign_expired_key(self):
        """Signing fails with non-zero exit code if key is expired."""
        expired_key = "e8ac80c924116dabb51d4b987cb07d6d2c199c7c"

        uri, public_key = GPGSigner.import_(expired_key, self.gnupg_home)
        signer = Signer.from_priv_key_uri(uri, public_key)
        with self.assertRaises(CommandError):
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
        # pylint: disable=protected-access
        _, public_key = GPGSigner.import_(
            self.signing_subkey_keyid, self.gnupg_home
        )
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
        # pylint: disable=protected-access
        _, public_key = GPGSigner.import_(
            self.signing_subkey_keyid, self.gnupg_home
        )
        legacy_fields = {"keyid", "type", "method"}
        fields = {"keytype", "scheme"}

        legacy_dict = GPGSigner._key_to_legacy_dict(public_key)
        for field in legacy_fields:
            self.assertIn(field, legacy_dict)

        for field in fields:
            self.assertNotIn(field, legacy_dict)

        self.assertEqual(
            public_key, GPGSigner._key_from_legacy_dict(legacy_dict)
        )

    def test_gpg_key__eq__(self):
        """Test GPGKey.__eq__() ."""
        key1 = GPGKey("aa", "rsa", "pgp+rsa-pkcsv1.5", {"public": "val"})
        key2 = copy.deepcopy(key1)
        self.assertEqual(key1, key2)

        key2.keyid = "bb"
        self.assertNotEqual(key1, key2)

        other_key = SSlibKey(
            "aa", "rsa", "rsassa-pss-sha256", {"public": "val"}
        )
        self.assertNotEqual(key1, other_key)


class TestUtils(unittest.TestCase):
    """Test Signer utility methods."""

    def test_get_keyid(self):
        # pylint: disable=protected-access
        self.assertEqual(
            Signer._get_keyid("rsa", "rsassa-pss-sha256", {"public": "abcd"}),
            "7b56b88ae790729d4e359d3fc5e889f1e0669a2e71a12d00e87473870c73fbcf",
        )

        # Unsupported keys can have default keyids too
        self.assertEqual(
            Signer._get_keyid("foo", "bar", {"baz": "qux"}),
            "e3471be0598305190ba82f6f8043f4df52f3fbe471fdc187223bd9ade92abebb",
        )

        # Invalid keys cannot
        with self.assertRaises(FormatError):
            Signer._get_keyid("foo", "bar", {"baz": 1.1})


@unittest.skipIf(os.name == "nt", "PySPX n/a on Windows")
class TestSphincs(unittest.TestCase):
    """Test create keys, sign and verify for sphincs keys."""

    def test_sphincs(self):
        """sphincs signer smoketest."""

        # Test create/sign/verify
        public_bytes, private_bytes = generate_spx_key_pair()
        public_key = SpxKey.from_bytes(public_bytes)
        signer = SpxSigner(private_bytes, public_key)
        sig = signer.sign(b"data")
        self.assertIsNone(signer.public_key.verify_signature(sig, b"data"))
        with self.assertRaises(UnverifiedSignatureError):
            signer.public_key.verify_signature(sig, b"not data")

        # Test de/serialization
        self.assertEqual(
            signer.public_key,
            SpxKey.from_dict(
                signer.public_key.keyid, signer.public_key.to_dict()
            ),
        )


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
