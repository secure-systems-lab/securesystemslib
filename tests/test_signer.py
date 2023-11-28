"""Test cases for "signer.py". """

import copy
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    CryptoError,
    FormatError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.gpg.constants import have_gpg
from securesystemslib.gpg.exceptions import CommandError, KeyNotFoundError
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
    SpxKey,
    SpxSigner,
    SSlibKey,
    SSlibSigner,
    generate_spx_key_pair,
)
from securesystemslib.signer._utils import compute_default_keyid

PEMS_DIR = Path(__file__).parent / "data" / "pems"


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
            "fc3920f44a1deec695ed9327f70513909a36f51ad19774167ddf28a12f8bbbed"
        )
        ed25519_pub = (
            "50a5768a7a577483c28e57a6742b4d2170b9be628a961355ef127c45f2aefdc5"
        )
        rsa_keyid = (
            "b7c94258646e970d336b779eea6b90ef931ea56e2d356ce487201f6bb776e94b"
        )
        rsa_pub = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsDqUoiFJZX+5gm5pyI1l\nVc/N3yjJVOIl9GyiK0mRyzV3IzUQzhjq8nhk0eLfzXw2XwIAYOJC6dR/tGRG4JDx\nJkez5FFH4zLosr/XzT7CG5zxJ3kKICLD1v9rZQr5ZgARQDOpkxzPz46rGnE0sHd7\nMpnpPMScA1pMIzwM1RoPS4ntZipI1cl9M7HMQ6mkBp8/DNKCqaDWixJqaGgWrhhK\nhI/1mzBliMKriNxPKSCGVlOk/QpZft+y1fs42s0DMd5BOFBo+ZcoXLYRncg9S3A2\nxx/jT69Bt3ceiAZqnp7f6M+ZzoUifSelaoL7QIYg/GkEl+0oxTD0yRphGiCKwn9c\npSbn7NgnbjqSgIMeEtlf/5Coyrs26pyFf/9GbusddPSxxxwIJ/7IJuF7P1Yy0WpZ\nkMeY83h9n2IdnEYi+rpdbLJPQd7Fpu2xrdA3Fokj8AvCpcmxn8NIXZuK++r8/xsE\nAUL30HH7dgVn50AvdPaJnqAORT3OlabW0DK9prcwKnyzAgMBAAE=\n-----END PUBLIC KEY-----"
        ecdsa_keyid = (
            "985171ff9ee901fbab17aa6f57347933aeae9d194f0f93e83e5c3dbc1755e754"
        )
        ecdsa_pub = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsYJfSlYU3UlYbGOZfE/yOHkayWWq\nLPR/NeCa83szZmnJGc9wwCRPvJS87K+eDGIhhhKueTyrLqXQqmyHioQbOQ==\n-----END PUBLIC KEY-----\n"

        key_sig_data = [
            (
                ed25519_keyid,
                "ed25519",
                "ed25519",
                ed25519_pub,
                "dbea1238620949daeb806b0347ffd9f28f8e481edc9ffb4dd8189715c0219f195f68f91ea72769fd8892d6b0af8884b4ad49ea09510201dae6ed0995075ea103",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha224",
                rsa_pub,
                "78fb3c56142868a5de1bd965af37f204763eac4755ea9b79911bac89159a98679987a8b99356987524cd9108a5f373f367aac8ba970d7b690a67b8fb79893d07fcf4a66569fcc479578c633302a95e7e4640f6f88d5e0d5e26af7497f613f6417bc30df6377137f63f167ee886d2e4c32a2a945a3e08a8d68630c9d9e57e8650cf5e501516b61bdb4d00de3b4046ae413e5a583ac2dbd885e40b8d8180e51ebfaab2f5d2b95e6b5b093e2511e5893997adb8f9ee233a4e40e902d60d6fbab7df04b97d9872df6081661b2e2bd0663019daee059eacaa9cebf8efde9ca9f1a22e7cfb6b907bcab29c4d4318e214d91b1ca1eb5977ecec45219472189a6720ec956e29716a0d82b9ba3c4a2c5d2187295c4f7a4e20b622081b38b2c2e315f168aea7bd864c5b8c30f07235145682de98c0f28784c515ae096dd68548107fc7c5b7a01286625dd40870338921036dfa07932cad4f6e42a939867b8aaf7e8e3e0ba03a1005412832ce3f53d9576b68938d57b87d0455d0de0d97e12132ac4f8dee2b",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha256",
                rsa_pub,
                "2f3ed7aa4d18fdb2a677d7a772f3b1283947b09b834a6d523a66b734404552ce4966e1984d4f4a46bc20f5effbc509bbf953469feb6eda5230e5bbe3399839e0d5c601e853918427849f2d90939a843527193932aef4711b65db353bc4adf76d4ec67886d6cbb2e2b315148deee649be7489fb09439a0d22b1abf4b4faa118dd8682f7be173ea398ecf0905eb8eb7232909492ceed1a3134fb678c10b0307ac9f5924b73399d7ac6e729c8e91eca6a0e541dafd22d5fc774fa900c18e38b854884342864951d05b519abf7cee8afe761334c546491b9a09545a9eb5a4096ac5e4be35b794fb9cb8c5204ddbc5eb7d1fc92c2f221d99d49909a41cd747e7f436c07480efb7e94f52d8a8641f9a32d2fa9e2e7f862537b66fa07ba56f44ce7d1f2ad7637ebd8c454d904eea09121977633bcef5748ccc843bc4ebe720878ad9caca97c714aeafeffffd9d1c0cd92218e78691c3abab43958f2defd39381bde71ed73de23044bf44791f8717e1d2150bb5fe7fe0184d089042c284e9ca5779276fc",
            ),
            # Test sig with max salt length (briefly available in v0.24.0)
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha256",
                rsa_pub,
                "392c5017fd389863649fcda8ba054e1bb346c2ed5cc9959c897a731fc37cd3401c15d77ed17f040a70517c9256f2682181da9aedca08bf3c2aac26658d3064c7df73365da6b47b8f02cb18813cb899e26a101b82e45752cba556e9fa8ad224bb363efa1db9209873ec82ca74bcb7109facfc29f45e5521a6a856803b1a221609f711da2b93915a65d6bfb1f5635a5bc7bdb98510b824fad243c0eaa4ac6674e492d10c25a9e442e9ec6e72871b5d67dfc20b1d5a76ab5f357a6cba4ae9587009744a8023a71c9da38e7ed9c1264c649664c8b72593b79ecc4d0f76d9ad539ace51dd73e9bbf11535f17d6d4caae576f67d1b203a08d35a823eb7c2df99675d4b6651d647f29a6e179263e1a18eb03a6c9209d1daf40c465c19052d46e8e6f5bb480309b91b064e127ea20812e5c0b4fc7ddd98f401a1b920866543335ac31ea8cd650341ef321ce98c3ba48c2ea9172da3a614b8791f98ac7dffd6e2e8506694df100903d60dffa6cf4f6723724ba71aba462229d5f62b7e007553b8af54dabc",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha384",
                rsa_pub,
                "1c2613ec1f07eacc74b77d0d390eccd25f035d5e973c31471b0521adc3ed3344cdb86a4cf7b73eacabc302198c1b064d4deea60b57dcff5d6b2717d37fff18fb8aa49d7fe07665f452c8a91e7aca11623a314262b3f829930fe65e574e12373737cfa2e15c72931309cb63624d93f62e4819ca449d33cdbfbdb737fe52f24c1bcf1d52b7b9bedd0770f8722ce5b0e273258450b2524d620c44d120a4a42a744880ecc9fbdee831374e9dd968128c10963ae2f43b53355ca5fb389d63895ffd318752ea4293fde548f50c06b9a71b4064f2646f2f10f1ee0df5f3a93ae0bd89e44dd9f595591ca79e9aa8a72b983de1019bbeb2746dbb4895154bcdd4b8bca8626b558b4e83aefdc2dbf5f7c5cd930303f18a49ddd52f41a8b4aaef61cc832f7d33def162e9a4a405ee4212bcde1cf7b186032f1edc4e089ff502e200282e2242e09771f0e6fa4e754150330f5f68df1ce58c85a1617b5f1cedfe9e7f1f1fa1e1ae8429bab86d8f17757daee028c9c38190dee71372a7a4003971f147f27bc75b",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsassa-pss-sha512",
                rsa_pub,
                "050f41edfd08249c9824f9940ef25ba1c2fae475bf4700bff3b4c2f209b5651e583892c5d3aa4b79d8f5e1d5b1805195fc96b7664e349509d2f5da366ac5a93641b46accc7571ecacb5472b8bdd16e2128ba237e6688244e3d65bbe3417d14e86ab4ff7e8b13e3fe0632c6c8222449986bdc432b0816cfc59c439e408492b63668269d300da7a59f6e4bcb541414b6b4bafdee62d7c9a6390c52a077a3c1585243bf1bc4319972cdb27e790461309ca83d607c37690b546489e7710fadb0c454ca0b2dc32c2d8c2ac210f5bfe1b278f2879f77186d0f3d228b9fa7d4eff7d89939eddc3acc37f513221d12ed7f84aeeb51516b7e001eae1ffb2046c0ea663f15cdfc5eb7651c9b7bee6468c25606e077cde95ade93a79d2c2ad42dec358e839582a3fd9b196a5dd0e20585f1d8c7c99692bc95ee5d33e064651bb0d70d1605390dfca5f907499897630a3a5229532c7cd6a57db102566bc2644485ba7aba5b40eee91d1fa64421a618fed90fc29168e5098ee1f27f893eb758f5c4087bd94b10",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha224",
                rsa_pub,
                "9d4eb41f187a44f384b0555bfef170428b0a46c6111f67104fec8843a9a3c91b8522b36f5bbfd5240a9871ffdc4f44faf33a4870c3daa5c2377ebcbeeab6aeb991d13840abd68f166631fe356e6dc0411af05a94a263d52805eacfe2c5fd3ce291898c6550427cd2ef79155331714eb553209bfb49f921c7aea46a2fa113bb5771a51f569dcb3c5766a8e0867172e9b1a914a0f1235145c33afb9532f63dc04f919c99347c7fca5eac6e3ab338a2a73b3c9e0ba19bb1454cd10b6ebbfe274daa8121681de84fa3d30a70e168e342748ab5d95f82a2bc74d287e89ef4031b7fc4b0fc59a5e5cdd792ae9c569d2de9463d09b45abc16ee4578bafeb32771aee4f5d777e597ec40fa155f2c8d05460ca32f0ae8e97e958420dc830ba33c3a53b0f3f4e68dfd0675f9b2eb71df9dbee695cb7700f05db0cecc6803cafa152774c0edca6617a734c4453248a584c35b2ec2aa0b8dfb196e67c5241c924d67586085a38b0f0210dbac724973a625cadce95527815bd01e1c1bbd9fd63e7da920f7850f",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha256",
                rsa_pub,
                "0c8ec1336540b7e04a2cef460597c54a586766725c532cbd13b3c7071018179e666b75f3165f805c677c5a6169097b4c20175fbea8a0aa4879ecb465cebe2040f6b8db4caa0965b56a20e39bea0c5a8f3746284e41239cd0ab998c5d70b7a0a26f1f5c2909461ab74941f8dcde8faa4d360be710cc405664e5b7a62b54509b32a80ac58b4c494e54270a9d51f8861c7eeb984898414507365bf4bf2f07e4e0507c1f01ee6560dca6f27bef79abd2c9e18bc7cf8820d017f3ad51ce82f6d9bc57e7c3ffc1ca13a9c83a8163c1c0850a7145b577d1db99634435e7b74de6fb29ec68ee13a79e16e5c00eae0d9a15b6cb4e81770fd8d0c40a80f3df4c6d2b9c29c4b35645914263d0aa91d6700ae6f23a7c16d3ab6095c7b736b34ea6b971937f49fad55145e41c6a77e67fbabd2870c8707e0b36fc6bcb8eba9889231df7153951a03e81478eb9bacde6e77eaa683f2133186bb7987f670b602d3902068b8a4a50e1de8334eeb411530599fa35ee37d1f678bf5277bf46cd30ea7bfe79e5161560",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha384",
                rsa_pub,
                "7eb62b42cafda8fadfbc957d759a3f09089c28132389e1a1d2fb50a8cdb7491e07bf351f03a442e36d7a5abe0daeec621a1e414827dbeac4bd8f6ede709801afec1969b903212995f56f7c544b35719f8819a340872530b4f087ab8159bb052e6d0a99ed65ed2114de0044a38cbb017a67fe3f41854fb95e5218d8d4d77d3e51192075b4f8bd38926484116642545225f7389b5bcd61baa49bdddaf8f499a1c3ef72a4e2e71767f56863416a13f4d5c4fb2a876a89e8c40ac12f7b188b971257a7fc4c48c6f4942e85120402e3c4c2c4761638a57c3f59cf4e136e64a755c68075ec85d49cb89d8f6ec2b348c40f3e46cf3fd9d93e5721e26bdd9ee2eadcc13a757cdf5d5ca40e59bf48e737e5341708adf9d306d123c50f08ebba1bec5cc233b9fd2dc5bffee179f40cf88648218710ec2bf273fb0d6f02cee3eedd19a0ca0b64f60991f9d4dff97cc088d6db9106c176cf48e12183c3ca3ff0acf2948e3fec8c82582d84e70342b0767c7b62aa2d92b9441b2bbdf7a00ec827fa0084361f92",
            ),
            (
                rsa_keyid,
                "rsa",
                "rsa-pkcs1v15-sha512",
                rsa_pub,
                "16f7e8877944cedc0bb8cf45c04a2dcee7e844f8aed71e8d10c8950b509be9959a3b0b7ad41db44bfaeebc1e00fc9d25fc05c477ae0eebc49aaba4a6f2f06e768452d2e3c6dd3401b78f945402a72390729de99fc3ef414f9cb9f9ed3052e26615517d3a82c30ac531a516a391867329f48fd6cbacb0ae4532bd9146879abd677a871bd80d45bdc596ce828d6a2bb6f40c8390978b336cc9d32634d2653f6a4f96f38799cd96931a9a0ac23834cc73de19ca804d683abff0c962cd77573b4f6df71a136be2f7eb3fd80e3d7eb74c3b56a21db49b3e3ac355492ba3a63c73f94533fc5c8567380e64b056a2199212fc3cf5f92a6b8514773bf2847b6598b3433297d282a74cdf21108dcd995761b47655be41dcefbb6e223778f6de8ade781d53f44c9767d77b3c41d43ddb9cc01eaa4db79a4698a30b5d8d00b8e7c7106a58d8dc9c2bb0a35f2fc11647727b2fd1ab254b288f1120ef8bf66b73617a7de4a7e3943e2ca921f55e08ffb7ed1138bd2e61f922659e1fe8bd21b9e39fe98ecf273c",
            ),
            (
                ecdsa_keyid,
                "ecdsa",
                "ecdsa-sha2-nistp256",
                ecdsa_pub,
                "3045022100b3db1e5ca53226ee27f93a3b2f5e1534f4a4c51f872aa1b6efd0b37be27f483602204f793f7ad7c25188ad55eb6a8a8d142f89b0b0090815de47d9a24389872b02e3",
            ),
            (
                ecdsa_keyid,
                "ecdsa",
                "ecdsa-sha2-nistp384",
                ecdsa_pub,
                "3045022100fc41dad2236dc479454cfeab69a8d77b67e38ef3290ddef3f240406db63c407c0220402ef9c132ec6682f70143079c6e0c11ce4904be03354bd1b0bc7553125e013e",
            ),
            (
                ecdsa_keyid,
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp256",
                ecdsa_pub,
                "304502207d0058b745b2259501204c2ba287ba3769ec2420e12463a325c59670c24df9b6022100836ca63a1b870f755c1596711a003a505e72e25cb0970e823a331e044adc63ec",
            ),
            (
                ecdsa_keyid,
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp384",
                ecdsa_pub,
                "304502200cf6f9794205d4694438cc4f394fe385c85d2ee6938f079c7e1bd896dcd8c635022100a2ba46172be199955be7317c9335ae7f073328d26a5f561968024ff46e430c21",
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


class TestSSlibKey(unittest.TestCase):
    """SSlibKey tests."""

    def test_from_crypto(self):
        """Test load pyca/cryptography public key for each SSlibKey keytype"""
        test_data = [
            (
                "rsa",
                "rsassa-pss-sha256",
                "2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241",
            ),
            (
                "ecdsa",
                "ecdsa-sha2-nistp256",
                "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            ),
            (
                "ed25519",
                "ed25519",
                "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
            ),
        ]

        def _from_file(path):
            with open(path, "rb") as f:
                pem = f.read()

            crypto_key = load_pem_public_key(pem)
            return crypto_key

        for keytype, default_scheme, default_keyid in test_data:
            crypto_key = _from_file(PEMS_DIR / f"{keytype}_public.pem")
            key = SSlibKey.from_crypto(crypto_key)
            self.assertEqual(key.keytype, keytype)
            self.assertEqual(key.scheme, default_scheme)
            self.assertEqual(key.keyid, default_keyid)

        # Test with non-default scheme/keyid
        crypto_key = _from_file(PEMS_DIR / "rsa_public.pem")
        key = SSlibKey.from_crypto(
            crypto_key,
            scheme="rsa-pkcs1v15-sha224",
            keyid="abcdef",
        )
        self.assertEqual(key.scheme, "rsa-pkcs1v15-sha224")
        self.assertEqual(key.keyid, "abcdef")


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

    def test_sslib_signer_sign_all_schemes(self):
        rsa_key, ed25519_key, ecdsa_key = self.keys
        keys = []
        for scheme in [
            "rsassa-pss-sha224",
            "rsassa-pss-sha256",
            "rsassa-pss-sha384",
            "rsassa-pss-sha512",
            "rsa-pkcs1v15-sha224",
            "rsa-pkcs1v15-sha256",
            "rsa-pkcs1v15-sha384",
            "rsa-pkcs1v15-sha512",
        ]:
            key = copy.deepcopy(rsa_key)
            key["scheme"] = scheme
            keys.append(key)

        self.assertEqual(ecdsa_key["scheme"], "ecdsa-sha2-nistp256")
        self.assertEqual(ed25519_key["scheme"], "ed25519")
        keys += [ecdsa_key, ed25519_key]

        # Test sign/verify for each supported scheme
        for scheme_dict in keys:
            # Test generation of signatures.
            sslib_signer = SSlibSigner(scheme_dict)
            sig_obj = sslib_signer.sign(self.DATA)

            # Verify signature
            verified = KEYS.verify_signature(
                scheme_dict, sig_obj.to_dict(), self.DATA
            )
            self.assertTrue(verified, "Incorrect signature.")

    def test_sslib_signer_errors(self):
        # Test basic initialization errors for each keytype
        for scheme_dict in self.keys:
            # Assert error for invalid private key data
            bad_private = copy.deepcopy(scheme_dict)
            bad_private["keyval"]["private"] = ""
            with self.assertRaises(ValueError):
                SSlibSigner(bad_private)

            # Assert error for invalid scheme
            invalid_scheme = copy.deepcopy(scheme_dict)
            invalid_scheme["scheme"] = "invalid_scheme"
            with self.assertRaises(ValueError):
                SSlibSigner(invalid_scheme)

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
    """Test utility methods."""

    def test_compute_default_keyid(self):
        self.assertEqual(
            compute_default_keyid(
                "rsa", "rsassa-pss-sha256", {"public": "abcd"}
            ),
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


class TestCryptoSigner(unittest.TestCase):
    """CryptoSigner tests"""

    def test_init(self):
        """Test CryptoSigner constructor."""
        for keytype in ["rsa", "ecdsa", "ed25519"]:
            path = PEMS_DIR / f"{keytype}_private.pem"

            with open(path, "rb") as f:
                data = f.read()

            private_key = load_pem_private_key(data, None)

            # Init w/o public key (public key is created from private key)
            signer = CryptoSigner(private_key)
            self.assertEqual(keytype, signer.public_key.keytype)

            # Re-init with passed public key
            signer2 = CryptoSigner(private_key, signer.public_key)
            self.assertEqual(keytype, signer2.public_key.keytype)

    def test_from_priv_key_uri(self):
        """Test load and use PEM/PKCS#8 files for each sslib keytype"""
        test_data = [
            (
                "rsa",
                "rsassa-pss-sha256",
                "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwhX6rioiL/cX5Ys32InF\nU52H8tL14QeX0tacZdb+AwcH6nIh97h3RSHvGD7Xy6uaMRmGldAnSVYwJHqoJ5j2\nynVzU/RFpr+6n8Ps0QFg5GmlEqZboFjLbS0bsRQcXXnqJNsVLEPT3ULvu1rFRbWz\nAMFjNtNNk5W/u0GEzXn3D03jIdhD8IKAdrTRf0VMD9TRCXLdMmEU2vkf1NVUnOTb\n/dRX5QA8TtBylVnouZknbavQ0J/pPlHLfxUgsKzodwDlJmbPG9BWwXqQCmP0DgOG\nNIZ1X281MOBaGbkNVEuntNjCSaQxQjfALVVU5NAfal2cwMINtqaoc7Wa+TWvpFEI\nWwIDAQAB\n-----END PUBLIC KEY-----\n",
            ),
            (
                "ecdsa",
                "ecdsa-sha2-nistp256",
                "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcLYSZyFGeKdWNt5dWFbnv6N9NyHC\noUNLcG6GZIxLwN8Q8MUdHdOOxGkDnyBRSJpIZ/r/oDECSTwfCYhdogweLA==\n-----END PUBLIC KEY-----\n",
            ),
            (
                "ed25519",
                "ed25519",
                "4f66dabebcf30628963786001984c0b75c175cdcf3bc4855933a2628f0cd0a0f",
            ),
        ]

        signer_backup = SIGNER_FOR_URI_SCHEME[CryptoSigner.FILE_URI_SCHEME]
        SIGNER_FOR_URI_SCHEME[CryptoSigner.FILE_URI_SCHEME] = CryptoSigner

        for keytype, scheme, public_key_value in test_data:
            for encrypted in [True, False]:
                if encrypted:
                    file_name = f"{keytype}_private_encrypted.pem"
                    parameter = "true"

                    def handler(_):
                        return "hunter2"

                else:
                    file_name = f"{keytype}_private.pem"
                    parameter = "false"
                    handler = None

                uri = f"file:{PEMS_DIR / file_name}?encrypted={parameter}"
                public_key = SSlibKey(
                    "abcdefg", keytype, scheme, {"public": public_key_value}
                )
                signer = Signer.from_priv_key_uri(uri, public_key, handler)
                self.assertIsInstance(signer, CryptoSigner)

                sig = signer.sign(b"DATA")
                self.assertIsNone(
                    signer.public_key.verify_signature(sig, b"DATA")
                )
                with self.assertRaises(UnverifiedSignatureError):
                    signer.public_key.verify_signature(sig, b"NOT DATA")

        SIGNER_FOR_URI_SCHEME[CryptoSigner.FILE_URI_SCHEME] = signer_backup

    def test_generate(self):
        """Test generate and use signer (key pair) for each sslib keytype"""
        test_data = [
            (CryptoSigner.generate_rsa, "rsa", "rsassa-pss-sha256"),
            (CryptoSigner.generate_ecdsa, "ecdsa", "ecdsa-sha2-nistp256"),
            (CryptoSigner.generate_ed25519, "ed25519", "ed25519"),
        ]
        for generate, keytype, default_scheme in test_data:
            signer = generate()
            self.assertEqual(signer.public_key.keytype, keytype)
            self.assertEqual(signer.public_key.scheme, default_scheme)

            sig = signer.sign(b"DATA")
            self.assertIsNone(signer.public_key.verify_signature(sig, b"DATA"))
            with self.assertRaises(UnverifiedSignatureError):
                signer.public_key.verify_signature(sig, b"NOT DATA")


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
