#!/usr/bin/env python
"""
<Program Name>
  check_public_interfaces_gpg.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Feb 26, 2020.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Check that the public facing 'gpg.functions' module remains importable if
  gnupg is not installed, and that each function presents meaningful
  user-feedback.
  Further check that gpg signature verification works even without gpg.

  NOTE: the filename is purposefully check_ rather than test_ so that test
  discovery doesn't find this test module and the test cases within are only
  run when explicitly invoked.

"""

import unittest
from securesystemslib.gpg.constants import HAVE_GPG, NO_GPG_MSG
from securesystemslib.gpg.util import get_version
from securesystemslib.gpg.functions import (
    create_signature, export_pubkey, export_pubkeys, verify_signature)

from securesystemslib.exceptions import UnsupportedLibraryError


class TestPublicInterfacesGPG(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    assert not HAVE_GPG, \
        "please remove GnuPG from your environment to run this test case"

  def test_gpg_functions(self):
    """Signing, key export and util functions must raise on missing gpg. """
    with self.assertRaises(UnsupportedLibraryError) as ctx:
      create_signature('bar')
    self.assertEqual(NO_GPG_MSG, str(ctx.exception))

    with self.assertRaises(UnsupportedLibraryError) as ctx:
      export_pubkey('f00')
    self.assertEqual(NO_GPG_MSG, str(ctx.exception))

    with self.assertRaises(UnsupportedLibraryError) as ctx:
      export_pubkeys(['f00'])
    self.assertEqual(NO_GPG_MSG, str(ctx.exception))

    with self.assertRaises(UnsupportedLibraryError) as ctx:
      get_version()
    self.assertEqual(NO_GPG_MSG, str(ctx.exception))

  def test_gpg_verify(self):
    """Signature verification does not require gpg to be installed on the host.
    To prove it, we run basic verification tests for rsa, dsa and eddsa with
    pre-generated/exported signatures and keys. More thorough testing is
    available in test_gpg.py

    """
    data = b"deadbeef"
    key_signature_pairs = [
        # RSA
        ({'method': 'pgp+rsa-pkcsv1.5', 'type': 'rsa', 'hashes': ['pgp+SHA2'], 'creation_time': 1519661780, 'keyid': 'c5a0abe6ec19d0d65f85e2c39be9df5131d924e9', 'keyval': {'private': '', 'public': {'e': '010001', 'n': 'c152fc1f1535a6d3c1e8c0dece7f0a1d09324466e10e4ea51d5d7223ab125c1743393eebca73ccb1022d44c379fae30ef63b263d0a793882a7332ef06f28a4b9ae777f5d2d8d289167e86c162df1b9a9e127acb26803688556ecb08492d071f06caf88cea95571354349d8ef131eff03b0d259fae30ebf8dac9ab5acd6f26f4770fe2f30fcd0a3c54f03463a3094aa6524e39027a625108f04e12475da248fb3b536df61b0f6e2954739b8828c61171f66f8e176823e1c887e65fa0aec081013b2a50ed60515f7e3b3291ca443e1222b9b625005dba045a7208188fb88d436d473f6340348953e891354c7a5734bf64e6274e196db3074a7ce3607960baacb1b'}}},
          {'keyid': 'c5a0abe6ec19d0d65f85e2c39be9df5131d924e9', 'other_headers': '04000108001d162104c5a0abe6ec19d0d65f85e2c39be9df5131d924e905025e56444b', 'signature': 'bc4490901bd6edfe0ec49e0358c0a7ef37fc229824ca75dd4f163205745c78baaa2ca5cda79be259a5ac8323b4c1a1ee18fab0a8cc90eeafeb3eb1221d4bafb55510f34cf99e7ac121874f3c01152d6d8953c661c3e5147a387fffaee672318ed39c49fa02c80fa806956695f2fdfe0429a61639e7fb544f1531100eb02b7a140ffa284746fa1620e8461e4af5f93594f8aed6d34a33d51b265bae90ea8bedccb7497594003eb46516bddb1778a4fadd02cbb227e1931eeb5ef445fb9745f85cfbebfa169c3ae7d15e2ca75b15dd020877c9a968ff853993a06420d3c3ff158800014f21e558103cd4e7e84cf5e320ebf7c525e0eab9ab22ad4af02c7ad48b5e'}),
        # DSA
        ({'method': 'pgp+dsa-fips-180-2', 'type': 'dsa', 'hashes': ['pgp+SHA2'], 'creation_time': 1510870182, 'keyid': 'c242a830daaf1c2bef604a9ef033a3a3e267b3b1', 'keyval': {'private': '', 'public': {'y': '2dd50b2292441444581f9a0b7d8d7f88b573fc451f5e7207c324694232c22e171b508f6842ae9babc56fe4e586a22086188b4827b7aba8c7bff4a4ac9aa80c835420b1afba4ab4f1b1c0ef894437903a9f4c56ebef037804a99925c9a153b8a16c1562f297755aeaa20fa02ab32aa5366e052b6baa9a934356d4f5fc218785018dd12b2c8e6d605d2afb36cb06a9cced9ea1f5f82798d635de264ef0eb59590c4a4b2fdf2369a36f95614804c7aa5966ba9597404ba2d2c6881959112de52de4b6d4f1e2c8a59ddaadb08a59ac8334118f15aa01593e851024905ea6d884c3a545af6fdd03c8d2b54da1d35e710ef75a2b4775bb78c50b28d1e2fb48416dc941', 'p': 'fca3276cd78c20e3c73ae2398674046039f5d90f41e3ede9bc99f94000d145693522671fba481d22e0a9b31e695d198da5e62f4ffb4db5dc64076d0f2d7d03ce953fc7846a6d4e17a10bf1dcd17167f7aff761b59fa2180e7fcd2ca527c03c50c78665b5539bf2b45648b6d23f31f37999e6a7b4e0876ddad7ec783b8eec7e1fb14733e74b6b0b105cbdc5a7de8e094657f2146ce43a3177581cb022a4e2ce6678a3364a56e02090559a6dfd81d91ca3b7c6afd4fcfc66fd88339d217062462f51c5c91d6eccfafb32065be68e6b91ec837c59a51baebeca1c70fd3891c9bbb67f7d920f9153fc4d2ca03f88a27b70df1684709f99ad18707189b015441b2bfb', 'g': '7f7252ae1824baf2be5fc8f431a1978683a38d4a22cc2bcdc01ccd1f5eee47a964aa57639a618cfb1b10707b4d09ff11a448e83ba70123573f2d49a599f5313a74463e5bb3ca3d6172a00f02b01065ce312501e1797f7b57e606947c44bd839fde8d43269f1fb74af6cedf4db7fabf0b2357ed09d56381ac769ef5a8af1b4450e0c88b64ee1cab9fadeb31b7be6207b7e17008a33a7613831f70a123d59279dcbc2238f46eeaa8097795b7805f1b837ef3b8e807164e186fae9fa3ff510213096bf54040eac545a6a5b47c910e6cf7e306e1f46723f14b02cd9e0b0ff2a56c3b2604869431ab3263d61bf5068bee36c880c7bf2c746dcae5d0d7b2fff244ef43', 'q': '84779eeae0238d7a9a030a639bf01a0f9ef517a5d950599c19a4e54fbbf23219'}}},
          {'keyid': 'c242a830daaf1c2bef604a9ef033a3a3e267b3b1', 'other_headers': '04001108001d162104c242a830daaf1c2bef604a9ef033a3a3e267b3b105025e5644d1', 'signature': '3044022009e95f952f64f559852fb6b321173f3cb142a5dbe0c84d709d55026ab945582802203144ee0f4c2cb70fa00ca6942c847208b96811271445ed85c75ebebdb609b174'}),
        # EDDSA
        ({'method': 'pgp+eddsa-ed25519', 'type': 'eddsa', 'hashes': ['pgp+SHA2'], 'creation_time': 1572269200, 'keyid': '4e630f84838bf6f7447b830b22692f5fea9e2dd2', 'keyval': {'private': '', 'public': {'q': '716e57b8c5d4397a4194f80bd43af2e07691db7ee58d2473ceb56cef1eda7569'}}},
          {'keyid': '4e630f84838bf6f7447b830b22692f5fea9e2dd2', 'other_headers': '04001608001d1621044e630f84838bf6f7447b830b22692f5fea9e2dd205025e564505', 'signature': '70ba3fe785bccac105b837b6b27cc8d5ddd0159c3f640bbac026b744e0b10839bf4ea53e786074d32f9617389a4fe3356ec1c4a19045c5c02821563786e1d10d'})
      ]

    for key, sig in key_signature_pairs:
      self.assertTrue(verify_signature(sig, key, data))


if __name__ == "__main__":
  unittest.main(verbosity=1, buffer=True)
