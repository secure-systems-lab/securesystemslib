#!/usr/bin/env python

"""
<Program Name>
  check_public_interfaces.py

<Author>
  Joshua Lock <jlock@vmware.com>

<Started>
  January 6, 2020.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Public facing modules (e.g. interface.py and keys.py) must be
  importable, even if the optional dependencies are not installed.

  Each public facing function should always be callable and present
  meaningful user-feedback if an optional dependency that is required for
  that function is not installed.

  This test purposefully only checks the public functions with a native
  dependency, to avoid duplicated tests.

  NOTE: the filename is purposefully check_ rather than test_ so that test
  discovery doesn't find this unittest and the tests within are only run
  when explicitly invoked.
"""

import inspect
import json
import os
import shutil
import sys
import tempfile
import unittest

if sys.version_info >= (3, 3):
  import unittest.mock as mock
else:
  import mock

import securesystemslib.exceptions
import securesystemslib.gpg.constants
import securesystemslib.gpg.functions
import securesystemslib.gpg.util
import securesystemslib.interface
import securesystemslib.keys



class TestPublicInterfaces(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.temp_dir = tempfile.mkdtemp(dir=os.getcwd())

  @classmethod
  def tearDownClass(cls):
    shutil.rmtree(cls.temp_dir)

  def test_interface(self):

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface._generate_and_write_rsa_keypair(password='pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface.generate_and_write_rsa_keypair('pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface.generate_and_write_rsa_keypair('pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      # Mock entry on prompt which is presented before lower-level functions
      # raise UnsupportedLibraryError
      with mock.patch("securesystemslib.interface.get_password", return_value=""):
        securesystemslib.interface.generate_and_write_rsa_keypair_with_prompt()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface.generate_and_write_unencrypted_rsa_keypair()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      path = os.path.join(self.temp_dir, 'rsa_key')
      with open(path, 'a'):
        securesystemslib.interface.import_rsa_privatekey_from_file(
            path)

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface._generate_and_write_ed25519_keypair(
          password='pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface.generate_and_write_ed25519_keypair('pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      # Mock entry on prompt which is presented before lower-level functions
      # raise UnsupportedLibraryError
      with mock.patch("securesystemslib.interface.get_password", return_value=""):
        securesystemslib.interface.generate_and_write_ed25519_keypair_with_prompt()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface.generate_and_write_unencrypted_ed25519_keypair()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      path = os.path.join(self.temp_dir, 'ed25519_priv.json')
      with open(path, 'a') as f:
        f.write('{}')
        securesystemslib.interface.import_ed25519_privatekey_from_file(
            path, 'pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface._generate_and_write_ecdsa_keypair(
          password='pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface.generate_and_write_ecdsa_keypair('pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      # Mock entry on prompt which is presented before lower-level functions
      # raise UnsupportedLibraryError
      with mock.patch("securesystemslib.interface.get_password", return_value=""):
        securesystemslib.interface.generate_and_write_ecdsa_keypair_with_prompt()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.interface.generate_and_write_unencrypted_ecdsa_keypair()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      path = os.path.join(self.temp_dir, 'ecddsa.priv')
      with open(path, 'a') as f:
        f.write('{}')
        securesystemslib.interface.import_ecdsa_privatekey_from_file(
            path, password='pw')


  def test_keys(self):
    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.generate_rsa_key()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.generate_ecdsa_key()

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.generate_ed25519_key()

    data = 'foo'
    keydict = {'keytype': 'ed25519',
               'scheme': 'ed25519',
               'keyid': 'f00',
               'keyval': {'private': 'f001',
                          'public': 'b00f'}}
    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.create_signature(keydict, data)

    keydict['keytype'] = 'ecdsa'
    keydict['scheme'] = 'ecdsa-sha2-nistp256'
    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.create_signature(keydict, data)

    keydict['keytype'] = 'rsa'
    keydict['scheme'] = 'rsassa-pss-sha256'
    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.create_signature(keydict, data)

    keydict['keytype'] = 'ecdsa'
    keydict['scheme'] = 'ecdsa-sha2-nistp256'
    sig = {'keyid': 'f00',
           'sig': 'cfbce8e23eef478975a4339036de2335002d57c7b1632dd01e526a3bc52a5b261508ad50b9e25f1b819d61017e7347e912db1af019bf47ee298cc58bbdef9703'}
    # NOTE: we don't test ed25519 keys as they can be verified in pure python
    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.verify_signature(keydict, sig, data)

    keydict['keytype'] = 'rsa'
    keydict['scheme'] = 'rsassa-pss-sha256'
    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.verify_signature(keydict, sig, data)

    priv = '-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n'

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.import_rsakey_from_private_pem('')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.encrypt_key(keydict, 'foo')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.decrypt_key('enc', 'pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.create_rsa_encrypted_pem(priv, 'pw')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.import_ed25519key_from_private_json(
          ''.encode('utf-8'), '')

    with self.assertRaises(
          securesystemslib.exceptions.UnsupportedLibraryError):
      securesystemslib.keys.import_ecdsakey_from_private_pem(priv)

  def test_purepy_ed25519(self):
    data = b'The quick brown fox jumps over the lazy dog'
    pub = b'\xbe\xb7\\&\x82\x06UN\x96<E\xdc\xbf<\x00A@\xd1\xcbi\xbb\xfe\x93p\xefso\x198\x8c\x9b&'
    sig = b'.\xc7\xa5\xe2\x95\xfabe\xe1\x0f=\xa7\xf1\xa42\xe7t/\x04\x1f\x08\x1bO\xae\xca\xb3\xa1+\xf0\xfc\x8f6l\x91\x9c\x90\xc2g\xe9\xed\x1d\xfd\xebzuV\xb9Y\xa9m\xd0\xdc\xfe\xa1}\xa3Xb-9\xaf6\xbf\t'

    valid = securesystemslib.ed25519_keys.verify_signature(
        pub, 'ed25519', sig, data)
    self.assertEqual(True, valid)

    bsig = b'\xd3/\x7f\x7f\xa5;6Pq\x14f]\x8b\x0e@\x8a:\xc2\xa1\xb8\xee\x11\xef\x06s\x12\xa9\x0b0\xe9@\xd5Q\xb6\xf7\xe7\xb9\xf6\xc7J\x99_L\x01\xf7\xcdi\x05\xea\xdf\x05D\x12\x1f\xeeT\xe1y\xb1\x9a\x8e\xebS\x04'
    invalid = securesystemslib.ed25519_keys.verify_signature(
        pub, 'ed25519', bsig, data)
    self.assertEqual(False, invalid)

  def test_gpg_functions(self):
    """Public GPG functions must raise error on missing cryptography lib. """
    expected_error = securesystemslib.exceptions.UnsupportedLibraryError
    expected_error_msg = securesystemslib.gpg.functions.NO_CRYPTO_MSG

    with self.assertRaises(expected_error) as ctx:
      securesystemslib.gpg.functions.create_signature('bar')
    self.assertEqual(expected_error_msg, str(ctx.exception))

    with self.assertRaises(expected_error) as ctx:
      securesystemslib.gpg.functions.verify_signature(None, 'f00', 'bar')
    self.assertEqual(expected_error_msg, str(ctx.exception))

    with self.assertRaises(expected_error) as ctx:
      securesystemslib.gpg.functions.export_pubkey('f00')
    self.assertEqual(expected_error_msg, str(ctx.exception))

if __name__ == "__main__":
  unittest.main(verbosity=1, buffer=True)
