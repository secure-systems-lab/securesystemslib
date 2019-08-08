#!/usr/bin/env python

"""
<Program Name>
  test_interface.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 5, 2017.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'interface.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import time
import datetime
import logging
import tempfile
import json
import shutil
import stat
import sys
import unittest

# Use external backport 'mock' on versions under 3.3
if sys.version_info >= (3, 3):
  import unittest.mock as mock

else:
  import mock

import securesystemslib.formats
import securesystemslib.formats
import securesystemslib.hash
import securesystemslib.interface as interface

import six

logger = logging.getLogger('securesystemslib_test_interface')



class TestInterfaceFunctions(unittest.TestCase):
  @classmethod
  def setUpClass(cls):

    # setUpClass() is called before tests in an individual class are executed.

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownClass() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())



  @classmethod
  def tearDownClass(cls):

    # tearDownModule() is called after all the tests have run.
    # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
    shutil.rmtree(cls.temporary_directory)


  def setUp(self):
    pass


  def tearDown(self):
    pass


  def test_generate_and_write_rsa_keypair(self):

    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_keypath = os.path.join(temporary_directory, 'rsa_key')
    test_keypath_unencrypted = os.path.join(temporary_directory,
        'rsa_key_unencrypted')

    returned_path = interface.generate_and_write_rsa_keypair(test_keypath,
        password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))
    self.assertEqual(returned_path, test_keypath)

    # If an empty string is given for 'password', the private key file
    # is written to disk unencrypted.
    interface.generate_and_write_rsa_keypair(test_keypath_unencrypted,
        password='')
    self.assertTrue(os.path.exists(test_keypath_unencrypted))
    self.assertTrue(os.path.exists(test_keypath_unencrypted + '.pub'))

    # Ensure the generated key files are importable.
    scheme = 'rsassa-pss-sha256'
    imported_pubkey = \
      interface.import_rsa_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(imported_pubkey))

    imported_privkey = interface.import_rsa_privatekey_from_file(test_keypath,
      'pw')
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(imported_privkey))

    # Try to import the unencrypted key file, by not passing a password
    imported_privkey = interface.import_rsa_privatekey_from_file(test_keypath_unencrypted)
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(imported_privkey))

    # Try to import the unencrypted key file, by entering an empty password
    with mock.patch('securesystemslib.interface.get_password',
        return_value=''):
      imported_privkey = \
            interface.import_rsa_privatekey_from_file(test_keypath_unencrypted,
                                                      prompt=True)
      self.assertTrue(
          securesystemslib.formats.RSAKEY_SCHEMA.matches(imported_privkey))

    # Fail importing unencrypted key passing a password
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_rsa_privatekey_from_file(test_keypath_unencrypted, 'pw')

    # Fail importing encrypted key passing no password
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_rsa_privatekey_from_file(test_keypath)

    # Custom 'bits' argument.
    os.remove(test_keypath)
    os.remove(test_keypath + '.pub')
    interface.generate_and_write_rsa_keypair(test_keypath, bits=2048,
        password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))

    # Test for a default filepath.  If 'filepath' is not given, the key's
    # KEYID is used as the filename.  The key is saved to the current working
    # directory.
    default_keypath = interface.generate_and_write_rsa_keypair(password='pw')
    self.assertTrue(os.path.exists(default_keypath))
    self.assertTrue(os.path.exists(default_keypath + '.pub'))

    written_key = interface.import_rsa_publickey_from_file(default_keypath + '.pub')
    self.assertEqual(written_key['keyid'], os.path.basename(default_keypath))

    os.remove(default_keypath)
    os.remove(default_keypath + '.pub')

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
      interface.generate_and_write_rsa_keypair, 3, bits=2048, password='pw')
    self.assertRaises(securesystemslib.exceptions.FormatError,
      interface.generate_and_write_rsa_keypair, test_keypath, bits='bad',
      password='pw')
    self.assertRaises(securesystemslib.exceptions.FormatError,
      interface.generate_and_write_rsa_keypair, test_keypath, bits=2048,
      password=3)


    # Test invalid 'bits' argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
      interface.generate_and_write_rsa_keypair, test_keypath, bits=1024,
      password='pw')



  def test_import_rsa_privatekey_from_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)

    # Load one of the pre-generated key files from
    # 'securesystemslib/tests/repository_data'.  'password' unlocks the
    # pre-generated key files.
    key_filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
        'data', 'keystore', 'rsa_key')
    self.assertTrue(os.path.exists(key_filepath))

    imported_rsa_key = interface.import_rsa_privatekey_from_file(
        key_filepath, 'password')
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(imported_rsa_key))

    # Test load encrypted key prompt for password
    with mock.patch('securesystemslib.interface.get_password',
        return_value='password'):
      imported_rsa_key = interface.import_rsa_privatekey_from_file(
          key_filepath, prompt=True)
      self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(
          imported_rsa_key))

    # Test improperly formatted 'filepath' argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_rsa_privatekey_from_file, 3, 'pw')

    # Test improperly formatted 'password' argument.
    with self.assertRaises(securesystemslib.exceptions.FormatError):
      interface.import_rsa_privatekey_from_file(key_filepath, 123)

    # Test unallowed empty 'password'
    with self.assertRaises(ValueError):
      interface.import_rsa_privatekey_from_file(key_filepath, '')

    # Test unallowed passing 'prompt' and 'password'
    with self.assertRaises(ValueError):
      interface.import_rsa_privatekey_from_file(key_filepath,
          password='pw', prompt=True)

    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(IOError, interface.import_rsa_privatekey_from_file,
        nonexistent_keypath, 'pw')

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')
    self.assertRaises(securesystemslib.exceptions.CryptoError,
        interface.import_rsa_privatekey_from_file, invalid_keyfile, 'pw')



  def test_import_rsa_publickey_from_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)

    # Load one of the pre-generated key files from 'securesystemslib/tests/data'.
    key_filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
        'data', 'keystore', 'rsa_key.pub')
    self.assertTrue(os.path.exists(key_filepath))

    imported_rsa_key = interface.import_rsa_publickey_from_file(key_filepath)
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(imported_rsa_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_rsa_privatekey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(IOError, interface.import_rsa_publickey_from_file,
        nonexistent_keypath)

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')
    self.assertRaises(securesystemslib.exceptions.Error,
        interface.import_rsa_publickey_from_file, invalid_keyfile)



  def test_generate_and_write_ed25519_keypair(self):

    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_keypath = os.path.join(temporary_directory, 'ed25519_key')
    test_keypath_unencrypted = os.path.join(temporary_directory,
                                            'ed25519_key_unencrypted')

    returned_path = interface.generate_and_write_ed25519_keypair(
        test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))
    self.assertEqual(returned_path, test_keypath)

    # If an empty string is given for 'password', the private key file
    # is written to disk unencrypted.
    interface.generate_and_write_ed25519_keypair(test_keypath_unencrypted,
                                                 password='')
    self.assertTrue(os.path.exists(test_keypath_unencrypted))
    self.assertTrue(os.path.exists(test_keypath_unencrypted + '.pub'))

    # Ensure the generated key files are importable.
    imported_pubkey = \
      interface.import_ed25519_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA\
                    .matches(imported_pubkey))

    imported_privkey = \
      interface.import_ed25519_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA\
                    .matches(imported_privkey))

    # Fail importing encrypted key passing password and prompt
    with self.assertRaises(ValueError):
      interface.import_ed25519_privatekey_from_file(test_keypath,
                                                    password='pw',
                                                    prompt=True)

    # Fail importing encrypted key passing an empty string for passwd 
    with self.assertRaises(ValueError):
      interface.import_ed25519_privatekey_from_file(test_keypath,
                                                    password='')

    # Try to import the unencrypted key file, by not passing a password
    imported_privkey = \
        interface.import_ed25519_privatekey_from_file(test_keypath_unencrypted)
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA.\
                    matches(imported_privkey))

    # Try to import the unencrypted key file, by entering an empty password
    with mock.patch('securesystemslib.interface.get_password',
        return_value=''):
      imported_privkey = \
        interface.import_ed25519_privatekey_from_file(test_keypath_unencrypted,
                                                      prompt=True)
      self.assertTrue(
          securesystemslib.formats.ED25519KEY_SCHEMA.matches(imported_privkey))

    # Fail importing unencrypted key passing a password
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_ed25519_privatekey_from_file(test_keypath_unencrypted,
                                                    'pw')

    # Fail importing encrypted key passing no password
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_ed25519_privatekey_from_file(test_keypath)

    # Test for a default filepath.  If 'filepath' is not given, the key's
    # KEYID is used as the filename.  The key is saved to the current working
    # directory.
    default_keypath = interface.generate_and_write_ed25519_keypair(password='pw')
    self.assertTrue(os.path.exists(default_keypath))
    self.assertTrue(os.path.exists(default_keypath + '.pub'))

    written_key = interface.import_ed25519_publickey_from_file(default_keypath + '.pub')
    self.assertEqual(written_key['keyid'], os.path.basename(default_keypath))

    os.remove(default_keypath)
    os.remove(default_keypath + '.pub')


    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_ed25519_keypair, 3, password='pw')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_rsa_keypair, test_keypath, password=3)



  def test_import_ed25519_publickey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key')
    interface.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')

    imported_ed25519_key = \
      interface.import_ed25519_publickey_from_file(ed25519_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_publickey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(IOError, interface.import_ed25519_publickey_from_file,
        nonexistent_keypath)

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
        interface.import_ed25519_publickey_from_file, invalid_keyfile)

    # Invalid public key imported (contains unexpected keytype.)
    keytype = imported_ed25519_key['keytype']
    keyval = imported_ed25519_key['keyval']
    scheme = imported_ed25519_key['scheme']

    ed25519key_metadata_format = \
      securesystemslib.keys.format_keyval_to_metadata(keytype, scheme,
      keyval, private=False)

    ed25519key_metadata_format['keytype'] = 'invalid_keytype'
    with open(ed25519_keypath + '.pub', 'wb') as file_object:
      file_object.write(json.dumps(ed25519key_metadata_format).encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_publickey_from_file,
        ed25519_keypath + '.pub')



  def test_import_ed25519_privatekey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    scheme = 'ed25519'
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key')
    interface.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')

    imported_ed25519_key = \
      interface.import_ed25519_privatekey_from_file(ed25519_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(IOError, interface.import_ed25519_privatekey_from_file,
        nonexistent_keypath, 'pw')

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
      interface.import_ed25519_privatekey_from_file, invalid_keyfile, 'pw')

    # Invalid private key imported (contains unexpected keytype.)
    imported_ed25519_key['keytype'] = 'invalid_keytype'

    # Use 'pyca_crypto_keys.py' to bypass the key format validation performed
    # by 'keys.py'.
    salt, iterations, derived_key = \
      securesystemslib.pyca_crypto_keys._generate_derived_key('pw')

    # Store the derived key info in a dictionary, the object expected
    # by the non-public _encrypt() routine.
    derived_key_information = {'salt': salt, 'iterations': iterations,
        'derived_key': derived_key}

    # Convert the key object to json string format and encrypt it with the
    # derived key.
    encrypted_key = \
      securesystemslib.pyca_crypto_keys._encrypt(json.dumps(imported_ed25519_key),
          derived_key_information)

    with open(ed25519_keypath, 'wb') as file_object:
      file_object.write(encrypted_key.encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_privatekey_from_file, ed25519_keypath, 'pw')



  def test_generate_and_write_ecdsa_keypair(self):

    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_keypath = os.path.join(temporary_directory, 'ecdsa_key')

    returned_path = interface.generate_and_write_ecdsa_keypair(test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))
    self.assertEqual(returned_path, test_keypath)

    # Ensure the generated key files are importable.
    imported_pubkey = \
      interface.import_ecdsa_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_pubkey))

    imported_privkey = \
      interface.import_ecdsa_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_privkey))

    # Test for a default filepath.  If 'filepath' is not given, the key's
    # KEYID is used as the filename.  The key is saved to the current working
    # directory.
    default_keypath = interface.generate_and_write_ecdsa_keypair(password='pw')
    self.assertTrue(os.path.exists(default_keypath))
    self.assertTrue(os.path.exists(default_keypath + '.pub'))

    written_key = interface.import_ecdsa_publickey_from_file(default_keypath + '.pub')
    self.assertEqual(written_key['keyid'], os.path.basename(default_keypath))

    os.remove(default_keypath)
    os.remove(default_keypath + '.pub')

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_ecdsa_keypair, 3, password='pw')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_ecdsa_keypair, test_keypath, password=3)



  def test_import_ecdsa_publickey_from_file(self):
    # Test normal case.
    # Generate ecdsa keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ecdsa_keypath = os.path.join(temporary_directory, 'ecdsa_key')
    interface.generate_and_write_ecdsa_keypair(ecdsa_keypath, password='pw')

    imported_ecdsa_key = \
      interface.import_ecdsa_publickey_from_file(ecdsa_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_ecdsa_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_publickey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(IOError, interface.import_ecdsa_publickey_from_file,
        nonexistent_keypath)

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
        interface.import_ecdsa_publickey_from_file, invalid_keyfile)

    # Invalid public key imported (contains unexpected keytype.)
    keytype = imported_ecdsa_key['keytype']
    keyval = imported_ecdsa_key['keyval']
    scheme = imported_ecdsa_key['scheme']

    ecdsakey_metadata_format = \
      securesystemslib.keys.format_keyval_to_metadata(keytype,
          scheme, keyval, private=False)

    ecdsakey_metadata_format['keytype'] = 'invalid_keytype'
    with open(ecdsa_keypath + '.pub', 'wb') as file_object:
      file_object.write(json.dumps(ecdsakey_metadata_format).encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_publickey_from_file,
        ecdsa_keypath + '.pub')



  def test_import_ecdsa_privatekey_from_file(self):
    # Test normal case.
    # Generate ecdsa keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ecdsa_keypath = os.path.join(temporary_directory, 'ecdsa_key')
    interface.generate_and_write_ecdsa_keypair(ecdsa_keypath, password='pw')

    imported_ecdsa_key = \
      interface.import_ecdsa_privatekey_from_file(ecdsa_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_ecdsa_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory, 'nonexistent_keypath')
    self.assertRaises(IOError, interface.import_ecdsa_privatekey_from_file,
        nonexistent_keypath, 'pw')

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
      interface.import_ecdsa_privatekey_from_file, invalid_keyfile, 'pw')

    # Invalid private key imported (contains unexpected keytype.)
    imported_ecdsa_key['keytype'] = 'invalid_keytype'

    # Use 'pyca_crypto_keys.py' to bypass the key format validation performed
    # by 'keys.py'.
    salt, iterations, derived_key = \
      securesystemslib.pyca_crypto_keys._generate_derived_key('pw')

    # Store the derived key info in a dictionary, the object expected
    # by the non-public _encrypt() routine.
    derived_key_information = {'salt': salt, 'iterations': iterations,
        'derived_key': derived_key}

    # Convert the key object to json string format and encrypt it with the
    # derived key.
    encrypted_key = \
      securesystemslib.pyca_crypto_keys._encrypt(json.dumps(imported_ecdsa_key),
          derived_key_information)

    with open(ecdsa_keypath, 'wb') as file_object:
      file_object.write(encrypted_key.encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_privatekey_from_file, ecdsa_keypath, 'pw')


# Run the test cases.
if __name__ == '__main__':
  unittest.main()
