#!/usr/bin/env python

"""
<Program Name>
  test_pycrypto_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 10, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_pycrypto_keys.py.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import logging

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.pycrypto_keys

logger = logging.getLogger('securesystemslib.test_pycrypto_keys')

public_rsa, private_rsa = securesystemslib.pycrypto_keys.generate_rsa_public_and_private()
FORMAT_ERROR_MSG = 'securesystemslib.exceptions.FormatError raised.  Check object\'s format.'


class TestPycrypto_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_rsa_public_and_private(self):
    pub, priv = securesystemslib.pycrypto_keys.generate_rsa_public_and_private()

    # Check format of 'pub' and 'priv'.
    self.assertEqual(None, securesystemslib.formats.PEMRSA_SCHEMA.check_match(pub),
                     FORMAT_ERROR_MSG)
    self.assertEqual(None, securesystemslib.formats.PEMRSA_SCHEMA.check_match(priv),
                     FORMAT_ERROR_MSG)

    # Check for invalid bits argument.  bit >= 2048 and a multiple of 256.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.generate_rsa_public_and_private, 1024)

    self.assertRaises(ValueError,
                      securesystemslib.pycrypto_keys.generate_rsa_public_and_private, 2049)

    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.generate_rsa_public_and_private, '2048')


  def test_create_rsa_signature(self):
    global private_rsa
    global public_rsa
    data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    signature, method = securesystemslib.pycrypto_keys.create_rsa_signature(private_rsa, data)

    # Verify format of returned values.
    self.assertNotEqual(None, signature)
    self.assertEqual(None, securesystemslib.formats.NAME_SCHEMA.check_match(method),
                     FORMAT_ERROR_MSG)
    self.assertEqual('RSASSA-PSS', method)

    # Check for improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.create_rsa_signature, 123, data)

    self.assertRaises(ValueError,
                      securesystemslib.pycrypto_keys.create_rsa_signature, '', data)

    # Check for invalid 'data'.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.create_rsa_signature, private_rsa, '')

    # Check for invalid private RSA key.
    self.assertRaises(securesystemslib.exceptions.CryptoError,
                      securesystemslib.pycrypto_keys.create_rsa_signature, 'bad_key', data)

    # create_rsa_signature should reject non-string data.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.create_rsa_signature, private_rsa, 123)

    # Check for missing private key.
    self.assertRaises(securesystemslib.exceptions.CryptoError,
                      securesystemslib.pycrypto_keys.create_rsa_signature, public_rsa, data)


  def test_verify_rsa_signature(self):
    global public_rsa
    global private_rsa
    data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    signature, method = securesystemslib.pycrypto_keys.create_rsa_signature(private_rsa, data)

    valid_signature = securesystemslib.pycrypto_keys.verify_rsa_signature(signature, method, public_rsa,
                                                data)
    self.assertEqual(True, valid_signature)

    # Check for invalid arguments that result in a failed signature
    # verification.
    self.assertRaises(securesystemslib.exceptions.CryptoError,
      securesystemslib.pycrypto_keys.verify_rsa_signature, signature, method,
      'bad_key', data)

    # Check for improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, securesystemslib.pycrypto_keys.verify_rsa_signature, signature,
                                       123, public_rsa, data)

    self.assertRaises(securesystemslib.exceptions.FormatError, securesystemslib.pycrypto_keys.verify_rsa_signature, signature,
                                       method, 123, data)

    self.assertRaises(securesystemslib.exceptions.FormatError, securesystemslib.pycrypto_keys.verify_rsa_signature, 123, method,
                                       public_rsa, data)

    self.assertRaises(securesystemslib.exceptions.UnknownMethodError, securesystemslib.pycrypto_keys.verify_rsa_signature,
                                                      signature,
                                                      'invalid_method',
                                                      public_rsa, data)

    # Check for invalid signature and data.
    # Verify_rsa_signature should reject non-string data.
    self.assertRaises(securesystemslib.exceptions.FormatError, securesystemslib.pycrypto_keys.verify_rsa_signature, signature,
                                       method, public_rsa, 123)

    self.assertEqual(False, securesystemslib.pycrypto_keys.verify_rsa_signature(signature, method,
                            public_rsa, b'mismatched data'))

    mismatched_signature, method = securesystemslib.pycrypto_keys.create_rsa_signature(private_rsa,
                                                             b'mismatched data')

    self.assertEqual(False, securesystemslib.pycrypto_keys.verify_rsa_signature(mismatched_signature,
                            method, public_rsa, data))


  def test_create_rsa_encrypted_pem(self):
    global public_rsa
    global private_rsa
    passphrase = 'pw'

    # Check format of 'public_rsa'.
    self.assertEqual(None, securesystemslib.formats.PEMRSA_SCHEMA.check_match(public_rsa),
                     FORMAT_ERROR_MSG)

    # Check format of 'passphrase'.
    self.assertEqual(None, securesystemslib.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Generate the encrypted PEM string of 'public_rsa'.
    pem_rsakey = securesystemslib.pycrypto_keys.create_rsa_encrypted_pem(private_rsa, passphrase)

    # Check format of 'pem_rsakey'.
    self.assertEqual(None, securesystemslib.formats.PEMRSA_SCHEMA.check_match(pem_rsakey),
                     FORMAT_ERROR_MSG)

    # Check for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.create_rsa_encrypted_pem, 1, passphrase)
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.create_rsa_encrypted_pem, private_rsa, ['pw'])

    self.assertRaises(securesystemslib.exceptions.CryptoError, securesystemslib.pycrypto_keys.create_rsa_encrypted_pem,
                                       'abc', passphrase)
    self.assertRaises(TypeError, securesystemslib.pycrypto_keys.create_rsa_encrypted_pem, '', passphrase)



  def test_create_rsa_public_and_private_from_pem(self):
    global private_rsa
    passphrase = 'pw'

    # Generate the encrypted PEM string of 'private_rsa'.
    pem_rsakey = securesystemslib.pycrypto_keys.create_rsa_encrypted_pem(private_rsa, passphrase)

    # Check format of 'passphrase'.
    self.assertEqual(None, securesystemslib.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Decrypt 'pem_rsakey' and verify the decrypted object is properly
    # formatted.
    public_decrypted, private_decrypted = \
    securesystemslib.pycrypto_keys.create_rsa_public_and_private_from_pem(pem_rsakey,
                                                             passphrase)
    self.assertEqual(None,
                     securesystemslib.formats.PEMRSA_SCHEMA.check_match(public_decrypted),
                     FORMAT_ERROR_MSG)

    self.assertEqual(None,
                     securesystemslib.formats.PEMRSA_SCHEMA.check_match(private_decrypted),
                     FORMAT_ERROR_MSG)

    # Does 'public_decrypted' and 'private_decrypted' match the originals?
    self.assertEqual(public_rsa, public_decrypted)
    self.assertEqual(private_rsa, private_decrypted)

    # Attempt decryption of 'pem_rsakey' using an incorrect passphrase.
    self.assertRaises(securesystemslib.exceptions.CryptoError,
                      securesystemslib.pycrypto_keys.create_rsa_public_and_private_from_pem,
                      pem_rsakey, 'bad_pw')

    # Check for non-encrypted PEM strings.
    # create_rsa_public_and_private_from_pem() returns a tuple of
    # securesystemslib.formats.PEMRSA_SCHEMA objects if the PEM formatted string is
    # not actually encrypted but still a valid PEM string.
    pub, priv = securesystemslib.pycrypto_keys.create_rsa_public_and_private_from_pem(
                              private_rsa, passphrase)
    self.assertEqual(None, securesystemslib.formats.PEMRSA_SCHEMA.check_match(pub),
                     FORMAT_ERROR_MSG)
    self.assertEqual(None, securesystemslib.formats.PEMRSA_SCHEMA.check_match(priv),
                     FORMAT_ERROR_MSG)

    # Check for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.create_rsa_public_and_private_from_pem,
                      123, passphrase)
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      securesystemslib.pycrypto_keys.create_rsa_public_and_private_from_pem,
                      pem_rsakey, ['pw'])

    self.assertRaises(securesystemslib.exceptions.CryptoError,
                      securesystemslib.pycrypto_keys.create_rsa_public_and_private_from_pem,
                      'invalid_pem', passphrase)



  def test_encrypt_key(self):
    # Test for valid arguments.
    global public_rsa
    global private_rsa
    passphrase = 'pw'

    rsa_key = {'keytype': 'rsa',
    'keyid': 'd62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d',
    'keyval': {'public': public_rsa, 'private': private_rsa}}

    encrypted_rsa_key = securesystemslib.pycrypto_keys.encrypt_key(rsa_key, passphrase)

    # Test for invalid arguments.
    rsa_key['keyval']['private'] = ''
    self.assertRaises(securesystemslib.exceptions.FormatError, securesystemslib.pycrypto_keys.encrypt_key, rsa_key,
                                       'passphrase')


  def test_decrypt_key(self):
    # Test for valid arguments.
    global public_rsa
    global private_rsa
    passphrase = 'pw'

    rsa_key = {'keytype': 'rsa',
    'keyid': 'd62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d',
    'keyval': {'public': public_rsa, 'private': private_rsa}}

    encrypted_rsa_key = securesystemslib.pycrypto_keys.encrypt_key(rsa_key, passphrase).encode('utf-8')

    decrypted_rsa_key = securesystemslib.pycrypto_keys.decrypt_key(encrypted_rsa_key, passphrase)


    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.CryptoError, securesystemslib.pycrypto_keys.decrypt_key, b'bad',
                                       passphrase)

    # Test for invalid encrypted content (i.e., invalid hmac and ciphertext.)
    encryption_delimiter = securesystemslib.pycrypto_keys._ENCRYPTION_DELIMITER
    salt, iterations, hmac, iv, ciphertext = \
      encrypted_rsa_key.decode('utf-8').split(encryption_delimiter)

    # Set an invalid hmac.  The decryption routine sould raise a
    # securesystemslib.exceptions.CryptoError exception because 'hmac' does not
    # match the hmac calculated by the decryption routine.
    bad_hmac = '12345abcd'
    invalid_encrypted_rsa_key = \
      salt + encryption_delimiter + iterations + encryption_delimiter + \
      bad_hmac + encryption_delimiter + iv + encryption_delimiter + ciphertext

    self.assertRaises(securesystemslib.exceptions.CryptoError, securesystemslib.pycrypto_keys.decrypt_key,
                      invalid_encrypted_rsa_key.encode('utf-8'), passphrase)

    # Test for invalid 'ciphertext'
    bad_ciphertext = '12345abcde'
    invalid_encrypted_rsa_key = \
      salt + encryption_delimiter + iterations + encryption_delimiter + \
      hmac + encryption_delimiter + iv + encryption_delimiter + bad_ciphertext

    self.assertRaises(securesystemslib.exceptions.CryptoError, securesystemslib.pycrypto_keys.decrypt_key,
                      invalid_encrypted_rsa_key.encode('utf-8'), passphrase)



  def test__decrypt_key(self):
    # Test for invalid arguments.
    salt, iterations, derived_key = securesystemslib.pycrypto_keys._generate_derived_key('pw')
    derived_key_information = {'salt': salt, 'derived_key': derived_key,
                               'iterations': iterations}

    self.assertRaises(securesystemslib.exceptions.CryptoError, securesystemslib.pycrypto_keys._encrypt,
                          8, derived_key_information)




# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
