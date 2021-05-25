#!/usr/bin/env/ python

"""
<Program Name>
  test_ecdsa_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  November 23, 2016.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_ecdsa_keys.py.
"""

import unittest
import os

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.ecdsa_keys
import securesystemslib.rsa_keys


public, private = securesystemslib.ecdsa_keys.generate_public_and_private()
FORMAT_ERROR_MSG = 'securesystemslib.exceptions.FormatError raised.  Check object\'s format.'


class TestECDSA_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_public_and_private(self):
    public, private = securesystemslib.ecdsa_keys.generate_public_and_private()

    # Check format of 'public' and 'private'.
    self.assertEqual(True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(public))
    self.assertEqual(True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(private))

    # Test for invalid argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
      securesystemslib.ecdsa_keys.generate_public_and_private, 'bad_algo')


  def test_create_ecdsa_public_and_private_from_pem(self):
    global public
    global private

    # Check format of 'public' and 'private'.
    self.assertEqual(True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(public))
    self.assertEqual(True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(private))

    # Check for a valid private pem.
    public, private = \
      securesystemslib.ecdsa_keys.create_ecdsa_public_and_private_from_pem(private)

    # Check for an invalid pem (non-private).
    self.assertRaises(securesystemslib.exceptions.CryptoError,
      securesystemslib.ecdsa_keys.create_ecdsa_public_and_private_from_pem,
      public)

    # Test for invalid argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
      securesystemslib.ecdsa_keys.create_ecdsa_public_and_private_from_pem,
      123)


  def test_create_signature(self):
    global public
    global private
    data = b'The quick brown fox jumps over the lazy dog'
    signature, method = securesystemslib.ecdsa_keys.create_signature(public,
        private, data)

    # Verify format of returned values.
    self.assertEqual(True,
        securesystemslib.formats.ECDSASIGNATURE_SCHEMA.matches(signature))

    self.assertEqual(True, securesystemslib.formats.NAME_SCHEMA.matches(method))
    self.assertEqual('ecdsa-sha2-nistp256', method)

    # Check for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ecdsa_keys.create_signature, 123, private, data)

    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ecdsa_keys.create_signature, public, 123, data)

    # Check for invalid 'data'.
    self.assertRaises(securesystemslib.exceptions.CryptoError,
        securesystemslib.ecdsa_keys.create_signature, public, private, 123)


  def test_verify_signature(self):
    global public
    global private
    data = b'The quick brown fox jumps over the lazy dog'
    scheme = 'ecdsa-sha2-nistp256'
    signature, scheme = securesystemslib.ecdsa_keys.create_signature(public,
        private, data, scheme)

    valid_signature = securesystemslib.ecdsa_keys.verify_signature(public,
        scheme, signature, data)
    self.assertEqual(True, valid_signature)

    # Generate an RSA key so that we can verify that non-ECDSA keys are
    # rejected.
    rsa_pem, junk = securesystemslib.rsa_keys.generate_rsa_public_and_private()

    # Verify that a non-ECDSA key (via the PEM argument) is rejected.
    self.assertRaises(securesystemslib.exceptions.FormatError,
      securesystemslib.ecdsa_keys.verify_signature, rsa_pem, scheme, signature,
      data)

    # Check for improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ecdsa_keys.verify_signature, 123, scheme,
        signature, data)

    # Signature method improperly formatted.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ecdsa_keys.verify_signature, public, 123,
        signature, data)

    # Invalid signature method.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ecdsa_keys.verify_signature, public,
        'unsupported_scheme', signature, data)

    # Signature not a string.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ecdsa_keys.verify_signature, public, scheme,
        123, data)

    # Invalid signature..
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ecdsa_keys.verify_signature, public, scheme,
        'bad_signature', data)

    # Check for invalid signature and data.
    self.assertEqual(False, securesystemslib.ecdsa_keys.verify_signature(public,
        scheme, signature, b'123'))

    # Mismatched signature.
    bad_signature = b'a'*64
    self.assertEqual(False, securesystemslib.ecdsa_keys.verify_signature(public,
        scheme, bad_signature, data))

    # Generated signature created with different data.
    new_signature, scheme = securesystemslib.ecdsa_keys.create_signature(public,
        private, b'mismatched data')

    self.assertEqual(False, securesystemslib.ecdsa_keys.verify_signature(public,
        scheme, new_signature, data))



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
