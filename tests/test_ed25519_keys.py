#!/usr/bin/env/ python

"""
<Program Name>
  test_ed25519_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 11, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_ed25519_keys.py.
"""

import unittest
import os

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.ed25519_keys


public, private = securesystemslib.ed25519_keys.generate_public_and_private()
FORMAT_ERROR_MSG = 'securesystemslib.exceptions.FormatError raised.  Check object\'s format.'


class TestEd25519_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_public_and_private(self):
    pub, priv = securesystemslib.ed25519_keys.generate_public_and_private()

    # Check format of 'pub' and 'priv'.
    self.assertEqual(True, securesystemslib.formats.ED25519PUBLIC_SCHEMA.matches(pub))
    self.assertEqual(True, securesystemslib.formats.ED25519SEED_SCHEMA.matches(priv))



  def test_create_signature(self):
    global public
    global private
    data = b'The quick brown fox jumps over the lazy dog'
    scheme = 'ed25519'
    signature, scheme = securesystemslib.ed25519_keys.create_signature(public,
        private, data, scheme)

    # Verify format of returned values.
    self.assertEqual(True,
        securesystemslib.formats.ED25519SIGNATURE_SCHEMA.matches(signature))

    self.assertEqual(True, securesystemslib.formats.ED25519_SIG_SCHEMA.matches(scheme))
    self.assertEqual('ed25519', scheme)

    # Check for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ed25519_keys.create_signature, 123, private, data,
        scheme)

    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ed25519_keys.create_signature, public, 123, data,
        scheme)

    # Check for invalid 'data'.
    self.assertRaises(securesystemslib.exceptions.CryptoError,
        securesystemslib.ed25519_keys.create_signature, public, private, 123,
        scheme)


  def test_verify_signature(self):
    global public
    global private
    data = b'The quick brown fox jumps over the lazy dog'
    scheme = 'ed25519'
    signature, scheme = securesystemslib.ed25519_keys.create_signature(public,
        private, data, scheme)

    valid_signature = securesystemslib.ed25519_keys.verify_signature(public,
        scheme, signature, data)
    self.assertEqual(True, valid_signature)

    bad_signature = os.urandom(64)
    valid_signature = securesystemslib.ed25519_keys.verify_signature(public,
        scheme, bad_signature, data)
    self.assertEqual(False, valid_signature)



    # Check for improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ed25519_keys.verify_signature, 123, scheme,
        signature, data)

    # Signature method improperly formatted.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ed25519_keys.verify_signature, public, 123,
        signature, data)

    # Invalid signature method.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ed25519_keys.verify_signature, public,
        'unsupported_scheme', signature, data)

    # Signature not a string.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ed25519_keys.verify_signature, public, scheme,
        123, data)

    # Invalid signature length, which must be exactly 64 bytes..
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.ed25519_keys.verify_signature, public, scheme,
        'bad_signature', data)

    # Check for invalid signature and data.
    # Mismatched data.
    self.assertEqual(False, securesystemslib.ed25519_keys.verify_signature(
        public, scheme, signature, b'123'))

    # Mismatched signature.
    bad_signature = b'a'*64
    self.assertEqual(False, securesystemslib.ed25519_keys.verify_signature(
        public, scheme, bad_signature, data))

    # Generated signature created with different data.
    new_signature, scheme = securesystemslib.ed25519_keys.create_signature(
        public, private, b'mismatched data', scheme)

    self.assertEqual(False, securesystemslib.ed25519_keys.verify_signature(
        public, scheme, new_signature, data))



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
