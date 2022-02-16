#!/usr/bin/env python

"""
<Program Name>
  test_keys.py

<Author>
  Vladimir Diaz

<Started>
  October 10, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_keys.py.
"""

import unittest
import copy

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.keys
import securesystemslib.ecdsa_keys

KEYS = securesystemslib.keys
FORMAT_ERROR_MSG = 'securesystemslib.exceptions.FormatError was raised!' + \
  '  Check object\'s format.'
DATA_STR = 'SOME DATA REQUIRING AUTHENTICITY.'
DATA = securesystemslib.formats.encode_canonical(DATA_STR).encode('utf-8')



class TestKeys(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.rsakey_dict = KEYS.generate_rsa_key()
    cls.ed25519key_dict = KEYS.generate_ed25519_key()
    cls.ecdsakey_dict = KEYS.generate_ecdsa_key()

  def test_generate_rsa_key(self):
    _rsakey_dict = KEYS.generate_rsa_key()

    # Check if the format of the object returned by generate() corresponds
    # to RSAKEY_SCHEMA format.
    self.assertEqual(None,
        securesystemslib.formats.RSAKEY_SCHEMA.check_match(_rsakey_dict),
        FORMAT_ERROR_MSG)

    # Passing a bit value that is <2048 to generate() - should raise
    # 'securesystemslib.exceptions.FormatError'.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.generate_rsa_key, 555)

    # Passing a string instead of integer for a bit value.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.generate_rsa_key, 'bits')

    # NOTE if random bit value >=2048 (not 4096) is passed generate(bits)
    # does not raise any errors and returns a valid key.
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(KEYS.generate_rsa_key(2048)))
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(KEYS.generate_rsa_key(4096)))



  def test_generate_ecdsa_key(self):
    _ecdsakey_dict = KEYS.generate_ecdsa_key()

    # Check if the format of the object returned by generate_ecdsa_key()
    # corresponds to ECDSAKEY_SCHEMA format.
    self.assertEqual(None,
        securesystemslib.formats.ECDSAKEY_SCHEMA.check_match(_ecdsakey_dict),
        FORMAT_ERROR_MSG)

    # Passing an invalid algorithm to generate() should raise
    # 'securesystemslib.exceptions.FormatError'.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.generate_rsa_key, 'bad_algorithm')

    # Passing a string instead of integer for a bit value.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.generate_rsa_key, 123)



  def test_format_keyval_to_metadata(self):
    keyvalue = self.rsakey_dict['keyval']
    keytype = self.rsakey_dict['keytype']
    scheme = self.rsakey_dict['scheme']

    key_meta = KEYS.format_keyval_to_metadata(keytype, scheme, keyvalue)

    # Check if the format of the object returned by this function corresponds
    # to KEY_SCHEMA format.
    self.assertEqual(None,
        securesystemslib.formats.KEY_SCHEMA.check_match(key_meta),
        FORMAT_ERROR_MSG)
    key_meta = KEYS.format_keyval_to_metadata(keytype, scheme,
        keyvalue, private=True)

    # Check if the format of the object returned by this function corresponds
    # to KEY_SCHEMA format.
    self.assertEqual(None,
        securesystemslib.formats.KEY_SCHEMA.check_match(key_meta),
        FORMAT_ERROR_MSG)

    # Supplying a 'bad' keyvalue.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.format_keyval_to_metadata,
        'bad_keytype', scheme, keyvalue, private=True)

    # Test for missing 'public' entry.
    public = keyvalue['public']
    del keyvalue['public']
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.format_keyval_to_metadata, keytype, scheme, keyvalue)
    keyvalue['public'] = public

    # Test for missing 'private' entry.
    private = keyvalue['private']
    del keyvalue['private']
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.format_keyval_to_metadata, keytype, scheme, keyvalue, private=True)
    keyvalue['private'] = private



  def test_import_rsakey_from_public_pem(self):
    pem = self.rsakey_dict['keyval']['public']
    rsa_key = KEYS.import_rsakey_from_public_pem(pem)

    # Check if the format of the object returned by this function corresponds
    # to 'securesystemslib.formats.RSAKEY_SCHEMA' format.
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key))

    # Verify whitespace is stripped.
    self.assertEqual(rsa_key, KEYS.import_rsakey_from_public_pem(pem + '\n'))

    # Supplying a 'bad_pem' argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_public_pem, 'bad_pem')

    # Supplying an improperly formatted PEM.
    # Strip the PEM header and footer.
    pem_header = '-----BEGIN PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_public_pem,
        pem[len(pem_header):])

    pem_footer = '-----END PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_public_pem, pem[:-len(pem_footer)])



  def test_format_metadata_to_key(self):
    # Copying self.rsakey_dict so that rsakey_dict remains
    # unchanged during and after this test execution.
    test_rsakey_dict = copy.copy(self.rsakey_dict)
    del test_rsakey_dict['keyid']

    # Call format_metadata_to_key by using the default value for keyid_hash_algorithms
    rsakey_dict_from_meta_default, junk = KEYS.format_metadata_to_key(test_rsakey_dict)

    # Check if the format of the object returned by calling this function with
    # default hash algorithms e.g. securesystemslib.settings.HASH_ALGORITHMS corresponds
    # to RSAKEY_SCHEMA format.
    self.assertTrue(
        securesystemslib.formats.RSAKEY_SCHEMA.matches(rsakey_dict_from_meta_default),
        FORMAT_ERROR_MSG)

    self.assertTrue(
        securesystemslib.formats.KEY_SCHEMA.matches(rsakey_dict_from_meta_default),
        FORMAT_ERROR_MSG)

    # Call format_metadata_to_key by using custom value for keyid_hash_algorithms
    rsakey_dict_from_meta_custom, junk = KEYS.format_metadata_to_key(test_rsakey_dict,
        keyid_hash_algorithms=['sha384'])

    # Check if the format of the object returned by calling this function with
    # custom hash algorithms corresponds to RSAKEY_SCHEMA format.
    self.assertTrue(
        securesystemslib.formats.RSAKEY_SCHEMA.matches(rsakey_dict_from_meta_custom),
        FORMAT_ERROR_MSG)

    self.assertTrue(
        securesystemslib.formats.KEY_SCHEMA.matches(rsakey_dict_from_meta_custom),
        FORMAT_ERROR_MSG)

    test_rsakey_dict['keyid'] = self.rsakey_dict['keyid']

    # Supplying a wrong number of arguments.
    self.assertRaises(TypeError, KEYS.format_metadata_to_key)
    args = (test_rsakey_dict, test_rsakey_dict)
    self.assertRaises(TypeError, KEYS.format_metadata_to_key, *args)

    # Supplying a malformed argument to the function - should get FormatError
    del test_rsakey_dict['keyval']
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.format_metadata_to_key, test_rsakey_dict)



  def test_helper_get_keyid(self):
    keytype = self.rsakey_dict['keytype']
    keyvalue = self.rsakey_dict['keyval']
    scheme = self.rsakey_dict['scheme']

    # Check format of 'keytype'.
    self.assertEqual(None,
        securesystemslib.formats.KEYTYPE_SCHEMA.check_match(keytype),
        FORMAT_ERROR_MSG)

    # Check format of 'keyvalue'.
    self.assertEqual(None,
        securesystemslib.formats.KEYVAL_SCHEMA.check_match(keyvalue),
        FORMAT_ERROR_MSG)

    # Check format of 'scheme'.
    self.assertEqual(None,
        securesystemslib.formats.RSA_SCHEME_SCHEMA.check_match(scheme),
        FORMAT_ERROR_MSG)

    keyid = KEYS._get_keyid(keytype, scheme, keyvalue)

    # Check format of 'keyid' - the output of '_get_keyid()' function.
    self.assertEqual(None,
        securesystemslib.formats.KEYID_SCHEMA.check_match(keyid),
        FORMAT_ERROR_MSG)


  def test_create_signature(self):
    # Creating a signature for 'DATA'.
    rsa_signature = KEYS.create_signature(self.rsakey_dict, DATA)
    ed25519_signature = KEYS.create_signature(self.ed25519key_dict, DATA)

    # Check format of output.
    self.assertEqual(None,
        securesystemslib.formats.SIGNATURE_SCHEMA.check_match(rsa_signature),
        FORMAT_ERROR_MSG)
    self.assertEqual(None,
        securesystemslib.formats.SIGNATURE_SCHEMA.check_match(ed25519_signature),
        FORMAT_ERROR_MSG)

    # Test for invalid signature scheme.
    args = (self.rsakey_dict, DATA)

    valid_scheme = self.rsakey_dict['scheme']
    self.rsakey_dict['scheme'] = 'invalid_scheme'
    self.assertRaises(securesystemslib.exceptions.UnsupportedAlgorithmError,
        KEYS.create_signature, *args)
    self.rsakey_dict['scheme'] = valid_scheme

    # Removing private key from 'rsakey_dict' - should raise a TypeError.
    private = self.rsakey_dict['keyval']['private']
    self.rsakey_dict['keyval']['private'] = ''

    self.assertRaises(ValueError, KEYS.create_signature, *args)

    # Supplying an incorrect number of arguments.
    self.assertRaises(TypeError, KEYS.create_signature)
    self.rsakey_dict['keyval']['private'] = private

    # Test generation of ECDSA signatures.

    # Creating a signature for 'DATA'.
    ecdsa_signature = KEYS.create_signature(self.ecdsakey_dict, DATA)

    # Check format of output.
    self.assertEqual(None,
        securesystemslib.formats.SIGNATURE_SCHEMA.check_match(ecdsa_signature),
        FORMAT_ERROR_MSG)

    # Removing private key from 'ecdsakey_dict' - should raise a TypeError.
    private = self.ecdsakey_dict['keyval']['private']
    self.ecdsakey_dict['keyval']['private'] = ''

    args = (self.ecdsakey_dict, DATA)
    self.assertRaises(ValueError, KEYS.create_signature, *args)

    # Supplying an incorrect number of arguments.
    self.assertRaises(TypeError, KEYS.create_signature)
    self.ecdsakey_dict['keyval']['private'] = private




  def test_verify_signature(self):
    # Creating a signature of 'DATA' to be verified.
    rsa_signature = KEYS.create_signature(self.rsakey_dict, DATA)
    ed25519_signature = KEYS.create_signature(self.ed25519key_dict, DATA)
    ecdsa_signature = KEYS.create_signature(self.ecdsakey_dict, DATA)

    # Verifying the 'signature' of 'DATA'.
    verified = KEYS.verify_signature(self.rsakey_dict, rsa_signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Verifying the 'ed25519_signature' of 'DATA'.
    verified = KEYS.verify_signature(self.ed25519key_dict, ed25519_signature,
                                     DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Verify that an invalid ed25519 signature scheme is rejected.
    valid_scheme = self.ed25519key_dict['scheme']
    self.ed25519key_dict['scheme'] = 'invalid_scheme'
    self.assertRaises(securesystemslib.exceptions.UnsupportedAlgorithmError,
        KEYS.verify_signature, self.ed25519key_dict, ed25519_signature, DATA)
    self.ed25519key_dict['scheme'] = valid_scheme

    # Verifying the 'ecdsa_signature' of 'DATA'.
    verified = KEYS.verify_signature(self.ecdsakey_dict, ecdsa_signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Verifying the 'ecdsa_signature' of 'DATA' with an old-style key dict
    old_key_dict = self.ecdsakey_dict.copy()
    old_key_dict['keytype'] = 'ecdsa-sha2-nistp256'
    verified = KEYS.verify_signature(old_key_dict, ecdsa_signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Test for an invalid ecdsa signature scheme.
    valid_scheme = self.ecdsakey_dict['scheme']
    self.ecdsakey_dict['scheme'] = 'invalid_scheme'
    self.assertRaises(securesystemslib.exceptions.UnsupportedAlgorithmError,
        KEYS.verify_signature, self.ecdsakey_dict, ecdsa_signature, DATA)
    self.ecdsakey_dict['scheme'] = valid_scheme

    # Testing invalid signatures. Same signature is passed, with 'DATA' being
    # different than the original 'DATA' that was used in creating the
    # 'rsa_signature'. Function should return 'False'.

    # Modifying 'DATA'.
    _DATA_STR = '1111' + DATA_STR + '1111'
    _DATA = securesystemslib.formats.encode_canonical(_DATA_STR).encode('utf-8')

    # Verifying the 'signature' of modified '_DATA'.
    verified = KEYS.verify_signature(self.rsakey_dict, rsa_signature, _DATA)
    self.assertFalse(verified,
        'Returned \'True\' on an incorrect signature.')

    verified = KEYS.verify_signature(self.ed25519key_dict,
        ed25519_signature, _DATA)
    self.assertFalse(verified,
        'Returned \'True\' on an incorrect signature.')

    verified = KEYS.verify_signature(self.ecdsakey_dict, ecdsa_signature, _DATA)
    self.assertFalse(verified,
        'Returned \'True\' on an incorrect signature.')

    # Modifying 'rsakey_dict' to pass an incorrect scheme.
    valid_scheme = self.rsakey_dict['scheme']
    self.rsakey_dict['scheme'] = 'Biff'

    args = (self.rsakey_dict, rsa_signature, DATA)
    self.assertRaises(securesystemslib.exceptions.UnsupportedAlgorithmError,
        KEYS.verify_signature, *args)

    # Restore
    self.rsakey_dict['scheme'] = valid_scheme

    # Verify that the KEYIDS of 'key_dict' and 'signature' match.
    valid_keyid = self.rsakey_dict['keyid'] = '12345'
    self.rsakey_dict['keyid'] = 'bad123'

    self.assertRaises(securesystemslib.exceptions.CryptoError,
        KEYS.verify_signature, self.rsakey_dict, rsa_signature, DATA)
    self.rsakey_dict['keyid'] = valid_keyid

    # Passing incorrect number of arguments.
    self.assertRaises(TypeError, KEYS.verify_signature)

    # Verify that the pure python 'ed25519' base case (triggered if 'pynacl'
    # is unavailable) is executed in securesystemslib.keys.verify_signature().
    KEYS._ED25519_CRYPTO_LIBRARY = 'invalid'
    KEYS._available_crypto_libraries = ['invalid']
    verified = KEYS.verify_signature(self.ed25519key_dict,
        ed25519_signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Verify ecdsa key with HEX encoded keyval instead of PEM encoded keyval
    ecdsa_key = KEYS.generate_ecdsa_key()
    ecdsa_key['keyval']['public'] = 'abcd'
    # sig is not important as long as keyid is the same as the one in ecdsa_key
    sig = {'keyid': ecdsa_key['keyid'], 'sig': 'bb'}
    with self.assertRaises(securesystemslib.exceptions.FormatError):
        KEYS.verify_signature(ecdsa_key, sig, b'data')

    # Verify ed25519 key with PEM encoded keyval instead of HEX encoded keyval
    ed25519 = KEYS.generate_ed25519_key()
    ed25519['keyval']['public'] = \
        '-----BEGIN PUBLIC KEY-----\nfoo\n-----END PUBLIC KEY-----\n'
    # sig is not important as long as keyid is the same as the one in ed25519
    sig = {'keyid': ed25519['keyid'], 'sig': 'bb'}
    with self.assertRaises(securesystemslib.exceptions.FormatError):
        KEYS.verify_signature(ed25519, sig, b'data')


  def test_create_rsa_encrypted_pem(self):
    # Test valid arguments.
    private = self.rsakey_dict['keyval']['private']
    passphrase = 'secret'
    scheme = 'rsassa-pss-sha256'
    encrypted_pem = KEYS.create_rsa_encrypted_pem(private, passphrase)
    self.assertTrue(securesystemslib.formats.PEMRSA_SCHEMA.matches(encrypted_pem))
    self.assertTrue(KEYS.is_pem_private(encrypted_pem))

    # Try to import the encrypted PEM file.
    rsakey = KEYS.import_rsakey_from_private_pem(encrypted_pem,
        scheme, passphrase)
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(rsakey))

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.create_rsa_encrypted_pem, 8, passphrase)

    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.create_rsa_encrypted_pem, private, 8)





  def test_import_rsakey_from_private_pem(self):
    # Try to import an rsakey from a valid PEM.
    private_pem = self.rsakey_dict['keyval']['private']

    private_rsakey = KEYS.import_rsakey_from_private_pem(private_pem)

    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_private_pem, 123)



  def test_import_rsakey_from_public_pem(self):
    # Try to import an rsakey from a public PEM.
    pem = self.rsakey_dict['keyval']['public']
    rsa_key = KEYS.import_rsakey_from_public_pem(pem)

    # Check if the format of the object returned by this function corresponds
    # to 'securesystemslib.formats.RSAKEY_SCHEMA' format.
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key))

    # Verify whitespace is stripped.
    self.assertEqual(rsa_key, KEYS.import_rsakey_from_public_pem(pem + '\n'))

    # Supplying a 'bad_pem' argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_public_pem, 'bad_pem')

    # Supplying an improperly formatted PEM.
    # Strip the PEM header and footer.
    pem_header = '-----BEGIN PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_public_pem, pem[len(pem_header):])

    pem_footer = '-----END PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_public_pem, pem[:-len(pem_footer)])

    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_public_pem, 123)



  def test_import_rsakey_from_pem(self):
    # Try to import an rsakey from a public PEM.
    public_pem = self.rsakey_dict['keyval']['public']
    private_pem = self.rsakey_dict['keyval']['private']
    public_rsakey = KEYS.import_rsakey_from_pem(public_pem)
    private_rsakey = KEYS.import_rsakey_from_pem(private_pem)

    # Check if the format of the object returned by this function corresponds
    # to 'securesystemslib.formats.RSAKEY_SCHEMA' format.
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(public_rsakey))
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(private_rsakey))

    # Verify whitespace is stripped.
    self.assertEqual(public_rsakey,
        KEYS.import_rsakey_from_pem(public_pem + '\n'))
    self.assertEqual(private_rsakey,
        KEYS.import_rsakey_from_pem(private_pem + '\n'))

    # Supplying a 'bad_pem' argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_pem, 'bad_pem')

    # Supplying an improperly formatted public PEM.
    # Strip the PEM header and footer.
    pem_header = '-----BEGIN PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_pem, public_pem[len(pem_header):])

    pem_footer = '-----END PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_pem, public_pem[:-len(pem_footer)])

    # Supplying an improperly formatted private PEM.
    # Strip the PEM header and footer.
    pem_header = '-----BEGIN PRIVATE KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_pem, private_pem[len(pem_header):])

    pem_footer = '-----END PRIVATE KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_pem, private_pem[:-len(pem_footer)])

    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_rsakey_from_pem, 123)



  def test_import_ecdsakey_from_private_pem(self):
    # Try to import an ecdsakey from a valid PEM.
    private_pem = self.ecdsakey_dict['keyval']['private']
    ecdsakey = KEYS.import_ecdsakey_from_private_pem(private_pem)

    # Test for an encrypted PEM.
    scheme = 'ecdsa-sha2-nistp256'
    encrypted_pem = \
      securesystemslib.ecdsa_keys.create_ecdsa_encrypted_pem(private_pem,
        'password')
    private_ecdsakey = KEYS.import_ecdsakey_from_private_pem(encrypted_pem.decode('utf-8'),
        scheme, 'password')


    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_private_pem, 123)



  def test_import_ecdsakey_from_public_pem(self):
    # Try to import an ecdsakey from a public PEM.
    pem = self.ecdsakey_dict['keyval']['public']
    ecdsa_key = KEYS.import_ecdsakey_from_public_pem(pem)

    # Check if the format of the object returned by this function corresponds
    # to 'securesystemslib.formats.ECDSAKEY_SCHEMA' format.
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(ecdsa_key))

    # Verify whitespace is stripped.
    self.assertEqual(ecdsa_key, KEYS.import_ecdsakey_from_public_pem(pem + '\n'))

    # Supplying a 'bad_pem' argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_public_pem, 'bad_pem')

    # Supplying an improperly formatted PEM.  Strip the PEM header and footer.
    pem_header = '-----BEGIN PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_public_pem, pem[len(pem_header):])

    pem_footer = '-----END PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_public_pem, pem[:-len(pem_footer)])

    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_public_pem, 123)



  def test_import_ecdsakey_from_pem(self):
    # Try to import an ecdsakey from a public PEM.
    public_pem = self.ecdsakey_dict['keyval']['public']
    private_pem = self.ecdsakey_dict['keyval']['private']
    public_ecdsakey = KEYS.import_ecdsakey_from_pem(public_pem)
    private_ecdsakey = KEYS.import_ecdsakey_from_pem(private_pem)

    # Check if the format of the object returned by this function corresponds
    # to 'securesystemslib.formats.ECDSAKEY_SCHEMA' format.
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(public_ecdsakey))
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(private_ecdsakey))

    # Verify whitespace is stripped.
    self.assertEqual(public_ecdsakey,
        KEYS.import_ecdsakey_from_pem(public_pem + '\n'))
    self.assertEqual(private_ecdsakey,
        KEYS.import_ecdsakey_from_pem(private_pem + '\n'))

    # Supplying a 'bad_pem' argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_pem, 'bad_pem')

    # Supplying an improperly formatted public PEM.  Strip the PEM header and
    # footer.
    pem_header = '-----BEGIN PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_pem, public_pem[len(pem_header):])

    pem_footer = '-----END PUBLIC KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_pem, public_pem[:-len(pem_footer)])

    # Supplying an improperly formatted private PEM.  Strip the PEM header and
    # footer.
    pem_header = '-----BEGIN EC PRIVATE KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_pem, private_pem[len(pem_header):])

    pem_footer = '-----END EC PRIVATE KEY-----'
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_pem, private_pem[:-len(pem_footer)])

    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.import_ecdsakey_from_pem, 123)



  def test_decrypt_key(self):
    # Test valid arguments.
    passphrase = 'secret'
    encrypted_key = KEYS.encrypt_key(self.rsakey_dict, passphrase)
    decrypted_key = KEYS.decrypt_key(encrypted_key, passphrase)

    self.assertTrue(securesystemslib.formats.ANYKEY_SCHEMA.matches(decrypted_key))

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, KEYS.decrypt_key,
        8, passphrase)

    self.assertRaises(securesystemslib.exceptions.FormatError, KEYS.decrypt_key,
        encrypted_key, 8)



  def test_extract_pem(self):
    # Normal case.
    private_pem = KEYS.extract_pem(self.rsakey_dict['keyval']['private'],
        private_pem=True)
    self.assertTrue(securesystemslib.formats.PEMRSA_SCHEMA.matches(private_pem))

    public_pem = KEYS.extract_pem(self.rsakey_dict['keyval']['public'],
        private_pem=False)
    self.assertTrue(securesystemslib.formats.PEMRSA_SCHEMA.matches(public_pem))

    # Test encrypted private pem
    encrypted_private_pem = KEYS.create_rsa_encrypted_pem(private_pem, "pw")
    encrypted_private_pem_stripped = KEYS.extract_pem(encrypted_private_pem,
        private_pem=True)
    self.assertTrue(securesystemslib.formats.PEMRSA_SCHEMA.matches(
        encrypted_private_pem_stripped))

    # Test for an invalid PEM.
    pem_header = '-----BEGIN RSA PRIVATE KEY-----'
    pem_footer = '-----END RSA PRIVATE KEY-----'

    private_header_start = private_pem.index(pem_header)
    private_footer_start = private_pem.index(pem_footer,
        private_header_start + len(pem_header))

    private_missing_header = private_pem[private_header_start + len(pem_header):private_footer_start + len(pem_footer)]
    private_missing_footer = private_pem[private_header_start:private_footer_start]

    pem_header = '-----BEGIN PUBLIC KEY-----'
    pem_footer = '-----END PUBLIC KEY-----'

    public_header_start = public_pem.index(pem_header)
    public_footer_start = public_pem.index(pem_footer,
        public_header_start + len(pem_header))

    public_missing_header = public_pem[public_header_start + len(pem_header):public_footer_start + len(pem_footer)]
    public_missing_footer = public_pem[public_header_start:public_footer_start]

    self.assertRaises(securesystemslib.exceptions.FormatError, KEYS.extract_pem,
        'invalid_pem', private_pem=False)

    self.assertRaises(securesystemslib.exceptions.FormatError, KEYS.extract_pem,
        public_missing_header, private_pem=False)
    self.assertRaises(securesystemslib.exceptions.FormatError, KEYS.extract_pem,
        private_missing_header, private_pem=True)

    self.assertRaises(securesystemslib.exceptions.FormatError, KEYS.extract_pem,
        public_missing_footer, private_pem=False)

    self.assertRaises(securesystemslib.exceptions.FormatError, KEYS.extract_pem,
        private_missing_footer, private_pem=True)




  def test_is_pem_public(self):
    # Test for a valid PEM string.
    public_pem = self.rsakey_dict['keyval']['public']
    self.assertTrue(KEYS.is_pem_public(public_pem))

    # Test for a valid non-public PEM string.
    private_pem = self.rsakey_dict['keyval']['private']
    self.assertFalse(KEYS.is_pem_public(private_pem))

    # Test for an invalid PEM string.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.is_pem_public, 123)



  def test_is_pem_private(self):
    # Test for a valid PEM string.
    private_pem_rsa = self.rsakey_dict['keyval']['private']
    private_pem_ec = self.ecdsakey_dict['keyval']['private']
    encrypted_private_pem_rsa = KEYS.create_rsa_encrypted_pem(
        private_pem_rsa, "pw")

    self.assertTrue(KEYS.is_pem_private(private_pem_rsa))
    self.assertTrue(KEYS.is_pem_private(private_pem_ec, 'ec'))
    self.assertTrue(KEYS.is_pem_private(encrypted_private_pem_rsa))

    # Test for a valid non-private PEM string.
    public_pem = self.rsakey_dict['keyval']['public']
    public_pem_ec = self.ecdsakey_dict['keyval']['public']
    self.assertFalse(KEYS.is_pem_private(public_pem))
    self.assertFalse(KEYS.is_pem_private(public_pem_ec, 'ec'))

    # Test for unsupported keytype.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.is_pem_private, private_pem_rsa, 'bad_keytype')

    # Test for an invalid PEM string.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        KEYS.is_pem_private, 123)



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
