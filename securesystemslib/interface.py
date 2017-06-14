#!/usr/bin/env python

"""
<Program Name>
  interface.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 5, 2017.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide an interface to the cryptography funtions available in
  securesystemslib.  The interface can be used with the Python interpreter in
  interactive mode, or imported directly into a Python module.  See
  'securesystemslib/README' for the complete guide to using 'interface.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import errno
import sys
import time
import datetime
import getpass
import logging
import tempfile
import shutil
import json
import gzip
import random

import securesystemslib.formats
import securesystemslib.settings
import securesystemslib.util
import securesystemslib.keys

import six

# See 'log.py' to learn how logging is handled in securesystemslib.
logger = logging.getLogger('securesystemslib_interface')


# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond. 2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# Supported key types.
SUPPORTED_KEY_TYPES = ['rsa', 'ed25519']



def _prompt(message, result_type=str):
  """
    Non-public function that prompts the user for input by logging 'message',
    converting the input to 'result_type', and returning the value to the
    caller.
  """

  return result_type(six.moves.input(message))





def _get_password(prompt='Password: ', confirm=False):
  """
    Non-public function that returns the password entered by the user.  If
    'confirm' is True, the user is asked to enter the previously entered
    password once again.  If they match, the password is returned to the caller.
  """

  while True:
    # getpass() prompts the user for a password without echoing
    # the user input.
    password = getpass.getpass(prompt, sys.stderr)

    if not confirm:
      return password
    password2 = getpass.getpass('Confirm: ', sys.stderr)

    if password == password2:
      return password

    else:
      print('Mismatch; try again.')





def generate_and_write_rsa_keypair(filepath, bits=DEFAULT_RSA_KEY_BITS,
                                   password=None):
  """
  <Purpose>
    Generate an RSA key file, create an encrypted PEM string (using 'password'
    as the pass phrase), and store it in 'filepath'.  The public key portion of
    the generated RSA key is stored in <'filepath'>.pub.  Which cryptography
    library performs the cryptographic decryption is determined by the string
    set in 'settings.RSA_CRYPTO_LIBRARY'.  PyCrypto currently supported.  The
    PEM private key is encrypted with 3DES and CBC the mode of operation.  The
    password is strengthened with PBKDF1-MD5.

  <Arguments>
    filepath:
      The public and private key files are saved to <filepath>.pub, <filepath>,
      respectively.

    bits:
      The number of bits of the generated RSA key.

    password:
      The password used to encrypt 'filepath'.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    Writes key files to '<filepath>' and '<filepath>.pub'.

  <Returns>
    None.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of
  # objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # Does 'bits' have the correct format?
  securesystemslib.formats.RSAKEYBITS_SCHEMA.check_match(bits)

  # If the caller does not provide a password argument, prompt for one.
  if password is None: # pragma: no cover
    message = 'Enter a password for the RSA key file: '
    password = _get_password(message, confirm=True)

  # Does 'password' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  #  Generate public and private RSA keys, encrypted the private portion
  # and store them in PEM format.
  rsa_key = securesystemslib.keys.generate_rsa_key(bits)
  public = rsa_key['keyval']['public']
  private = rsa_key['keyval']['private']
  encrypted_pem = securesystemslib.keys.create_rsa_encrypted_pem(private, password)

  # Write public key (i.e., 'public', which is in PEM format) to
  # '<filepath>.pub'.  If the parent directory of filepath does not exist,
  # create it (and all its parent directories, if necessary).
  securesystemslib.util.ensure_parent_dir(filepath)

  # Create a tempororary file, write the contents of the public key, and move
  # to final destination.
  file_object = securesystemslib.util.TempFile()
  file_object.write(public.encode('utf-8'))

  # The temporary file is closed after the final move.
  file_object.move(filepath + '.pub')

  # Write the private key in encrypted PEM format to '<filepath>'.
  # Unlike the public key file, the private key does not have a file
  # extension.
  file_object = securesystemslib.util.TempFile()
  file_object.write(encrypted_pem.encode('utf-8'))
  file_object.move(filepath)





def import_rsa_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted PEM file in 'filepath', decrypt it, and return the key
    object in 'securesystemslib.formats.RSAKEY_SCHEMA' format.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'settings.RSA_CRYPTO_LIBRARY'.  PyCrypto
    currently supported.

    The PEM private key is encrypted with 3DES and CBC the mode of operation.
    The password is strengthened with PBKDF1-MD5.

  <Arguments>
    filepath:
      <filepath> file, an RSA encrypted PEM file.  Unlike the public RSA PEM
      key file, 'filepath' does not have an extension.

    password:
      The passphrase to decrypt 'filepath'.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'filepath' is not a valid
    encrypted key file.

  <Side Effects>
    The contents of 'filepath' is read, decrypted, and the key stored.

  <Returns>
    An RSA key object, conformant to 'securesystemslib.formats.RSAKEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  # Password confirmation disabled here, which should ideally happen only
  # when creating encrypted key files (i.e., improve usability).
  if password is None: # pragma: no cover
    message = 'Enter a password for the encrypted RSA file: '
    password = _get_password(message, confirm=False)

  # Does 'password' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  encrypted_pem = None

  # Read the contents of 'filepath' that should be an encrypted PEM.
  with open(filepath, 'rb') as file_object:
    encrypted_pem = file_object.read().decode('utf-8')

  # Convert 'encrypted_pem' to 'securesystemslib.formats.RSAKEY_SCHEMA' format.
  # Raise 'securesystemslib.exceptions.CryptoError' if 'encrypted_pem' is
  # invalid.
  rsa_key = securesystemslib.keys.import_rsakey_from_private_pem(encrypted_pem, password)

  return rsa_key





def import_rsa_publickey_from_file(filepath):
  """
  <Purpose>
    Import the RSA key stored in 'filepath'.  The key object returned is in the
    format 'securesystemslib.formats.RSAKEY_SCHEMA'.  If the RSA PEM in
    'filepath' contains a private key, it is discarded.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'settings.RSA_CRYPTO_LIBRARY'.  PyCrypto
    currently supported.  If the RSA PEM in 'filepath' contains a private key,
    it is discarded.

  <Arguments>
    filepath:
      <filepath>.pub file, an RSA PEM file.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'filepath' is improperly formatted.

    securesystemslib.exceptions.Error, if a valid RSA key object cannot be
    generated.  This may be caused by an improperly formatted PEM file.

  <Side Effects>
    'filepath' is read and its contents extracted.

  <Returns>
    An RSA key object conformant to 'securesystemslib.formats.RSAKEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # Read the contents of the key file that should be in PEM format and contains
  # the public portion of the RSA key.
  with open(filepath, 'rb') as file_object:
    rsa_pubkey_pem = file_object.read().decode('utf-8')

  # Convert 'rsa_pubkey_pem' to 'securesystemslib.formats.RSAKEY_SCHEMA' format.
  try:
    rsakey_dict = securesystemslib.keys.import_rsakey_from_public_pem(rsa_pubkey_pem)

  except securesystemslib.exceptions.FormatError as e:
    raise securesystemslib.exceptions.Error('Cannot import improperly formatted'
      ' PEM file.' + repr(str(e)))

  return rsakey_dict





def generate_and_write_ed25519_keypair(filepath, password=None):
  """
  <Purpose>
    Generate an Ed25519 key file, create an encrypted key (using 'password'
    as the pass phrase), and store it in 'filepath'.  The public key portion of
    the generated ED25519 key is stored in <'filepath'>.pub.  Which cryptography
    library performs the cryptographic decryption is determined by the string
    set in 'settings.ED25519_CRYPTO_LIBRARY'.

    PyCrypto currently supported.  The Ed25519 private key is encrypted with
    AES-256 and CTR the mode of operation.  The password is strengthened with
    PBKDF2-HMAC-SHA256.

  <Arguments>
    filepath:
      The public and private key files are saved to <filepath>.pub and
      <filepath>, respectively.

    password:
      The password, or passphrase, to encrypt the private portion of the
      generated ed25519 key.  A symmetric encryption key is derived from
      'password', so it is not directly used.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'filepath' cannot be encrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if 'filepath' cannot be
    encrypted due to an invalid configuration setting (i.e., invalid
    'settings.py' setting).

  <Side Effects>
    Writes key files to '<filepath>' and '<filepath>.pub'.

  <Returns>
    None.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  if password is None: # pragma: no cover
    message = 'Enter a password for the Ed25519 key: '
    password = _get_password(message, confirm=True)

  # Does 'password' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  # Generate a new ED25519 key object and encrypt it.  The cryptography library
  # used is determined by the user, or by default (set in
  # 'settings.ED25519_CRYPTO_LIBRARY').  Raise
  # 'securesystemslib.exceptions.CryptoError' or
  # 'securesystemslib.exceptions.UnsupportedLibraryError', if 'ed25519_key'
  # cannot be encrypted.
  ed25519_key = securesystemslib.keys.generate_ed25519_key()
  encrypted_key = securesystemslib.keys.encrypt_key(ed25519_key, password)

  # ed25519 public key file contents in metadata format (i.e., does not include
  # the keyid portion).
  keytype = ed25519_key['keytype']
  keyval = ed25519_key['keyval']
  ed25519key_metadata_format = \
    securesystemslib.keys.format_keyval_to_metadata(keytype, keyval, private=False)

  # Write the public key, conformant to 'securesystemslib.formats.KEY_SCHEMA', to
  # '<filepath>.pub'.
  securesystemslib.util.ensure_parent_dir(filepath)

  # Create a tempororary file, write the contents of the public key, and move
  # to final destination.
  file_object = securesystemslib.util.TempFile()
  file_object.write(json.dumps(ed25519key_metadata_format).encode('utf-8'))

  # The temporary file is closed after the final move.
  file_object.move(filepath + '.pub')

  # Write the encrypted key string, conformant to
  # 'securesystemslib.formats.ENCRYPTEDKEY_SCHEMA', to '<filepath>'.
  file_object = securesystemslib.util.TempFile()
  file_object.write(encrypted_key.encode('utf-8'))
  file_object.move(filepath)





def import_ed25519_publickey_from_file(filepath):
  """
  <Purpose>
    Load the ED25519 public key object (conformant to
    'securesystemslib.formats.KEY_SCHEMA') stored in 'filepath'.  Return
    'filepath' in securesystemslib.formats.ED25519KEY_SCHEMA format.

    If the key object in 'filepath' contains a private key, it is discarded.

  <Arguments>
    filepath:
      <filepath>.pub file, a public key file.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'filepath' is improperly
    formatted or is an unexpected key type.

  <Side Effects>
    The contents of 'filepath' is read and saved.

  <Returns>
    An ED25519 key object conformant to
    'securesystemslib.formats.ED25519KEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # ED25519 key objects are saved in json and metadata format.  Return the
  # loaded key object in securesystemslib.formats.ED25519KEY_SCHEMA' format that
  # also includes the keyid.
  ed25519_key_metadata = securesystemslib.util.load_json_file(filepath)
  ed25519_key, junk = securesystemslib.keys.format_metadata_to_key(ed25519_key_metadata)

  # Raise an exception if an unexpected key type is imported.  Redundant
  # validation of 'keytype'.  'securesystemslib.keys.format_metadata_to_key()'
  # should have fully validated 'ed25519_key_metadata'.
  if ed25519_key['keytype'] != 'ed25519': # pragma: no cover
    message = 'Invalid key type loaded: ' + repr(ed25519_key['keytype'])
    raise securesystemslib.exceptions.FormatError(message)

  return ed25519_key





def import_ed25519_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted ed25519 key file in 'filepath', decrypt it, and
    return the key object in 'securesystemslib.formats.ED25519KEY_SCHEMA' format.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'settings.ED25519_CRYPTO_LIBRARY'.  PyCrypto
    currently supported.

    The private key (may also contain the public part) is encrypted with AES
    256 and CTR the mode of operation.  The password is strengthened with
    PBKDF2-HMAC-SHA256.

  <Arguments>
    filepath:
      <filepath> file, an RSA encrypted key file.

    password:
      The password, or passphrase, to import the private key (i.e., the
      encrypted key file 'filepath' must be decrypted before the ed25519 key
      object can be returned.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted or the imported key object contains an invalid key type (i.e.,
    not 'ed25519').

    securesystemslib.exceptions.CryptoError, if 'filepath' cannot be decrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if 'filepath' cannot be
    decrypted due to an invalid configuration setting (i.e., invalid
    'settings.py' setting).

  <Side Effects>
    'password' is used to decrypt the 'filepath' key file.

  <Returns>
    An ed25519 key object of the form: 'securesystemslib.formats.ED25519KEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  # Password confirmation disabled here, which should ideally happen only
  # when creating encrypted key files (i.e., improve usability).
  if password is None: # pragma: no cover
    message = 'Enter a password for the encrypted Ed25519 key: '
    password = _get_password(message, confirm=False)

  # Does 'password' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  # Store the encrypted contents of 'filepath' prior to calling the decryption
  # routine.
  encrypted_key = None

  with open(filepath, 'rb') as file_object:
    encrypted_key = file_object.read()

  # Decrypt the loaded key file, calling the appropriate cryptography library
  # (i.e., set by the user) and generating the derived encryption key from
  # 'password'.  Raise 'securesystemslib.exceptions.CryptoError' or
  # 'securesystemslib.exceptions.UnsupportedLibraryError' if the decryption
  # fails.
  key_object = securesystemslib.keys.decrypt_key(encrypted_key.decode('utf-8'), password)

  # Raise an exception if an unexpected key type is imported.
  if key_object['keytype'] != 'ed25519':
    message = 'Invalid key type loaded: ' + repr(key_object['keytype'])
    raise securesystemslib.exceptions.FormatError(message)

  # Add "keyid_hash_algorithms" so that equal ed25519 keys with
  # different keyids can be associated using supported keyid_hash_algorithms.
  key_object['keyid_hash_algorithms'] = \
      securesystemslib.settings.HASH_ALGORITHMS

  return key_object





def generate_and_write_ecdsa_keypair(filepath, password=None):
  """
  <Purpose>
    Generate an ECDSA key file, create an encrypted key (using 'password' as
    the pass phrase), and store it in 'filepath'.  The public key portion of
    the generated ECDSA key is stored in <'filepath'>.pub.  Which cryptography
    library performs the cryptographic decryption is determined by the string
    set in 'settings.ECDSA_CRYPTO_LIBRARY'.  'cryptography' library currently
    supported.  The private key is encrypted according to 'cryptography's
    approach: "Encrypt using the best available encryption for a given key's
    backend. This is a curated encryption choice and the algorithm may
    change over time."

  <Arguments>
    filepath:
      The public and private key files are saved to <filepath>.pub and
      <filepath>, respectively.

    password:
      The password, or passphrase, to encrypt the private portion of the
      generated ECDSA key.  A symmetric encryption key is derived from
      'password', so it is not directly used.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'filepath' cannot be encrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if 'filepath' cannot be
    encrypted due to an invalid configuration setting (i.e., invalid
    'settings.py' setting).

  <Side Effects>
    Writes key files to '<filepath>' and '<filepath>.pub'.

  <Returns>
    None.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  if password is None: # pragma: no cover
    message = 'Enter a password for the ECDSA key: '
    password = _get_password(message, confirm=True)

  # Does 'password' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  # Generate a new ECDSA key object and encrypt it.  The cryptography library
  # used is determined by the user, or by default (set in
  # 'settings.ECDSA_CRYPTO_LIBRARY').  Raise
  # 'securesystemslib.exceptions.CryptoError' or
  # 'securesystemslib.exceptions.UnsupportedLibraryError', if 'ed25519_key'
  # cannot be encrypted.
  ecdsa_key = securesystemslib.keys.generate_ecdsa_key()
  encrypted_key = securesystemslib.keys.encrypt_key(ecdsa_key, password)

  # ECDSA public key file contents in metadata format (i.e., does not include
  # the keyid portion).
  keytype = ecdsa_key['keytype']
  keyval = ecdsa_key['keyval']
  ecdsakey_metadata_format = \
    securesystemslib.keys.format_keyval_to_metadata(keytype, keyval, private=False)

  # Write the public key, conformant to 'securesystemslib.formats.KEY_SCHEMA', to
  # '<filepath>.pub'.
  securesystemslib.util.ensure_parent_dir(filepath)

  # Create a tempororary file, write the contents of the public key, and move
  # to final destination.
  file_object = securesystemslib.util.TempFile()
  file_object.write(json.dumps(ecdsakey_metadata_format).encode('utf-8'))

  # The temporary file is closed after the final move.
  file_object.move(filepath + '.pub')

  # Write the encrypted key string, conformant to
  # 'securesystemslib.formats.ENCRYPTEDKEY_SCHEMA', to '<filepath>'.
  file_object = securesystemslib.util.TempFile()
  file_object.write(encrypted_key.encode('utf-8'))
  file_object.move(filepath)





def import_ecdsa_publickey_from_file(filepath):
  """
  <Purpose>
    Load the ECDSA public key object (conformant to
    'securesystemslib.formats.KEY_SCHEMA') stored in 'filepath'.  Return
    'filepath' in securesystemslib.formats.ECDSAKEY_SCHEMA format.

    If the key object in 'filepath' contains a private key, it is discarded.

  <Arguments>
    filepath:
      <filepath>.pub file, a public key file.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'filepath' is improperly
    formatted or is an unexpected key type.

  <Side Effects>
    The contents of 'filepath' is read and saved.

  <Returns>
    An ECDSA key object conformant to
    'securesystemslib.formats.ECDSAKEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # ECDSA key objects are saved in json and metadata format.  Return the
  # loaded key object in securesystemslib.formats.ECDSAKEY_SCHEMA' format that
  # also includes the keyid.
  ecdsa_key_metadata = securesystemslib.util.load_json_file(filepath)
  ecdsa_key, junk = securesystemslib.keys.format_metadata_to_key(ecdsa_key_metadata)

  # Raise an exception if an unexpected key type is imported.  Redundant
  # validation of 'keytype'.  'securesystemslib.keys.format_metadata_to_key()'
  # should have fully validated 'ecdsa_key_metadata'.
  if ecdsa_key['keytype'] != 'ecdsa-sha2-nistp256': # pragma: no cover
    message = 'Invalid key type loaded: ' + repr(ecdsa_key['keytype'])
    raise securesystemslib.exceptions.FormatError(message)

  return ecdsa_key





def import_ecdsa_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted ECDSA key file in 'filepath', decrypt it, and return
    the key object in 'securesystemslib.formats.ECDSAKEY_SCHEMA' format.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'settings.ECDSA_CRYPTO_LIBRARY'.
    currently supported.  The 'cryptography' library currently supported.

  <Arguments>
    filepath:
      <filepath> file, an ECDSA encrypted key file.

    password:
      The password, or passphrase, to import the private key (i.e., the
      encrypted key file 'filepath' must be decrypted before the ECDSA key
      object can be returned.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted or the imported key object contains an invalid key type (i.e.,
    not 'ecdsa-sha2-nistp256').

    securesystemslib.exceptions.CryptoError, if 'filepath' cannot be decrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if 'filepath' cannot be
    decrypted due to an invalid configuration setting (i.e., invalid
    'settings.py' setting).

  <Side Effects>
    'password' is used to decrypt the 'filepath' key file.

  <Returns>
    An ECDSA key object of the form: 'securesystemslib.formats.ECDSAKEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  # Password confirmation disabled here, which should ideally happen only
  # when creating encrypted key files (i.e., improve usability).
  if password is None: # pragma: no cover
    message = 'Enter a password for the encrypted ECDSA key: '
    password = _get_password(message, confirm=False)

  # Does 'password' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  # Store the encrypted contents of 'filepath' prior to calling the decryption
  # routine.
  encrypted_key = None

  with open(filepath, 'rb') as file_object:
    encrypted_key = file_object.read()

  # Decrypt the loaded key file, calling the appropriate cryptography library
  # (i.e., set by the user) and generating the derived encryption key from
  # 'password'.  Raise 'securesystemslib.exceptions.CryptoError' or
  # 'securesystemslib.exceptions.UnsupportedLibraryError' if the decryption
  # fails.
  key_object = securesystemslib.keys.decrypt_key(encrypted_key.decode('utf-8'), password)

  # Raise an exception if an unexpected key type is imported.
  if key_object['keytype'] != 'ecdsa-sha2-nistp256':
    message = 'Invalid key type loaded: ' + repr(key_object['keytype'])
    raise securesystemslib.exceptions.FormatError(message)

  # Add "keyid_hash_algorithms" so that equal ecdsa keys with different keyids
  # can be associated using supported keyid_hash_algorithms.
  key_object['keyid_hash_algorithms'] = \
      securesystemslib.settings.HASH_ALGORITHMS

  return key_object



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running interface.py as a standalone module:
  # $ python interface.py.
  import doctest
  doctest.testmod()
