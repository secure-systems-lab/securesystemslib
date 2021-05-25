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
  Provide an interface to the cryptography functions available in
  securesystemslib.  The interface can be used with the Python interpreter in
  interactive mode, or imported directly into a Python module.  See
  'securesystemslib/README' for the complete guide to using 'interface.py'.
"""

import os
import sys
import getpass
import logging
import tempfile
import json

from securesystemslib import exceptions
from securesystemslib import formats
from securesystemslib import keys
from securesystemslib import settings
from securesystemslib import util
from securesystemslib.storage import FilesystemBackend

from securesystemslib import KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA

logger = logging.getLogger(__name__)

try:
  from colorama import Fore
  TERM_RED = Fore.RED
  TERM_RESET = Fore.RESET
except ImportError: # pragma: no cover
  logger.debug("Failed to find colorama module, terminal output won't be colored")
  TERM_RED = ''
  TERM_RESET = ''

# Recommended RSA key sizes:
# https://en.wikipedia.org/wiki/Key_size#Asymmetric_algorithm_key_lengths
# Based on the above, RSA keys of size 3072 bits are expected to provide
# security through 2031 and beyond.
DEFAULT_RSA_KEY_BITS = 3072





def get_password(prompt='Password: ', confirm=False):
  """Prompts user to enter a password.

  Arguments:
    prompt (optional): A text displayed on the prompt (stderr).
    confirm (optional): A boolean indicating if the user needs to enter the
        same password twice.

  Returns:
    The password entered on the prompt.

  """
  formats.TEXT_SCHEMA.check_match(prompt)
  formats.BOOLEAN_SCHEMA.check_match(confirm)

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



def _get_key_file_encryption_password(password, prompt, path):
  """Encryption password helper for `_generate_and_write_*_keypair` functions.

  Combinations of 'password' and 'prompt' -> result (explanation)
  ----------------------------------------------------------------
  None                  False -> return None (clear non-encryption desire)
  "<non-empty string>"  False -> return password (clear encryption desire)
  <anything else>       False -> raise (bad pw type, unclear encryption desire)
  <not None>            True  -> raise (unclear password/prompt precedence)
  None                  True  -> prompt and return password if entered and None
                                 otherwise (users on the prompt can only
                                 indicate desire to not encrypt by entering no
                                 password)
  """
  formats.BOOLEAN_SCHEMA.check_match(prompt)

  # We don't want to decide which takes precedence so we fail
  if password is not None and prompt:
    raise ValueError("passing 'password' and 'prompt=True' is not allowed")

  # Prompt user for password and confirmation
  if prompt:
    password = get_password("enter password to encrypt private key file "
        "'" + TERM_RED + str(path) + TERM_RESET + "' (leave empty if key "
        "should not be encrypted): ", confirm=True)

    # Treat empty password as no password. A user on the prompt can only
    # indicate the desire to not encrypt by entering no password.
    if not len(password):
      return None

  if password is not None:
    formats.PASSWORD_SCHEMA.check_match(password)

    # Fail on empty passed password. A caller should pass None to indicate the
    # desire to not encrypt.
    if not len(password):
      raise ValueError("encryption password must be 1 or more characters long")

  return password



def _get_key_file_decryption_password(password, prompt, path):
  """Decryption password helper for `import_*_privatekey_from_file` functions.

  Combinations of 'password' and 'prompt' -> result (explanation)
  ----------------------------------------------------------------
  None             False -> return None (clear non-decryption desire)
  "<any string>"   False -> return password (clear decryption desire)
  <anything else>  False -> raise (bad pw type, unclear decryption desire)
  <not None>       True  -> raise (unclear password/prompt precedence)
  None             True  -> prompt and return password if entered and None
                            otherwise (users on the prompt can only indicate
                            desire to not decrypt by entering no password)

  """
  formats.BOOLEAN_SCHEMA.check_match(prompt)

  # We don't want to decide which takes precedence so we fail
  if password is not None and prompt:
    raise ValueError("passing 'password' and 'prompt=True' is not allowed")

  # Prompt user for password
  if prompt:
    password = get_password("enter password to decrypt private key file "
        "'" + TERM_RED + str(path) + TERM_RESET + "' "
        "(leave empty if key not encrypted): ", confirm=False)

    # Treat empty password as no password. A user on the prompt can only
    # indicate the desire to not decrypt by entering no password.
    if not len(password):
      return None

  if password is not None:
    formats.PASSWORD_SCHEMA.check_match(password)
    # No additional vetting needed. Decryption will show if it was correct.

  return password



def _generate_and_write_rsa_keypair(filepath=None, bits=DEFAULT_RSA_KEY_BITS,
    password=None, prompt=False):
  """Generates RSA key pair and writes PEM-encoded keys to disk.

  If a password is passed or entered on the prompt, the private key is
  encrypted. According to the documentation of the used pyca/cryptography
  library, encryption is performed "using the best available encryption for a
  given key's backend", which "is a curated encryption choice and the algorithm
  may change over time."  The private key is written in PKCS#1 and the public
  key in X.509 SubjectPublicKeyInfo format.

  NOTE: A signing scheme can be assigned on key import (see import functions).

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.
    bits (optional): The number of bits of the generated RSA key.
    password (optional): An encryption password.
    prompt (optional): A boolean indicating if the user should be prompted
        for an encryption password. If the user enters an empty password, the
        key is not encrypted.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: An empty string is passed as 'password', or both a 'password'
        is passed and 'prompt' is true.
    StorageError: Key files cannot be written.

  Side Effects:
    Prompts user for a password if 'prompt' is True.
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  formats.RSAKEYBITS_SCHEMA.check_match(bits)

  # Generate private RSA key and extract public and private both in PEM
  rsa_key = keys.generate_rsa_key(bits)
  public = rsa_key['keyval']['public']
  private = rsa_key['keyval']['private']

  # Use passed 'filepath' or keyid as file name
  if not filepath:
    filepath = os.path.join(os.getcwd(), rsa_key['keyid'])

  formats.PATH_SCHEMA.check_match(filepath)

  password = _get_key_file_encryption_password(password, prompt, filepath)

  # Encrypt the private key if a 'password' was passed or entered on the prompt
  if password is not None:
    private = keys.create_rsa_encrypted_pem(private, password)

  # Create intermediate directories as required
  util.ensure_parent_dir(filepath)

  # Write PEM-encoded public key to <filepath>.pub
  file_object = tempfile.TemporaryFile()
  file_object.write(public.encode('utf-8'))
  util.persist_temp_file(file_object, filepath + '.pub')

  # Write PEM-encoded private key to <filepath>
  file_object = tempfile.TemporaryFile()
  file_object.write(private.encode('utf-8'))
  util.persist_temp_file(file_object, filepath)

  return filepath



def generate_and_write_rsa_keypair(password, filepath=None,
      bits=DEFAULT_RSA_KEY_BITS):
  """Generates RSA key pair and writes PEM-encoded keys to disk.

  The private key is encrypted using the best available encryption algorithm
  chosen by 'pyca/cryptography', which may change over time. The private key is
  written in PKCS#1 and the public key in X.509 SubjectPublicKeyInfo format.

  NOTE: A signing scheme can be assigned on key import (see import functions).

  Arguments:
    password: An encryption password.
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.
    bits (optional): The number of bits of the generated RSA key.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: An empty string is passed as 'password'.
    StorageError: Key files cannot be written.

  Side Effects:
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  formats.PASSWORD_SCHEMA.check_match(password)
  return _generate_and_write_rsa_keypair(
      filepath=filepath, bits=bits, password=password, prompt=False)



def generate_and_write_rsa_keypair_with_prompt(filepath=None,
      bits=DEFAULT_RSA_KEY_BITS):
  """Generates RSA key pair and writes PEM-encoded keys to disk.

  The private key is encrypted with a password entered on the prompt, using the
  best available encryption algorithm chosen by 'pyca/cryptography', which may
  change over time. The private key is written in PKCS#1 and the public key in
  X.509 SubjectPublicKeyInfo format.

  NOTE: A signing scheme can be assigned on key import (see import functions).

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.
    bits (optional): The number of bits of the generated RSA key.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    StorageError: Key files cannot be written.

  Side Effects:
    Prompts user for a password.
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  return _generate_and_write_rsa_keypair(
      filepath=filepath, bits=bits, password=None, prompt=True)



def generate_and_write_unencrypted_rsa_keypair(filepath=None,
      bits=DEFAULT_RSA_KEY_BITS):
  """Generates RSA key pair and writes PEM-encoded keys to disk.

  The private key is written in PKCS#1 and the public key in X.509
  SubjectPublicKeyInfo format.

  NOTE: A signing scheme can be assigned on key import (see import functions).

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.
    bits (optional): The number of bits of the generated RSA key.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    StorageError: Key files cannot be written.

  Side Effects:
    Writes unencrypted key files to disk.

  Returns:
    The private key filepath.

  """
  return _generate_and_write_rsa_keypair(
      filepath=filepath, bits=bits, password=None, prompt=False)



def import_rsa_privatekey_from_file(filepath, password=None,
    scheme='rsassa-pss-sha256', prompt=False,
    storage_backend=None):
  """Imports PEM-encoded RSA private key from file storage.

  The expected key format is PKCS#1. If a password is passed or entered on the
  prompt, the private key is decrypted, otherwise it is treated as unencrypted.

  Arguments:
    filepath: The path to read the file from.
    password (optional): A password to decrypt the key.
    scheme (optional): The signing scheme assigned to the returned key object.
        See RSA_SCHEME_SCHEMA for available signing schemes.
    prompt (optional): A boolean indicating if the user should be prompted
        for a decryption password. If the user enters an empty password, the
        key is not decrypted.
    storage_backend (optional): An object implementing StorageBackendInterface.
        If not passed a default FilesystemBackend will be used.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: Both a 'password' is passed and 'prompt' is true.
    StorageError: Key file cannot be read.
    CryptoError: Key cannot be parsed.

  Returns:
    An RSA private key object conformant with 'RSAKEY_SCHEMA'.

  """
  formats.PATH_SCHEMA.check_match(filepath)
  formats.RSA_SCHEME_SCHEMA.check_match(scheme)

  password = _get_key_file_decryption_password(password, prompt, filepath)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  with storage_backend.get(filepath) as file_object:
    pem_key = file_object.read().decode('utf-8')

  # Optionally decrypt and convert PEM-encoded key to 'RSAKEY_SCHEMA' format
  rsa_key = keys.import_rsakey_from_private_pem(pem_key, scheme, password)

  return rsa_key



def import_rsa_publickey_from_file(filepath, scheme='rsassa-pss-sha256',
    storage_backend=None):
  """Imports PEM-encoded RSA public key from file storage.

  The expected key format is X.509 SubjectPublicKeyInfo.

  Arguments:
    filepath: The path to read the file from.
    scheme (optional): The signing scheme assigned to the returned key object.
        See RSA_SCHEME_SCHEMA for available signing schemes.
    storage_backend (optional): An object implementing StorageBackendInterface.
        If not passed a default FilesystemBackend will be used.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    StorageError: Key file cannot be read.
    Error: Public key is malformed.

  Returns:
    An RSA public key object conformant with 'RSAKEY_SCHEMA'.

  """
  formats.PATH_SCHEMA.check_match(filepath)
  formats.RSA_SCHEME_SCHEMA.check_match(scheme)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  with storage_backend.get(filepath) as file_object:
    rsa_pubkey_pem = file_object.read().decode('utf-8')

  # Convert PEM-encoded key to 'RSAKEY_SCHEMA' format
  try:
    rsakey_dict = keys.import_rsakey_from_public_pem(rsa_pubkey_pem, scheme)

  except exceptions.FormatError as e:
    raise exceptions.Error('Cannot import improperly formatted'
      ' PEM file.' + repr(str(e)))

  return rsakey_dict



def _generate_and_write_ed25519_keypair(filepath=None, password=None,
    prompt=False):
  """Generates ed25519 key pair and writes custom JSON-formatted keys to disk.

  If a password is passed or entered on the prompt, the private key is
  encrypted using AES-256 in CTR mode, with the password strengthened in
  PBKDF2-HMAC-SHA256.

  NOTE: The custom key format includes 'ed25519' as signing scheme.

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.
    password (optional): An encryption password.
    prompt (optional): A boolean indicating if the user should be prompted
        for an encryption password. If the user enters an empty password, the
        key is not encrypted.

  Raises:
    UnsupportedLibraryError: pyca/pynacl or pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: An empty string is passed as 'password', or both a 'password'
        is passed and 'prompt' is true.
    StorageError: Key files cannot be written.

  Side Effects:
    Prompts user for a password if 'prompt' is True.
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  ed25519_key = keys.generate_ed25519_key()

  # Use passed 'filepath' or keyid as file name
  if not filepath:
    filepath = os.path.join(os.getcwd(), ed25519_key['keyid'])

  formats.PATH_SCHEMA.check_match(filepath)

  password = _get_key_file_encryption_password(password, prompt, filepath)

  # Create intermediate directories as required
  util.ensure_parent_dir(filepath)

  # Use custom JSON format for ed25519 keys on-disk
  keytype = ed25519_key['keytype']
  keyval = ed25519_key['keyval']
  scheme = ed25519_key['scheme']
  ed25519key_metadata_format = keys.format_keyval_to_metadata(
      keytype, scheme, keyval, private=False)

  # Write public key to <filepath>.pub
  file_object = tempfile.TemporaryFile()
  file_object.write(json.dumps(ed25519key_metadata_format).encode('utf-8'))
  util.persist_temp_file(file_object, filepath + '.pub')

  # Encrypt private key if we have a password, store as JSON string otherwise
  if password is not None:
    ed25519_key = keys.encrypt_key(ed25519_key, password)
  else:
    ed25519_key = json.dumps(ed25519_key)

  # Write private key to <filepath>
  file_object = tempfile.TemporaryFile()
  file_object.write(ed25519_key.encode('utf-8'))
  util.persist_temp_file(file_object, filepath)

  return filepath



def generate_and_write_ed25519_keypair(password, filepath=None):
  """Generates ed25519 key pair and writes custom JSON-formatted keys to disk.

  The private key is encrypted using AES-256 in CTR mode, with the passed
  password strengthened in PBKDF2-HMAC-SHA256.

  NOTE: The custom key format includes 'ed25519' as signing scheme.

  Arguments:
    password: An encryption password.
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.

  Raises:
    UnsupportedLibraryError: pyca/pynacl or pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: An empty string is passed as 'password'.
    StorageError: Key files cannot be written.

  Side Effects:
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  formats.PASSWORD_SCHEMA.check_match(password)
  return _generate_and_write_ed25519_keypair(
      filepath=filepath, password=password, prompt=False)



def generate_and_write_ed25519_keypair_with_prompt(filepath=None):
  """Generates ed25519 key pair and writes custom JSON-formatted keys to disk.

  The private key is encrypted using AES-256 in CTR mode, with the password
  entered on the prompt strengthened in PBKDF2-HMAC-SHA256.

  NOTE: The custom key format includes 'ed25519' as signing scheme.

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.

  Raises:
    UnsupportedLibraryError: pyca/pynacl or pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    StorageError: Key files cannot be written.

  Side Effects:
    Prompts user for a password.
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  return _generate_and_write_ed25519_keypair(
      filepath=filepath, password=None, prompt=True)



def generate_and_write_unencrypted_ed25519_keypair(filepath=None):
  """Generates ed25519 key pair and writes custom JSON-formatted keys to disk.

  NOTE: The custom key format includes 'ed25519' as signing scheme.

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.

  Raises:
    UnsupportedLibraryError: pyca/pynacl or pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    StorageError: Key files cannot be written.

  Side Effects:
    Writes unencrypted key files to disk.

  Returns:
    The private key filepath.

  """
  return _generate_and_write_ed25519_keypair(
      filepath=filepath, password=None, prompt=False)


def import_ed25519_publickey_from_file(filepath):
  """Imports custom JSON-formatted ed25519 public key from disk.

  NOTE: The signing scheme is set at key generation (see generate function).

  Arguments:
    filepath: The path to read the file from.

  Raises:
    FormatError: Argument is malformed.
    StorageError: Key file cannot be read.
    Error: Public key is malformed.

  Returns:
    An ed25519 public key object conformant with 'ED25519KEY_SCHEMA'.

  """
  formats.PATH_SCHEMA.check_match(filepath)

  # Load custom on-disk JSON formatted key and convert to its custom in-memory
  # dict key representation
  ed25519_key_metadata = util.load_json_file(filepath)
  ed25519_key, _ = keys.format_metadata_to_key(ed25519_key_metadata)

  # Check that the generic loading functions indeed loaded an ed25519 key
  if ed25519_key['keytype'] != 'ed25519':
    message = 'Invalid key type loaded: ' + repr(ed25519_key['keytype'])
    raise exceptions.FormatError(message)

  return ed25519_key



def import_ed25519_privatekey_from_file(filepath, password=None, prompt=False,
    storage_backend=None):
  """Imports custom JSON-formatted ed25519 private key from file storage.

  If a password is passed or entered on the prompt, the private key is
  decrypted, otherwise it is treated as unencrypted.

  NOTE: The signing scheme is set at key generation (see generate function).

  Arguments:
    filepath: The path to read the file from.
    password (optional): A password to decrypt the key.
    prompt (optional): A boolean indicating if the user should be prompted
        for a decryption password. If the user enters an empty password, the
        key is not decrypted.
    storage_backend (optional): An object implementing StorageBackendInterface.
        If not passed a default FilesystemBackend will be used.


  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: Both a 'password' is passed and 'prompt' is true.
    StorageError: Key file cannot be read.
    Error, CryptoError: Key cannot be parsed.


  Returns:
    An ed25519 private key object conformant with 'ED25519KEY_SCHEMA'.

  """
  formats.PATH_SCHEMA.check_match(filepath)
  password = _get_key_file_decryption_password(password, prompt, filepath)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  with storage_backend.get(filepath) as file_object:
    json_str = file_object.read()

    # Load custom on-disk JSON formatted key and convert to its custom
    # in-memory dict key representation, decrypting it if password is not None
    return keys.import_ed25519key_from_private_json(
        json_str, password=password)



def _generate_and_write_ecdsa_keypair(filepath=None, password=None,
    prompt=False):
  """Generates ecdsa key pair and writes custom JSON-formatted keys to disk.

  If a password is passed or entered on the prompt, the private key is
  encrypted using AES-256 in CTR mode, with the password strengthened in
  PBKDF2-HMAC-SHA256.

  NOTE: The custom key format includes 'ecdsa-sha2-nistp256' as signing scheme.

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.
    password (optional): An encryption password.
    prompt (optional): A boolean indicating if the user should be prompted
        for an encryption password. If the user enters an empty password, the
        key is not encrypted.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: An empty string is passed as 'password', or both a 'password'
        is passed and 'prompt' is true.
    StorageError: Key files cannot be written.

  Side Effects:
    Prompts user for a password if 'prompt' is True.
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  ecdsa_key = keys.generate_ecdsa_key()

  # Use passed 'filepath' or keyid as file name
  if not filepath:
    filepath = os.path.join(os.getcwd(), ecdsa_key['keyid'])

  formats.PATH_SCHEMA.check_match(filepath)

  password = _get_key_file_encryption_password(password, prompt, filepath)

  # Create intermediate directories as required
  util.ensure_parent_dir(filepath)

  # Use custom JSON format for ecdsa keys on-disk
  keytype = ecdsa_key['keytype']
  keyval = ecdsa_key['keyval']
  scheme = ecdsa_key['scheme']
  ecdsakey_metadata_format = keys.format_keyval_to_metadata(
      keytype, scheme, keyval, private=False)

  # Write public key to <filepath>.pub
  file_object = tempfile.TemporaryFile()
  file_object.write(json.dumps(ecdsakey_metadata_format).encode('utf-8'))
  util.persist_temp_file(file_object, filepath + '.pub')

  # Encrypt private key if we have a password, store as JSON string otherwise
  if password is not None:
    ecdsa_key = keys.encrypt_key(ecdsa_key, password)
  else:
    ecdsa_key = json.dumps(ecdsa_key)

  # Write private key to <filepath>
  file_object = tempfile.TemporaryFile()
  file_object.write(ecdsa_key.encode('utf-8'))
  util.persist_temp_file(file_object, filepath)

  return filepath



def generate_and_write_ecdsa_keypair(password, filepath=None):
  """Generates ecdsa key pair and writes custom JSON-formatted keys to disk.

  The private key is encrypted using AES-256 in CTR mode, with the passed
  password strengthened in PBKDF2-HMAC-SHA256.

  NOTE: The custom key format includes 'ecdsa-sha2-nistp256' as signing scheme.

  Arguments:
    password: An encryption password.
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: An empty string is passed as 'password'.
    StorageError: Key files cannot be written.

  Side Effects:
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  formats.PASSWORD_SCHEMA.check_match(password)
  return _generate_and_write_ecdsa_keypair(
      filepath=filepath, password=password, prompt=False)



def generate_and_write_ecdsa_keypair_with_prompt(filepath=None):
  """Generates ecdsa key pair and writes custom JSON-formatted keys to disk.

  The private key is encrypted using AES-256 in CTR mode, with the password
  entered on the prompt strengthened in PBKDF2-HMAC-SHA256.

  NOTE: The custom key format includes 'ecdsa-sha2-nistp256' as signing scheme.

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    StorageError: Key files cannot be written.

  Side Effects:
    Prompts user for a password.
    Writes key files to disk.

  Returns:
    The private key filepath.

  """
  return _generate_and_write_ecdsa_keypair(
      filepath=filepath, password=None, prompt=True)



def generate_and_write_unencrypted_ecdsa_keypair(filepath=None):
  """Generates ecdsa key pair and writes custom JSON-formatted keys to disk.

  NOTE: The custom key format includes 'ecdsa-sha2-nistp256' as signing scheme.

  Arguments:
    filepath (optional): The path to write the private key to. If not passed,
        the key is written to CWD using the keyid as filename. The public key
        is written to the same path as the private key using the suffix '.pub'.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    StorageError: Key files cannot be written.

  Side Effects:
    Writes unencrypted key files to disk.

  Returns:
    The private key filepath.

  """
  return _generate_and_write_ecdsa_keypair(
      filepath=filepath, password=None, prompt=False)



def import_ecdsa_publickey_from_file(filepath):
  """Imports custom JSON-formatted ecdsa public key from disk.

  NOTE: The signing scheme is set at key generation (see generate function).

  Arguments:
    filepath: The path to read the file from.

  Raises:
    FormatError: Argument is malformed.
    StorageError: Key file cannot be read.
    Error: Public key is malformed.

  Returns:
    An ecdsa public key object conformant with 'ECDSAKEY_SCHEMA'.

  """
  formats.PATH_SCHEMA.check_match(filepath)

  # Load custom on-disk JSON formatted key and convert to its custom in-memory
  # dict key representation
  ecdsa_key_metadata = util.load_json_file(filepath)
  ecdsa_key, _ = keys.format_metadata_to_key(ecdsa_key_metadata)

  return ecdsa_key



def import_ecdsa_privatekey_from_file(filepath, password=None, prompt=False,
    storage_backend=None):
  """Imports custom JSON-formatted ecdsa private key from file storage.

  If a password is passed or entered on the prompt, the private key is
  decrypted, otherwise it is treated as unencrypted.

  NOTE: The signing scheme is set at key generation (see generate function).

  Arguments:
    filepath: The path to read the file from.
    password (optional): A password to decrypt the key.
    prompt (optional): A boolean indicating if the user should be prompted
        for a decryption password. If the user enters an empty password, the
        key is not decrypted.
    storage_backend (optional): An object implementing StorageBackendInterface.
        If not passed a default FilesystemBackend will be used.

  Raises:
    UnsupportedLibraryError: pyca/cryptography is not available.
    FormatError: Arguments are malformed.
    ValueError: Both a 'password' is passed and 'prompt' is true.
    StorageError: Key file cannot be read.
    Error, CryptoError: Key cannot be parsed.

  Returns:
    An ecdsa private key object conformant with 'ED25519KEY_SCHEMA'.

  """
  formats.PATH_SCHEMA.check_match(filepath)

  password = _get_key_file_decryption_password(password, prompt, filepath)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  with storage_backend.get(filepath) as file_object:
    key_data = file_object.read().decode('utf-8')

  # Decrypt private key if we have a password, directly load JSON otherwise
  if password is not None:
    key_object = keys.decrypt_key(key_data, password)
  else:
    key_object = util.load_json_string(key_data)

  # Raise an exception if an unexpected key type is imported.
  # NOTE: we support keytype's of ecdsa-sha2-nistp256 and ecdsa-sha2-nistp384
  # in order to support key files generated with older versions of
  # securesystemslib. At some point this backwards compatibility should be
  # removed.
  if key_object['keytype'] not in['ecdsa', 'ecdsa-sha2-nistp256',
      'ecdsa-sha2-nistp384']:
    message = 'Invalid key type loaded: ' + repr(key_object['keytype'])
    raise exceptions.FormatError(message)

  # Add "keyid_hash_algorithms" so that equal ecdsa keys with different keyids
  # can be associated using supported keyid_hash_algorithms.
  key_object['keyid_hash_algorithms'] = settings.HASH_ALGORITHMS

  return key_object



def import_publickeys_from_file(filepaths, key_types=None):
  """Imports multiple public keys from files.

  NOTE: The default signing scheme 'rsassa-pss-sha256' is assigned to RSA keys.
  Use 'import_rsa_publickey_from_file' to specify any other than the default
  signing scheme for an RSA key. ed25519 and ecdsa keys have the signing scheme
  included in the custom key format (see generate functions).

  Arguments:
    filepaths: A list of paths to public key files.
    key_types (optional): A list of types of keys to be imported associated
        with filepaths by index. Must be one of KEY_TYPE_RSA, KEY_TYPE_ED25519
        or KEY_TYPE_ECDSA. If not specified, all keys are assumed to be
        KEY_TYPE_RSA.

  Raises:
    TypeError: filepaths or 'key_types' (if passed) is not iterable.
    FormatError: Argument are malformed, or 'key_types' is passed and does not
        have the same length as 'filepaths' or contains an unsupported type.
    UnsupportedLibraryError: pyca/cryptography is not available.
    StorageError: Key file cannot be read.
    Error: Public key is malformed.

  Returns:
    A dict of public keys in KEYDICT_SCHEMA format.

  """
  if key_types is None:
    key_types = [KEY_TYPE_RSA] * len(filepaths)

  if len(key_types) != len(filepaths):
    raise exceptions.FormatError(
        "Pass equal amount of 'filepaths' (got {}) and 'key_types (got {}), "
        "or no 'key_types' at all to default to '{}'.".format(
        len(filepaths), len(key_types), KEY_TYPE_RSA))

  key_dict = {}
  for idx, filepath in enumerate(filepaths):
    if key_types[idx] == KEY_TYPE_ED25519:
      key = import_ed25519_publickey_from_file(filepath)

    elif key_types[idx] == KEY_TYPE_RSA:
      key = import_rsa_publickey_from_file(filepath)

    elif key_types[idx] == KEY_TYPE_ECDSA:
      key = import_ecdsa_publickey_from_file(filepath)

    else:
      raise exceptions.FormatError(
          "Unsupported key type '{}'. Must be '{}', '{}' or '{}'.".format(
          key_types[idx], KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA))

    key_dict[key["keyid"]] = key

  return key_dict



def import_privatekey_from_file(filepath, key_type=None, password=None,
    prompt=False):
  """Imports private key from file.

  If a password is passed or entered on the prompt, the private key is
  decrypted, otherwise it is treated as unencrypted.

  NOTE: The default signing scheme 'rsassa-pss-sha256' is assigned to RSA keys.
  Use 'import_rsa_privatekey_from_file' to specify any other than the default
  signing scheme for an RSA key. ed25519 and ecdsa keys have the signing scheme
  included in the custom key format (see generate functions).

  Arguments:
    filepath: The path to read the file from.
    key_type (optional): One of KEY_TYPE_RSA, KEY_TYPE_ED25519 or
        KEY_TYPE_ECDSA. Default is KEY_TYPE_RSA.
    password (optional): A password to decrypt the key.
    prompt (optional): A boolean indicating if the user should be prompted
        for a decryption password. If the user enters an empty password, the
        key is not decrypted.

  Raises:
    FormatError: Arguments are malformed or 'key_type' is not supported.
    ValueError: Both a 'password' is passed and 'prompt' is true.
    UnsupportedLibraryError: pyca/cryptography is not available.
    StorageError: Key file cannot be read.
    Error, CryptoError: Key cannot be parsed.

  Returns:
    A private key object conformant with one of 'ED25519KEY_SCHEMA',
    'RSAKEY_SCHEMA' or 'ECDSAKEY_SCHEMA'.

  """
  if key_type is None:
    key_type = KEY_TYPE_RSA

  if key_type == KEY_TYPE_ED25519:
    return import_ed25519_privatekey_from_file(
        filepath, password=password, prompt=prompt)

  elif key_type == KEY_TYPE_RSA:
    return import_rsa_privatekey_from_file(
        filepath, password=password, prompt=prompt)

  elif key_type == KEY_TYPE_ECDSA:
    return import_ecdsa_privatekey_from_file(
        filepath, password=password, prompt=prompt)

  else:
    raise exceptions.FormatError(
        "Unsupported key type '{}'. Must be '{}', '{}' or '{}'.".format(
        key_type, KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA))



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running interface.py as a standalone module:
  # $ python interface.py.
  import doctest
  doctest.testmod()
