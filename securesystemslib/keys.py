#!/usr/bin/env python

"""
<Program Name>
  keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 4, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to centralize cryptographic key routines and their
  supported operations (e.g., creating and verifying signatures).  This module
  is designed to support multiple public-key algorithms, such as RSA, Ed25519,
  and ECDSA, and multiple cryptography libraries.  Which cryptography library
  to use is determined by the default, or user modified, values set in
  'settings.py'

  https://en.wikipedia.org/wiki/RSA_(algorithm)
  http://ed25519.cr.yp.to/
  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

  The (RSA, ECDSA and Ed25519)-related functions provided include
  generate_rsa_key(), generate_ed25519_key(), generate_ecdsa_key(),
  create_signature(), and verify_signature().  The cryptography libraries
  called by 'securesystemslib.keys.py' generate the actual keys and the
  functions listed above can be viewed as the easy-to-use public interface.

  Additional functions contained here include format_keyval_to_metadata() and
  format_metadata_to_key().  These last two functions produce or use keys
  compatible with the key structures listed in Metadata files.  The key
  generation functions return a dictionary containing all the information needed
  of keys, such as public & private keys, and a keyID.  create_signature()
  and verify_signature() are supplemental functions needed for generating
  signatures and verifying them.

  Key IDs are used as identifiers for keys (e.g., RSA key).  They are the
  hexadecimal representation of the hash of the key object (specifically, the
  key object containing only the public key).  Review the '_get_keyid()'
  function of this module to see precisely how keyids are generated.  One may
  get the keyid of a key object by simply accessing the dictionary's 'keyid'
  key (i.e., rsakey['keyid']).
 """

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# Required for hexadecimal conversions.  Signatures and public/private keys are
# hexlified.
import binascii

# NOTE:  'warnings' needed to temporarily suppress user warnings raised by
# 'pynacl' (as of version 0.2.3).
# http://docs.python.org/2/library/warnings.html#temporarily-suppressing-warnings
import warnings
import logging

# 'pycrypto' and 'cryptography' are the only currently supported libraries for
# the creation of RSA keys.
# https://github.com/dlitz/pycrypto
# https://github.com/pyca/cryptography
_SUPPORTED_RSA_CRYPTO_LIBRARIES = ['pycrypto', 'pyca-cryptography']

# The currently supported libraries for the creation of ed25519 keys and
# signatures.  The 'pynacl' library should be installed and used over the
# slower python implementation of ed25519.  The python implementation will be
# used if 'pynacl' is unavailable.
_SUPPORTED_ED25519_CRYPTO_LIBRARIES = ['ed25519', 'pynacl']

# The currently supported libraries for the creation of ECDSA keys and
# signatures.
_SUPPORTED_ECDSA_CRYPTO_LIBRARIES = ['pyca-cryptography']

# 'pycrypto' and 'cryptography' are the only currently supported libraries for
# general-purpose cryptography.
# https://github.com/dlitz/pycrypto
# https://github.com/pyca/cryptography
_SUPPORTED_GENERAL_CRYPTO_LIBRARIES = ['pycrypto', 'pyca-cryptography']

# Track which libraries are imported and thus available.  An optimized version
# of the ed25519 python implementation is provided (available by default).
# https://github.com/pyca/ed25519
_available_crypto_libraries = ['ed25519']

# Try to import the PyCrypto module (pycrypto_keys.py), which is used here
# for general-purpose cryptography and generation of RSA keys and signatures.
try:
  import securesystemslib.pycrypto_keys
  _available_crypto_libraries.append('pycrypto')

except ImportError: # pragma: no cover
  pass

# Try to import the pyca/Cryptography module (pyca_crypto_keys.py), which is
# used for general-purpose cryptography and generation of RSA keys and
# signatures.
try:
  import securesystemslib.pyca_crypto_keys
  _available_crypto_libraries.append('pyca-cryptography')

except ImportError: # pragma: no cover
  pass

# Import the PyNaCl library, if available.  It is recommended this library be
# used over the pure python implementation of ed25519, due to its speedier
# routines and side-channel protections available in the libsodium library.

# NOTE: Version 0.2.3 of 'pynacl' prints: "UserWarning: reimporting '...' might
# overwrite older definitions." when importing 'nacl.signing' below.  Suppress
# user warnings temporarily (at least until this issue is fixed).
with warnings.catch_warnings():
  warnings.simplefilter('ignore')
  try:
    import nacl
    import nacl.signing
    _available_crypto_libraries.append('pynacl')

  # PyNaCl's 'cffi' dependency may raise an 'IOError' exception when importing
  # 'nacl.signing'.
  except (ImportError, IOError): # pragma: no cover
    pass

# The optimized version of the Ed25519 library provided by default is imported
# regardless of the availability of PyNaCl.
import securesystemslib.ed25519_keys

import securesystemslib.ecdsa_keys
import securesystemslib.exceptions

# Digest objects needed to generate hashes.
import securesystemslib.hash

# Perform format checks of argument objects.
import securesystemslib.formats

# The hash algorithm to use in the generation of keyids.
_KEY_ID_HASH_ALGORITHM = 'sha256'

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.
_DEFAULT_RSA_KEY_BITS = 3072

# The crypto libraries to use in 'keys.py', set by default or by the user.
# The following cryptography libraries are currently supported:
# ['pycrypto', 'pynacl', 'ed25519', 'pyca-cryptography']
_RSA_CRYPTO_LIBRARY = securesystemslib.settings.RSA_CRYPTO_LIBRARY
_ED25519_CRYPTO_LIBRARY = securesystemslib.settings.ED25519_CRYPTO_LIBRARY
_ECDSA_CRYPTO_LIBRARY = securesystemslib.settings.ECDSA_CRYPTO_LIBRARY
_GENERAL_CRYPTO_LIBRARY = securesystemslib.settings.GENERAL_CRYPTO_LIBRARY

logger = logging.getLogger('securesystemslib_keys')


def generate_rsa_key(bits=_DEFAULT_RSA_KEY_BITS):
  """
  <Purpose>
    Generate public and private RSA keys, with modulus length 'bits'.  In
    addition, a keyid identifier for the RSA key is generated.  The object
    returned conforms to 'securesystemslib.formats.RSAKEY_SCHEMA' and has the
    form:

    {'keytype': 'rsa',
     'keyid': keyid,
     'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

    The public and private keys are strings in PEM format.

    Although the PyCrypto and PyCA cryptography libraries do set a minimum key
    size (e.g., 1024-bit minimum in PyCrypto), generate() enforces a minimum
    key size of 2048 bits.  If 'bits' is unspecified, a 3072-bit RSA key is
    generated, which is the key size recommended by securesystemslib.  These
    key size restrictions are only enforced for keys generated within
    securesystemslib.  RSA keys with sizes lower than what we recommended may
    still be imported (e.g., with import_rsakey_from_pem().

    >>> rsa_key = generate_rsa_key(bits=2048)
    >>> securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key)
    True
    >>> public = rsa_key['keyval']['public']
    >>> private = rsa_key['keyval']['private']
    >>> securesystemslib.formats.PEMRSA_SCHEMA.matches(public)
    True
    >>> securesystemslib.formats.PEMRSA_SCHEMA.matches(private)
    True

  <Arguments>
    bits:
      The key size, or key length, of the RSA key.  'bits' must be 2048, or
      greater, and a multiple of 256.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'bits' is improperly or invalid
    (i.e., not an integer and not at least 2048).

    securesystemslib.exceptions.UnsupportedLibraryError, if any of the cryptography
    libraries specified in 'settings.py' are unsupported or unavailable.

    ValueError, if an exception occurs after calling the RSA key generation
    routine.  'bits' must be a multiple of 256 if PyCrypto is set via
    'settings.py'.  The 'ValueError' exception is raised by the key generation
    function of the cryptography library called.

  <Side Effects>
    The RSA keys are generated by calling PyCrypto's
    Crypto.PublicKey.RSA.generate().

  <Returns>
    A dictionary containing the RSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.RSAKEY_SCHEMA'.
  """

  # Does 'bits' have the correct format?
  # This check will ensure 'bits' conforms to
  # 'securesystemslib.formats.RSAKEYBITS_SCHEMA'.  'bits' must be an integer object,
  # with a minimum value of 2048.  Raise 'securesystemslib.exceptions.FormatError'
  # if the check fails.
  securesystemslib.formats.RSAKEYBITS_SCHEMA.check_match(bits)

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'settings.RSA_CRYPTO_LIBRARY'.
  check_crypto_libraries(['rsa'])

  # Begin building the RSA key dictionary.
  rsakey_dict = {}
  keytype = 'rsa'
  public = None
  private = None

  # Generate the public and private RSA keys.  The PyCrypto module performs
  # the actual key generation.  Raise 'ValueError' if 'bits' is less than 1024
  # or not a multiple of 256, although a 2048-bit minimum is enforced by
  # securesystemslib.formats.RSAKEYBITS_SCHEMA.check_match().
  if _RSA_CRYPTO_LIBRARY == 'pycrypto':
    public, private = securesystemslib.pycrypto_keys.generate_rsa_public_and_private(bits)

  # Unlike PyCrypto, PyCA Cryptography does not require 'bits' to be a multiple
  # 256.
  elif _RSA_CRYPTO_LIBRARY == 'pyca-cryptography':
    public, private = securesystemslib.pyca_crypto_keys.generate_rsa_public_and_private(bits)

  else: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('Invalid crypto'
      ' library: ' + repr(_RSA_CRYPTO_LIBRARY) + '.')

  # Generate the keyid of the RSA key.  Note: The private key material is
  # not included in the generation of the 'keyid' identifier.
  key_value = {'public': public,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  # Build the 'rsakey_dict' dictionary.  Update 'key_value' with the RSA
  # private key prior to adding 'key_value' to 'rsakey_dict'.
  key_value['private'] = private

  rsakey_dict['keytype'] = keytype
  rsakey_dict['keyid'] = keyid
  rsakey_dict['keyid_hash_algorithms'] = securesystemslib.settings.HASH_ALGORITHMS
  rsakey_dict['keyval'] = key_value

  return rsakey_dict





def generate_ecdsa_key(algorithm='ecdsa-sha2-nistp256'):
  """
  <Purpose>
    Generate public and private ECDSA keys, with NIST P-256 + SHA256 (for
    hashing) being the default algorithm.  In addition, a keyid identifier for
    the ECDSA key is generated.  The object returned conforms to
    'securesystemslib.formats.ECDSAKEY_SCHEMA' and has the form:

    {'keytype': 'ecdsa-sha2-nistp256',
     'keyid': keyid,
     'keyval': {'public': '',
                'private': ''}}

    The public and private keys are strings in TODO format.

    >>> ecdsa_key = generate_ecdsa_key(algorithm='ecdsa-sha2-nistp256')
    >>> securesystemslib.formats.ECDSAKEY_SCHEMA.matches(ecdsa_key)
    True

  <Arguments>
    algorithm:
      The ECDSA algorithm.  By default, ECDSA NIST P-256 is used, with SHA256
      for hashing.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'algorithm' is improperly or invalid
    (i.e., not one of the supported ECDSA algorithms).

    securesystemslib.exceptions.UnsupportedLibraryError, if any of the cryptography
    libraries specified in 'settings.py' are unsupported or unavailable.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the ECDSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.ECDSAKEY_SCHEMA'.
  """

  # Does 'algorithm' have the correct format?  This check will ensure
  # 'algorithm is properly formatted and is a supported ECDSA algorithm.  Raise
  # 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.ECDSAALGORITHMS_SCHEMA.check_match(algorithm)

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'securesystemslib.settings.ECDSA_CRYPTO_LIBRARY'.
  check_crypto_libraries(['ecdsa-sha2-nistp256'])

  # Begin building the ECDSA key dictionary.
  ecdsa_key = {}
  keytype = algorithm
  public = None
  private = None

  # Generate the public and private ECDSA keys with one of the supported
  # libraries.
  if 'pyca-cryptography' in _available_crypto_libraries:
    public, private = \
      securesystemslib.ecdsa_keys.generate_public_and_private(algorithm)

  else: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('One of the'
      ' supported libraries is unavailable.')

  # Generate the keyid of the Ed25519 key.  'key_value' corresponds to the
  # 'keyval' entry of the 'Ed25519KEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  key_value = {'public': public,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  # Build the 'ed25519_key' dictionary.  Update 'key_value' with the Ed25519
  # private key prior to adding 'key_value' to 'ed25519_key'.

  key_value['private'] = private

  ecdsa_key['keytype'] = keytype
  ecdsa_key['keyid'] = keyid
  ecdsa_key['keyval'] = key_value

  # Add "keyid_hash_algorithms" so that equal ECDSA keys with different keyids
  # can be associated using supported keyid_hash_algorithms.
  ecdsa_key['keyid_hash_algorithms'] = \
      securesystemslib.settings.HASH_ALGORITHMS

  return ecdsa_key





def generate_ed25519_key():
  """
  <Purpose>
    Generate public and private ED25519 keys, both of length 32-bytes, although
    they are hexlified to 64 bytes.  In addition, a keyid identifier generated
    for the returned ED25519 object.  The object returned conforms to
    'securesystemslib.formats.ED25519KEY_SCHEMA' and has the form:

    {'keytype': 'ed25519',
     'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
     'keyval': {'public': '9ccf3f02b17f82febf5dd3bab878b767d8408...',
                'private': 'ab310eae0e229a0eceee3947b6e0205dfab3...'}}

    >>> ed25519_key = generate_ed25519_key()
    >>> securesystemslib.formats.ED25519KEY_SCHEMA.matches(ed25519_key)
    True
    >>> len(ed25519_key['keyval']['public'])
    64
    >>> len(ed25519_key['keyval']['private'])
    64

  <Arguments>
    None.

  <Exceptions>
    securesystemslib.exceptions.UnsupportedLibraryError, if an unsupported or
    unavailable library is detected.

  <Side Effects>
    The ED25519 keys are generated by calling either the optimized pure Python
    implementation of ed25519, or the ed25519 routines provided by 'pynacl'.

  <Returns>
    A dictionary containing the ED25519 keys and other identifying information.
    Conforms to 'securesystemslib.formats.ED25519KEY_SCHEMA'.
  """

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'securesystemslib.settings.ED25519_CRYPTO_LIBRARY'.
  check_crypto_libraries(['ed25519'])

  # Begin building the Ed25519 key dictionary.
  ed25519_key = {}
  keytype = 'ed25519'
  public = None
  private = None

  # Generate the public and private Ed25519 key with the 'pynacl' library.
  # Unlike in the verification of Ed25519 signatures, do not fall back to the
  # optimized, pure python implementation provided by PyCA.  Ed25519 should
  # always be generated with a backend like libsodium to prevent side-channel
  # attacks.
  if 'pynacl' in _available_crypto_libraries:
    public, private = \
      securesystemslib.ed25519_keys.generate_public_and_private()

  else: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('The required PyNaCl'
      ' library is unavailable.')

  # Generate the keyid of the Ed25519 key.  'key_value' corresponds to the
  # 'keyval' entry of the 'Ed25519KEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  key_value = {'public': binascii.hexlify(public).decode(),
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  # Build the 'ed25519_key' dictionary.  Update 'key_value' with the Ed25519
  # private key prior to adding 'key_value' to 'ed25519_key'.
  key_value['private'] = binascii.hexlify(private).decode()

  ed25519_key['keytype'] = keytype
  ed25519_key['keyid'] = keyid
  ed25519_key['keyid_hash_algorithms'] = securesystemslib.settings.HASH_ALGORITHMS
  ed25519_key['keyval'] = key_value

  return ed25519_key





def format_keyval_to_metadata(keytype, key_value, private=False):
  """
  <Purpose>
    Return a dictionary conformant to 'securesystemslib.formats.KEY_SCHEMA'.
    If 'private' is True, include the private key.  The dictionary
    returned has the form:

    {'keytype': keytype,
     'keyval': {'public': '...',
                'private': '...'}}

    or if 'private' is False:

    {'keytype': keytype,
     'keyval': {'public': '...',
                'private': ''}}

    >>> ed25519_key = generate_ed25519_key()
    >>> key_val = ed25519_key['keyval']
    >>> keytype = ed25519_key['keytype']
    >>> ed25519_metadata = \
    format_keyval_to_metadata(keytype, key_val, private=True)
    >>> securesystemslib.formats.KEY_SCHEMA.matches(ed25519_metadata)
    True

  <Arguments>
    key_type:
      The 'rsa' or 'ed25519' strings.

    key_value:
      A dictionary containing a private and public keys.
      'key_value' is of the form:

      {'public': '...',
       'private': '...'}},

      conformant to 'securesystemslib.formats.KEYVAL_SCHEMA'.

    private:
      Indicates if the private key should be included in the dictionary
      returned.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'key_value' does not conform to
    'securesystemslib.formats.KEYVAL_SCHEMA', or if the private key is not present in
    'key_value' if requested by the caller via 'private'.

  <Side Effects>
    None.

  <Returns>
    A 'securesystemslib.formats.KEY_SCHEMA' dictionary.
  """

  # Does 'keytype' have the correct format?
  # This check will ensure 'keytype' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.KEYTYPE_SCHEMA.check_match(keytype)

  # Does 'key_value' have the correct format?
  securesystemslib.formats.KEYVAL_SCHEMA.check_match(key_value)

  if private is True:
    # If the caller requests (via the 'private' argument) to include a private
    # key in the returned dictionary, ensure the private key is actually
    # present in 'key_val' (a private key is optional for 'KEYVAL_SCHEMA'
    # dicts).
    if 'private' not in key_value:
      raise securesystemslib.exceptions.FormatError('The required private key'
        ' is missing from: ' + repr(key_value))

    else:
      return {'keytype': keytype, 'keyval': key_value}

  else:
    public_key_value = {'public': key_value['public']}

    return {'keytype': keytype,
            'keyid_hash_algorithms': securesystemslib.settings.HASH_ALGORITHMS,
            'keyval': public_key_value}





def format_metadata_to_key(key_metadata):
  """
  <Purpose>
    Construct a key dictionary (e.g., securesystemslib.formats.RSAKEY_SCHEMA)
    according to the keytype of 'key_metadata'.  The dict returned by this
    function has the exact format as the dict returned by one of the key
    generations functions, like generate_ed25519_key().  The dict returned
    has the form:

    {'keytype': keytype,
     'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
     'keyval': {'public': '...',
                'private': '...'}}

    For example, RSA key dictionaries in RSAKEY_SCHEMA format should be used by
    modules storing a collection of keys, such as with keydb.py.  RSA keys as
    stored in metadata files use a different format, so this function should be
    called if an RSA key is extracted from one of these metadata files and need
    converting.  The key generation functions create an entirely new key and
    return it in the format appropriate for 'keydb.py'.

    >>> ed25519_key = generate_ed25519_key()
    >>> key_val = ed25519_key['keyval']
    >>> keytype = ed25519_key['keytype']
    >>> ed25519_metadata = \
    format_keyval_to_metadata(keytype, key_val, private=True)
    >>> ed25519_key_2, junk = format_metadata_to_key(ed25519_metadata)
    >>> securesystemslib.formats.ED25519KEY_SCHEMA.matches(ed25519_key_2)
    True
    >>> ed25519_key == ed25519_key_2
    True

  <Arguments>
    key_metadata:
      The key dictionary as stored in Metadata files, conforming to
      'securesystemslib.formats.KEY_SCHEMA'.  It has the form:

      {'keytype': '...',
       'keyval': {'public': '...',
                  'private': '...'}}

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'key_metadata' does not conform to
    'securesystemslib.formats.KEY_SCHEMA'.

  <Side Effects>
    None.

  <Returns>
    In the case of an RSA key, a dictionary conformant to
    'securesystemslib.formats.RSAKEY_SCHEMA'.
  """

  # Does 'key_metadata' have the correct format?
  # This check will ensure 'key_metadata' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.KEY_SCHEMA.check_match(key_metadata)

  # Construct the dictionary to be returned.
  key_dict = {}
  keytype = key_metadata['keytype']
  key_value = key_metadata['keyval']

  # Convert 'key_value' to 'securesystemslib.formats.KEY_SCHEMA' and generate its
  # hash The hash is in hexdigest form.
  default_keyid = _get_keyid(keytype, key_value)
  keyids = set()
  keyids.add(default_keyid)

  for hash_algorithm in securesystemslib.settings.HASH_ALGORITHMS:
    keyid = _get_keyid(keytype, key_value, hash_algorithm)
    keyids.add(keyid)

  # All the required key values gathered.  Build 'key_dict'.
  # 'keyid_hash_algorithms'
  key_dict['keytype'] = keytype
  key_dict['keyid'] = default_keyid
  key_dict['keyid_hash_algorithms'] = securesystemslib.settings.HASH_ALGORITHMS
  key_dict['keyval'] = key_value

  return key_dict, keyids



def _get_keyid(keytype, key_value, hash_algorithm = 'sha256'):
  """Return the keyid of 'key_value'."""

  # 'keyid' will be generated from an object conformant to KEY_SCHEMA,
  # which is the format Metadata files (e.g., root.json) store keys.
  # 'format_keyval_to_metadata()' returns the object needed by _get_keyid().
  key_meta = format_keyval_to_metadata(keytype, key_value, private=False)

  # Convert the key to JSON Canonical format, suitable for adding
  # to digest objects.
  key_update_data = securesystemslib.formats.encode_canonical(key_meta)

  # Create a digest object and call update(), using the JSON
  # canonical format of 'rskey_meta' as the update data.
  digest_object = securesystemslib.hash.digest(_KEY_ID_HASH_ALGORITHM)
  digest_object.update(key_update_data.encode('utf-8'))

  # 'keyid' becomes the hexadecimal representation of the hash.
  keyid = digest_object.hexdigest()

  return keyid





def check_crypto_libraries(required_libraries):
  """
  <Purpose>
    Public function that ensures the cryptography libraries specified in
    'settings' are supported and available for each 'required_libraries'.

  <Arguments>
    required_libraries:
      A list of library strings to validate.  One, or multiple, strings from
      ['rsa', 'ed25519', 'general'] can be specified.

  <Exceptions>
    securesystemslib.exceptions.UnsupportedLibraryError, if the 'required_libraries'
    and the libraries specified in 'settings' are not supported or unavailable.

  <Side Effects>
    Validates the libraries set in 'settings'.

  <Returns>
    None.
  """

  # Does 'required_libraries' have the correct format?
  # This check will ensure 'required_libraries' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.REQUIRED_LIBRARIES_SCHEMA.check_match(required_libraries)

  # The checks below all raise 'securesystemslib.exceptions.UnsupportedLibraryError'
  # if the general, RSA, and Ed25519 crypto libraries specified in
  # 'settings.py' are not supported or unavailable.  The appropriate error
  # message is added to the exception.  The funcions of this module that depend
  # on user-installed crypto libraries should call this private function to
  # ensure the called routine does not fail with unpredictable exceptions in
  # the event of a missing library.  The supported and available lists checked
  # are populated when 'securesystemslib.keys.py' is imported.

  if 'rsa' in required_libraries and _RSA_CRYPTO_LIBRARY not in \
                                   _SUPPORTED_RSA_CRYPTO_LIBRARIES:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_RSA_CRYPTO_LIBRARY) +
      ' crypto library specified in "securesystemslib.settings.RSA_CRYPTO_LIBRARY" is not '
      ' supported.\nSupported crypto libraries: ' +
      repr(_SUPPORTED_RSA_CRYPTO_LIBRARIES) + '.')

  if 'ed25519' in required_libraries and _ED25519_CRYPTO_LIBRARY not in \
                                         _SUPPORTED_ED25519_CRYPTO_LIBRARIES:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_ED25519_CRYPTO_LIBRARY) +
      ' crypto library specified in "settings.ED25519_CRYPTO_LIBRARY" is not '
      ' supported.\nSupported crypto libraries: ' +
      repr(_SUPPORTED_ED25519_CRYPTO_LIBRARIES) + '.')

  if 'ecdsa-sha2-nistp256' in required_libraries and _ECDSA_CRYPTO_LIBRARY not in \
                                         _SUPPORTED_ECDSA_CRYPTO_LIBRARIES:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_ECDSA_CRYPTO_LIBRARY) +
      ' crypto library specified in "settings.ECDSA_CRYPTO_LIBRARY" is not '
      ' supported.\nSupported crypto libraries: ' +
      repr(_SUPPORTED_ECDSA_CRYPTO_LIBRARIES) + '.')

  if 'general' in required_libraries and _GENERAL_CRYPTO_LIBRARY not in \
                                         _SUPPORTED_GENERAL_CRYPTO_LIBRARIES:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_GENERAL_CRYPTO_LIBRARY) +
      ' crypto library specified in "settings.GENERAL_CRYPTO_LIBRARY" is not'
      ' supported.\nSupported crypto libraries: ' +
      repr(_SUPPORTED_GENERAL_CRYPTO_LIBRARIES) + '.')



  if 'rsa' in required_libraries and _RSA_CRYPTO_LIBRARY not in \
                                     _available_crypto_libraries:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_RSA_CRYPTO_LIBRARY) +
      ' crypto library specified in "settings.RSA_CRYPTO_LIBRARY" could not'
      ' be imported.  Available libraries: ' + repr(_available_crypto_libraries))

  if 'ed25519' in required_libraries and _ED25519_CRYPTO_LIBRARY not in \
                                         _available_crypto_libraries:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_ED25519_CRYPTO_LIBRARY) +
      ' crypto library specified in "settings.ED25519_CRYPTO_LIBRARY" could'
      ' not be imported.')

  if 'ecdsa-sha2-nistp256' in required_libraries and _ECDSA_CRYPTO_LIBRARY not in \
                                         _available_crypto_libraries:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_ECDSA_CRYPTO_LIBRARY) +
      ' crypto library specified in "settings.ECDSA_CRYPTO_LIBRARY" could'
      ' not be imported.')

  if 'general' in required_libraries and _GENERAL_CRYPTO_LIBRARY not in \
                                         _available_crypto_libraries:
    raise securesystemslib.exceptions.UnsupportedLibraryError('The ' + repr(_GENERAL_CRYPTO_LIBRARY) +
      ' crypto library specified in "settings.GENERAL_CRYPTO_LIBRARY" could'
      ' not be imported.')





def create_signature(key_dict, data):
  """
  <Purpose>
    Return a signature dictionary of the form:
    {'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
     'method': '...',
     'sig': '...'}.

    The signing process will use the private key in
    key_dict['keyval']['private'] and 'data' to generate the signature.

    The following signature methods are supported:

    'RSASSA-PSS'
    RFC3447 - RSASSA-PSS
    http://www.ietf.org/rfc/rfc3447.

    'ed25519'
    ed25519 - high-speed high security signatures
    http://ed25519.cr.yp.to/

    Which signature to generate is determined by the key type of 'key_dict'
    and the available cryptography library specified in 'settings'.

    >>> ed25519_key = generate_ed25519_key()
    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> signature = create_signature(ed25519_key, data)
    >>> securesystemslib.formats.SIGNATURE_SCHEMA.matches(signature)
    True
    >>> len(signature['sig'])
    128
    >>> rsa_key = generate_rsa_key(2048)
    >>> signature = create_signature(rsa_key, data)
    >>> securesystemslib.formats.SIGNATURE_SCHEMA.matches(signature)
    True
    >>> ecdsa_key = generate_ecdsa_key()
    >>> signature = create_signature(ecdsa_key, data)
    >>> securesystemslib.formats.SIGNATURE_SCHEMA.matches(signature)
    True

  <Arguments>
    key_dict:
      A dictionary containing the keys.  An example RSA key dict has the
      form:

      {'keytype': 'rsa',
       'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
       'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                  'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

      The public and private keys are strings in PEM format.

    data:
      Data object used by create_signature() to generate the signature.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'key_dict' is improperly formatted.

    securesystemslib.exceptions.UnsupportedLibraryError, if an unsupported or
    unavailable library is detected.

    TypeError, if 'key_dict' contains an invalid keytype.

  <Side Effects>
    The cryptography library specified in 'settings' called to perform the
    actual signing routine.

  <Returns>
    A signature dictionary conformant to 'securesystemslib_format.SIGNATURE_SCHEMA'.
  """

  # Does 'key_dict' have the correct format?
  # This check will ensure 'key_dict' has the appropriate number of objects
  # and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  # The key type of 'key_dict' must be either 'rsa' or 'ed25519'.
  securesystemslib.formats.ANYKEY_SCHEMA.check_match(key_dict)

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'settings.RSA_CRYPTO_LIBRARY' or 'settings.ED25519_CRYPTO_LIBRARY'.
  check_crypto_libraries([key_dict['keytype']])

  # Signing the 'data' object requires a private key.
  # 'RSASSA-PSS' and 'ed25519' are the only signing methods currently
  # supported.  RSASSA-PSS keys and signatures can be generated and verified by
  # the PyCrypto and 'cryptography' modules, and Ed25519's by PyNaCl and PyCA's
  # optimized, pure python implementation of Ed25519.
  signature = {}
  keytype = key_dict['keytype']
  public = key_dict['keyval']['public']
  private = key_dict['keyval']['private']
  keyid = key_dict['keyid']
  method = None
  sig = None

  # Convert 'data' to canonical JSON format so that repeatable signatures are
  # generated across different platforms and Python key dictionaries.  The
  # resulting 'data' is a string encoded in UTF-8 and compatible with the input
  # expected by the cryptography functions called below.
  data = securesystemslib.formats.encode_canonical(data)

  # Call the appropriate cryptography libraries for the supported key types,
  # otherwise raise an exception.
  if keytype == 'rsa':
    if _RSA_CRYPTO_LIBRARY == 'pycrypto':
      sig, method = securesystemslib.pycrypto_keys.create_rsa_signature(private,
        data.encode('utf-8'))

    elif _RSA_CRYPTO_LIBRARY == 'pyca-cryptography':
      sig, method = securesystemslib.pyca_crypto_keys.create_rsa_signature(private,
        data.encode('utf-8'))

    else: # pragma: no cover
      raise securesystemslib.exceptions.UnsupportedLibraryError('Unsupported'
        ' "settings.RSA_CRYPTO_LIBRARY": ' + repr(_RSA_CRYPTO_LIBRARY) + '.')

  elif keytype == 'ed25519':
    public = binascii.unhexlify(public.encode('utf-8'))
    private = binascii.unhexlify(private.encode('utf-8'))
    if 'pynacl' in _available_crypto_libraries:
      sig, method = securesystemslib.ed25519_keys.create_signature(public, private,
        data.encode('utf-8'))

    else: # pragma: no cover
      raise securesystemslib.exceptions.UnsupportedLibraryError('The required'
        ' PyNaCl library is unavailable.')

  elif keytype == 'ecdsa-sha2-nistp256':
    if _ECDSA_CRYPTO_LIBRARY == 'pyca-cryptography':
      sig, method = securesystemslib.ecdsa_keys.create_signature(public, private,
        data.encode('utf-8'))

    else: # pragma: no cover
      raise securesystemslib.exceptions.UnsupportedLibraryError('Unsupported'
        ' "settings.ECDSA_CRYPTO_LIBRARY": ' + repr(_ECDSA_CRYPTO_LIBRARY) + '.')

  # 'securesystemslib.formats.ANYKEY_SCHEMA' should detect invalid key types.
  else: # pragma: no cover
    raise TypeError('Invalid key type.')

  # Build the signature dictionary to be returned.
  # The hexadecimal representation of 'sig' is stored in the signature.
  signature['keyid'] = keyid
  signature['method'] = method
  signature['sig'] = binascii.hexlify(sig).decode()

  return signature





def verify_signature(key_dict, signature, data):
  """
  <Purpose>
    Determine whether the private key belonging to 'key_dict' produced
    'signature'.  verify_signature() will use the public key found in
    'key_dict', the 'method' and 'sig' objects contained in 'signature',
    and 'data' to complete the verification.

    >>> ed25519_key = generate_ed25519_key()
    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> signature = create_signature(ed25519_key, data)
    >>> verify_signature(ed25519_key, signature, data)
    True
    >>> verify_signature(ed25519_key, signature, 'bad_data')
    False
    >>> rsa_key = generate_rsa_key()
    >>> signature = create_signature(rsa_key, data)
    >>> verify_signature(rsa_key, signature, data)
    True
    >>> verify_signature(rsa_key, signature, 'bad_data')
    False
    >>> ecdsa_key = generate_ecdsa_key()
    >>> signature = create_signature(ecdsa_key, data)
    >>> verify_signature(ecdsa_key, signature, data)
    True
    >>> verify_signature(ecdsa_key, signature, 'bad_data')
    False

  <Arguments>
    key_dict:
      A dictionary containing the keys and other identifying information.
      If 'key_dict' is an RSA key, it has the form:

      {'keytype': 'rsa',
       'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
       'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                  'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

      The public and private keys are strings in PEM format.

    signature:
      The signature dictionary produced by one of the key generation functions.
      'signature' has the form:

      {'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
       'method': 'method',
       'sig': sig}.

      Conformant to 'securesystemslib.formats.SIGNATURE_SCHEMA'.

    data:
      Data object used by securesystemslib.rsa_key.create_signature() to generate
      'signature'.  'data' is needed here to verify the signature.

  <Exceptions>
    securesystemslib.exceptions.FormatError, raised if either 'key_dict' or
    'signature' are improperly formatted.

    securesystemslib.exceptions.UnsupportedLibraryError, if an unsupported or
    unavailable library is detected.

    securesystemslib.exceptions.UnknownMethodError.  Raised if the signing method
    used by 'signature' is not one supported.

  <Side Effects>
    The cryptography library specified in 'settings' called to do the actual
    verification.

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """

  # Does 'key_dict' have the correct format?
  # This check will ensure 'key_dict' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.ANYKEY_SCHEMA.check_match(key_dict)

  # Does 'signature' have the correct format?
  securesystemslib.formats.SIGNATURE_SCHEMA.check_match(signature)

  # Using the public key belonging to 'key_dict'
  # (i.e., rsakey_dict['keyval']['public']), verify whether 'signature'
  # was produced by key_dict's corresponding private key
  # key_dict['keyval']['private'].
  method = signature['method']
  sig = signature['sig']
  sig = binascii.unhexlify(sig.encode('utf-8'))
  public = key_dict['keyval']['public']
  keytype = key_dict['keytype']
  valid_signature = False

  # Convert 'data' to canonical JSON format so that repeatable signatures are
  # generated across different platforms and Python key dictionaries.  The
  # resulting 'data' is a string encoded in UTF-8 and compatible with the input
  # expected by the cryptography functions called below.
  data = securesystemslib.formats.encode_canonical(data).encode('utf-8')

  # Call the appropriate cryptography libraries for the supported key types,
  # otherwise raise an exception.
  if keytype == 'rsa':
    if _RSA_CRYPTO_LIBRARY == 'pycrypto':
      if 'pycrypto' not in _available_crypto_libraries: # pragma: no cover
        raise securesystemslib.exceptions.UnsupportedLibraryError('Metadata'
          ' downloaded from the remote'
          ' repository listed an RSA signature.  "pycrypto" was set'
          ' (in settings.py) to generate RSA signatures, but the PyCrypto'
          ' library is not installed.  \n$ pip install PyCrypto, or you can'
          ' try switching your configuration (settings.py) to use'
          ' pyca-cryptography if that is available instead.')

      else:
        valid_signature = securesystemslib.pycrypto_keys.verify_rsa_signature(sig, method,
                                                                 public, data)
    elif _RSA_CRYPTO_LIBRARY == 'pyca-cryptography':
      if 'pyca-cryptography' not in _available_crypto_libraries: # pragma: no cover
        raise securesystemslib.exceptions.UnsupportedLibraryError('Metadata'
          ' downloaded from the remote'
          ' repository listed an RSA signature.  "pyca-cryptography" was set'
          ' (in settings.py) to generate RSA signatures, but the "cryptography"'
          ' library is not installed.  \n$ pip install cryptography,'
          ' or you can try switching your configuration'
          ' (securesystemslib/settings.py) to use PyCrypto if that is'
          ' available instead.')

      else:
        valid_signature = securesystemslib.pyca_crypto_keys.verify_rsa_signature(sig,
          method, public, data)

    else: # pragma: no cover
      raise securesystemslib.exceptions.UnsupportedLibraryError('Unsupported'
        ' "settings.RSA_CRYPTO_LIBRARY": ' + repr(_RSA_CRYPTO_LIBRARY) + '.')

  elif keytype == 'ed25519':
    public = binascii.unhexlify(public.encode('utf-8'))
    if _ED25519_CRYPTO_LIBRARY == 'pynacl' or \
                              'pynacl' in _available_crypto_libraries:
      valid_signature = securesystemslib.ed25519_keys.verify_signature(public,
                                                          method, sig, data,
                                                          use_pynacl=True)

    # Fall back to the optimized pure python implementation of ed25519.
    else: # pragma: no cover
      valid_signature = securesystemslib.ed25519_keys.verify_signature(public,
                                                          method, sig, data,
                                                          use_pynacl=False)
  elif keytype == 'ecdsa-sha2-nistp256':
      if _ECDSA_CRYPTO_LIBRARY in _available_crypto_libraries:
        valid_signature = securesystemslib.ecdsa_keys.verify_signature(public,
          method, sig, data)

      else: # pragma: no cover
        raise securesystemslib.exceptions.UnsupportedLibraryError('Unsupported'
          ' "settings.ECDSA_CRYPTO_LIBRARY": ' + repr(_ECDSA_CRYPTO_LIBRARY) + '.')

  # 'securesystemslib.formats.ANYKEY_SCHEMA' should detect invalid key types.
  else: # pragma: no cover
    raise TypeError('Unsupported key type.')

  return valid_signature





def import_rsakey_from_private_pem(pem, password=None):
  """
  <Purpose>
    Import the private RSA key stored in 'pem', and generate its public key
    (which will also be included in the returned rsakey object).  In addition,
    a keyid identifier for the RSA key is generated.  The object returned
    conforms to 'securesystemslib.formats.RSAKEY_SCHEMA' and has the form:

    {'keytype': 'rsa',
     'keyid': keyid,
     'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

    The private key is a string in PEM format.

    >>> rsa_key = generate_rsa_key()
    >>> private = rsa_key['keyval']['private']
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)
    >>> rsa_key2 = import_rsakey_from_private_pem(encrypted_pem, passphrase)
    >>> securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key)
    True
    >>> securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key2)
    True

  <Arguments>
    pem:
      A string in PEM format.  The private key is extracted and returned in
      an rsakey object.

    password: (optional)
      The password, or passphrase, to decrypt the private part of the RSA
      key if it is encrypted.  'password' is not used directly as the encryption
      key, a stronger encryption key is derived from it.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.UnsupportedLibraryError, if any of the cryptography
    libraries specified in 'settings.py' are unsupported or unavailable.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the RSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.RSAKEY_SCHEMA'.
  """

  # Does 'pem' have the correct format?
  # This check will ensure 'pem' conforms to
  # 'securesystemslib.formats.PEMRSA_SCHEMA'.
  securesystemslib.formats.PEMRSA_SCHEMA.check_match(pem)

  if password is not None:
    securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  else:
    logger.debug('The password/passphrase is unset.  The PEM is expected'
      ' to be unencrypted.')

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'settings.RSA_CRYPTO_LIBRARY' and 'settings.GENERAL_CRYPTO_LIBRARY'.
  check_crypto_libraries(['rsa', 'general'])

  # Begin building the RSA key dictionary.
  rsakey_dict = {}
  keytype = 'rsa'
  public = None
  private = None

  # Generate the public and private RSA keys.  The PyCrypto module performs the
  # actual import operation.
  if _RSA_CRYPTO_LIBRARY == 'pycrypto':
    public, private = \
      securesystemslib.pycrypto_keys.create_rsa_public_and_private_from_pem(pem,
                                                                      password)
    public =  extract_pem(public, private_pem=False)
    private = extract_pem(private, private_pem=True)

  elif _RSA_CRYPTO_LIBRARY == 'pyca-cryptography':
    public, private = \
      securesystemslib.pyca_crypto_keys.create_rsa_public_and_private_from_pem(
      pem, password)

    public =  extract_pem(public, private_pem=False)
    private = extract_pem(private, private_pem=True)

  else: #pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('Invalid crypto'
      ' library: ' + repr(_RSA_CRYPTO_LIBRARY) + '.')

  # Generate the keyid of the RSA key.  'key_value' corresponds to the
  # 'keyval' entry of the 'RSAKEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  key_value = {'public': public,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  # Build the 'rsakey_dict' dictionary.  Update 'key_value' with the RSA
  # private key prior to adding 'key_value' to 'rsakey_dict'.
  key_value['private'] = private

  rsakey_dict['keytype'] = keytype
  rsakey_dict['keyid'] = keyid
  rsakey_dict['keyval'] = key_value

  return rsakey_dict





def import_rsakey_from_public_pem(pem):
  """
  <Purpose>
    Generate an RSA key object from 'pem'.  In addition, a keyid identifier for
    the RSA key is generated.  The object returned conforms to
    'securesystemslib.formats.RSAKEY_SCHEMA' and has the form:

    {'keytype': 'rsa',
     'keyid': keyid,
     'keyval': {'public': '-----BEGIN PUBLIC KEY----- ...',
                'private': ''}}

    The public portion of the RSA key is a string in PEM format.

    >>> rsa_key = generate_rsa_key()
    >>> public = rsa_key['keyval']['public']
    >>> rsa_key['keyval']['private'] = ''
    >>> rsa_key2 = import_rsakey_from_public_pem(public)
    >>> securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key)
    True
    >>> securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key2)
    True

  <Arguments>
    pem:
      A string in PEM format (it should contain a public RSA key).

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'pem' is improperly formatted.

  <Side Effects>
    Only the public portion of the PEM is extracted.  Leading or trailing
    whitespace is not included in the PEM string stored in the rsakey object
    returned.

  <Returns>
    A dictionary containing the RSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.RSAKEY_SCHEMA'.
  """

  # Does 'pem' have the correct format?
  # This check will ensure arguments has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMRSA_SCHEMA.check_match(pem)

  # Ensure the PEM string has a public header and footer.  Although a simple
  # validation of 'pem' is performed here, a fully valid PEM string is needed
  # later to successfully verify signatures.  Performing stricter validation of
  # PEMs are left to the external libraries that use 'pem'.

  if is_pem_public(pem):
    public_pem = extract_pem(pem, private_pem=False)

  else:
    raise securesystemslib.exceptions.FormatError('Invalid public pem: ' + repr(pem))

  # Begin building the RSA key dictionary.
  rsakey_dict = {}
  keytype = 'rsa'

  # Generate the keyid of the RSA key.  'key_value' corresponds to the
  # 'keyval' entry of the 'RSAKEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  key_value = {'public': public_pem,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  rsakey_dict['keytype'] = keytype
  rsakey_dict['keyid'] = keyid
  rsakey_dict['keyval'] = key_value

  # Add "keyid_hash_algorithms" so that equal RSA keys with different keyids
  # can be associated using supported keyid_hash_algorithms.
  rsakey_dict['keyid_hash_algorithms'] = \
      securesystemslib.settings.HASH_ALGORITHMS

  return rsakey_dict





def import_rsakey_from_pem(pem):
  """
  <Purpose>
    Import either a public or private PEM.  In contrast to the other explicit
    import functions (import_rsakey_from_public_pem and
    import_rsakey_from_private_pem), this function is useful for when it is not
    known whether 'pem' is private or public.

  <Arguments>
    pem:
      A string in PEM format.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'pem' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the RSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.RSAKEY_SCHEMA'.
  """

  # Does 'pem' have the correct format?
  # This check will ensure arguments has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMRSA_SCHEMA.check_match(pem)

  public_pem = ''
  private_pem = ''

  # Ensure the PEM string has a public or private header and footer.  Although
  # a simple validation of 'pem' is performed here, a fully valid PEM string is
  # needed later to successfully verify signatures.  Performing stricter
  # validation of PEMs are left to the external libraries that use 'pem'.
  if is_pem_public(pem):
    public_pem = extract_pem(pem, private_pem=False)

  elif is_pem_private(pem):
    # Return an rsakey object (RSAKEY_SCHEMA) with the private key included.
    return import_rsakey_from_private_pem(pem, password=None)

  else:
    raise securesystemslib.exceptions.FormatError('PEM contains neither a public'
      ' nor private key: ' + repr(pem))

  # Begin building the RSA key dictionary.
  rsakey_dict = {}
  keytype = 'rsa'

  # Generate the keyid of the RSA key.  'key_value' corresponds to the
  # 'keyval' entry of the 'RSAKEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  # If a PEM is found to contain a private key, the generated rsakey object
  # should be returned above.  The following key object is for the case of a
  # PEM with only a public key.
  key_value = {'public': public_pem,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  rsakey_dict['keytype'] = keytype
  rsakey_dict['keyid'] = keyid
  rsakey_dict['keyval'] = key_value

  # Add "keyid_hash_algorithms" so that equal RSA keys with
  # different keyids can be associated using supported keyid_hash_algorithms.
  rsakey_dict['keyid_hash_algorithms'] = \
      securesystemslib.settings.HASH_ALGORITHMS

  return rsakey_dict




def extract_pem(pem, private_pem=False):
  """
  <Purpose>
    Extract only the portion of the pem that includes the header and footer,
    with any leading and trailing characters removed.  The string returned has
    the following form:

    '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----'

    or

    '-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----'

    Note: This function assumes "pem" is a valid pem in the following format:
    pem header + key material + key footer.  Crypto libraries (e.g., pyca's
    cryptography) that parse the pem returned by this function are expected to
    fully validate the pem.

  <Arguments>
    pem:
      A string in PEM format.

    private_pem:
      Boolean that indicates whether 'pem' is a private PEM.  Private PEMs
      are not shown in exception messages.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'pem' is improperly formatted.

  <Side Effects>
    Only the public and private portion of the PEM is extracted.  Leading or
    trailing whitespace is not included in the returned PEM string.

  <Returns>
    A PEM string (excluding leading and trailing newline characters).
    That is: pem header + key material + pem footer.

  """

  if private_pem:
    pem_header = '-----BEGIN RSA PRIVATE KEY-----'
    pem_footer = '-----END RSA PRIVATE KEY-----'

  else:
    pem_header = '-----BEGIN PUBLIC KEY-----'
    pem_footer = '-----END PUBLIC KEY-----'

  header_start = 0
  footer_start = 0

  # Raise error message if the expected header or footer is not found in 'pem'.
  try:
    header_start = pem.index(pem_header)

  except ValueError:
    # Be careful not to print private key material in exception message.
    if not private_pem:
      raise securesystemslib.exceptions.FormatError('Required PEM'
        ' header ' + repr(pem_header) + '\n not found in PEM string: ' + repr(pem))

    else:
      raise securesystemslib.exceptions.FormatError('Required PEM'
        ' header ' + repr(pem_header) + '\n not found in private PEM string.')

  try:
    # Search for 'pem_footer' after the PEM header.
    footer_start = pem.index(pem_footer, header_start + len(pem_header))

  except ValueError:
    # Be careful not to print private key material in exception message.
    if not private_pem:
      raise securesystemslib.exceptions.FormatError('Required PEM'
        ' footer ' + repr(pem_footer) + '\n not found in PEM string ' + repr(pem))

    else:
      raise securesystemslib.exceptions.FormatError('Required PEM'
        ' footer ' + repr(pem_footer) + '\n not found in private PEM string.')

  # Extract only the public portion of 'pem'.  Leading or trailing whitespace
  # is excluded.
  pem = pem[header_start:footer_start + len(pem_footer)]

  return pem





def encrypt_key(key_object, password):
  """
  <Purpose>
    Return a string containing 'key_object' in encrypted form. Encrypted strings
    may be safely saved to a file.  The corresponding decrypt_key() function can
    be applied to the encrypted string to restore the original key object.
    'key_object' is a key (e.g., RSAKEY_SCHEMA, ED25519KEY_SCHEMA).  This
    function calls the appropriate cryptography module (e.g., pycrypto_keys.py)
    to perform the encryption.

    The currently supported general-purpose crypto module, 'pycrypto_keys.py',
    performs the actual cryptographic operation on 'key_object'.  Whereas
    an encrypted PEM file uses the Triple Data Encryption Algorithm (3DES), the
    Cipher-block chaining (CBC) mode of operation, and the Password-Based Key
    Derivation Function 1 (PBKF1) + MD5 to strengthen 'password', encrypted
    keys use AES-256-CTR-Mode and passwords strengthened with
    PBKDF2-HMAC-SHA256 (100K iterations by default, but may be overriden in
    'securesystemslib.settings.PBKDF2_ITERATIONS' by the user).

    http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    http://en.wikipedia.org/wiki/CTR_mode#Counter_.28CTR.29
    https://en.wikipedia.org/wiki/PBKDF2

    >>> ed25519_key = generate_ed25519_key()
    >>> password = 'secret'
    >>> encrypted_key = encrypt_key(ed25519_key, password).encode('utf-8')
    >>> securesystemslib.formats.ENCRYPTEDKEY_SCHEMA.matches(encrypted_key)
    True

  <Arguments>
    key_object:
      A key (containing also the private key portion) of the form
      'securesystemslib.formats.ANYKEY_SCHEMA'

    password:
      The password, or passphrase, to encrypt the private part of the RSA
      key.  'password' is not used directly as the encryption key, a stronger
      encryption key is derived from it.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'key_object' cannot be encrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if the general-purpose
    cryptography library specified in 'settings.GENERAL_CRYPTO_LIBRARY' is
    unsupported.

  <Side Effects>
    Perform crytographic operations using the library specified in
    'securesystemslib.formats.GENERAL_CRYPTO_LIBRARY' and 'password'.

  <Returns>
    An encrypted string of the form: 'securesystemslib.formats.ENCRYPTEDKEY_SCHEMA'.
  """

  # Does 'key_object' have the correct format?
  # This check will ensure 'key_object' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.ANYKEY_SCHEMA.check_match(key_object)

  # Does 'password' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'securesystemslib.settings.GENERAL_CRYPTO_LIBRARY'.
  check_crypto_libraries(['general'])

  # Encrypted string of 'key_object'.  The encrypted string may be safely saved
  # to a file and stored offline.
  encrypted_key = None

  # Generate an encrypted string of 'key_object' using AES-256-CTR-Mode, where
  # 'password' is strengthened with PBKDF2-HMAC-SHA256.  Ensure the general-
  # purpose library specified in 'settings.GENERAL_CRYPTO_LIBRARY' is supported.
  if _GENERAL_CRYPTO_LIBRARY == 'pycrypto':
    encrypted_key = \
      securesystemslib.pycrypto_keys.encrypt_key(key_object, password)

  elif _GENERAL_CRYPTO_LIBRARY == 'pyca-cryptography':
    encrypted_key = \
      securesystemslib.pyca_crypto_keys.encrypt_key(key_object, password)

  # check_crypto_libraries() should have fully verified _GENERAL_CRYPTO_LIBRARY.
  else: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('Invalid crypto'
      ' library: ' + repr(_GENERAL_CRYPTO_LIBRARY) + '.')

  return encrypted_key





def decrypt_key(encrypted_key, passphrase):
  """
  <Purpose>
    Return a string containing 'encrypted_key' in non-encrypted form.
    The decrypt_key() function can be applied to the encrypted string to restore
    the original key object, a key (e.g., RSAKEY_SCHEMA, ED25519KEY_SCHEMA).
    This function calls the appropriate cryptography module (e.g.,
    pycrypto_keys.py) to perform the decryption.

    The currently supported general-purpose crypto module, 'pycrypto_keys.py',
    performs the actual cryptographic operation on 'key_object'.  Whereas
    an encrypted PEM file uses the Triple Data Encryption Algorithm (3DES), the
    Cipher-block chaining (CBC) mode of operation, and the Password-Based Key
    Derivation Function 1 (PBKF1) + MD5 to strengthen 'password', encrypted
    keys use AES-256-CTR-Mode and passwords strengthened with
    PBKDF2-HMAC-SHA256 (100K iterations be default, but may be overriden in
    'settings.py' by the user).

    http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    http://en.wikipedia.org/wiki/CTR_mode#Counter_.28CTR.29
    https://en.wikipedia.org/wiki/PBKDF2

    >>> ed25519_key = generate_ed25519_key()
    >>> password = 'secret'
    >>> encrypted_key = encrypt_key(ed25519_key, password)
    >>> decrypted_key = decrypt_key(encrypted_key.encode('utf-8'), password)
    >>> securesystemslib.formats.ANYKEY_SCHEMA.matches(decrypted_key)
    True
    >>> decrypted_key == ed25519_key
    True

  <Arguments>
    encrypted_key:
      An encrypted key (additional data is also included, such as salt,
      number of password iterations used for the derived encryption key, etc)
      of the form 'securesystemslib.formats.ENCRYPTEDKEY_SCHEMA'.  'encrypted_key'
      should have been generated with encrypted_key().

    password:
      The password, or passphrase, to decrypt 'encrypted_key'.  'password' is
      not used directly as the encryption key, a stronger encryption key is
      derived from it.  The supported general-purpose module takes care of
      re-deriving the encryption key.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'encrypted_key' cannot be decrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if the general-purpose
    cryptography library specified in 'settings.GENERAL_CRYPTO_LIBRARY' is
    unsupported.

  <Side Effects>
    Perform crytographic operations using the library specified in
    'securesystemslib.formats.GENERAL_CRYPTO_LIBRARY' and 'password'.

  <Returns>
    A key object of the form: 'securesystemslib.formats.ANYKEY_SCHEMA' (e.g.,
    RSAKEY_SCHEMA, ED25519KEY_SCHEMA).
  """

  # Does 'encrypted_key' have the correct format?
  # This check ensures 'encrypted_key' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.ENCRYPTEDKEY_SCHEMA.check_match(encrypted_key)

  # Does 'passphrase' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(passphrase)

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'settings.GENERAL_CRYPTO_LIBRARY'.
  check_crypto_libraries(['general'])

  # Store and return the decrypted key object.
  key_object = None

  # Decrypt 'encrypted_key' so that the original key object is restored.
  # encrypt_key() generates an encrypted string of the key object using
  # AES-256-CTR-Mode, where 'password' is strengthened with PBKDF2-HMAC-SHA256.
  # Ensure the general-purpose library specified in
  # 'settings.GENERAL_CRYPTO_LIBRARY' is supported.
  if _GENERAL_CRYPTO_LIBRARY == 'pycrypto':
    key_object = \
      securesystemslib.pycrypto_keys.decrypt_key(encrypted_key, passphrase)

  elif _GENERAL_CRYPTO_LIBRARY == 'pyca-cryptography':
    key_object = \
      securesystemslib.pyca_crypto_keys.decrypt_key(encrypted_key, passphrase)

  # check_crypto_libraries() should have fully verified _GENERAL_CRYPTO_LIBRARY.
  else: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('Invalid crypto'
      ' library: ' + repr(_GENERAL_CRYPTO_LIBRARY) + '.')

  # The corresponding encrypt_key() encrypts and stores key objects in
  # non-metadata format (i.e., original format of key object argument to
  # encrypt_key()) prior to returning.

  return key_object





def create_rsa_encrypted_pem(private_key, passphrase):
  """
  <Purpose>
  Return a string in PEM format, where the private part of the RSA key is
  encrypted. The private part of the RSA key is encrypted by the Triple
  Data Encryption Algorithm (3DES) and Cipher-block chaining (CBC) for the
  mode of operation. Password-Based Key Derivation Function 1 (PBKF1) + MD5
  is used to strengthen 'passphrase'.

  https://en.wikipedia.org/wiki/Triple_DES
  https://en.wikipedia.org/wiki/PBKDF2

  >>> rsa_key = generate_rsa_key()
  >>> private = rsa_key['keyval']['private']
  >>> passphrase = 'secret'
  >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)
  >>> securesystemslib.formats.PEMRSA_SCHEMA.matches(encrypted_pem)
  True

  <Arguments>
  private_key:
  The private key string in PEM format.

  passphrase:
  The passphrase, or password, to encrypt the private part of the RSA
  key. 'passphrase' is not used directly as the encryption key, a stronger
  encryption key is derived from it.

  <Exceptions>
  securesystemslib.exceptions.FormatError, if the arguments are improperly formatted.

  securesystemslib.exceptions.CryptoError, if an RSA key in encrypted PEM format
  cannot be created.

  TypeError, 'private_key' is unset.

  <Side Effects>
  PyCrypto's Crypto.PublicKey.RSA.exportKey() called to perform the actual
  generation of the PEM-formatted output.

  <Returns>
  A string in PEM format, where the private RSA key is encrypted.
  Conforms to 'securesystemslib.formats.PEMRSA_SCHEMA'.
  """

  # Does 'private_key' have the correct format?
  # This check will ensure 'private_key' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMRSA_SCHEMA.check_match(private_key)

  # Does 'passphrase' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(passphrase)

  # Raise 'securesystemslib.exceptions.UnsupportedLibraryError' if the following
  # libraries, specified in 'settings', are unsupported or unavailable:
  # 'settings.GENERAL_CRYPTO_LIBRARY' and 'settings.RSA_CRYPTO_LIBRARY'.
  check_crypto_libraries(['rsa', 'general'])

  encrypted_pem = None

  # Generate the public and private RSA keys. The PyCrypto module performs
  # the actual key generation. Raise 'ValueError' if 'bits' is less than 1024
  # or not a multiple of 256, although a 2048-bit minimum is enforced by
  # securesystemslib.formats.RSAKEYBITS_SCHEMA.check_match().
  if _RSA_CRYPTO_LIBRARY == 'pycrypto':
    encrypted_pem = \
      securesystemslib.pycrypto_keys.create_rsa_encrypted_pem(private_key, passphrase)

  elif _RSA_CRYPTO_LIBRARY == 'pyca-cryptography':
    encrypted_pem = \
      securesystemslib.pycrypto_keys.create_rsa_encrypted_pem(private_key, passphrase)

  # check_crypto_libraries() should have fully verified _RSA_CRYPTO_LIBRARY.
  else: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('Invalid crypto'
      ' library: ' + repr(_RSA_CRYPTO_LIBRARY) + '.')

  return encrypted_pem




def is_pem_public(pem):
  """
  <Purpose>
    Checks if a passed PEM formatted string is a PUBLIC key, by looking for the
    following pattern:

    '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----'

    >>> rsa_key = generate_rsa_key()
    >>> public = rsa_key['keyval']['public']
    >>> private = rsa_key['keyval']['private']
    >>> is_pem_public(public)
    True
    >>> is_pem_public(private)
    False

  <Arguments>
    pem:
      A string in PEM format.

  <Exceptions>
      securesystemslib.exceptions.FormatError, if 'pem' is improperly formatted.

  <Side Effects>
    None

  <Returns>
    True if 'pem' is public and false otherwise.
  """

  # Do the arguments have the correct format?
  # This check will ensure arguments have the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMRSA_SCHEMA.check_match(pem)

  pem_header = '-----BEGIN PUBLIC KEY-----'
  pem_footer = '-----END PUBLIC KEY-----'

  try:
    header_start = pem.index(pem_header)
    pem.index(pem_footer, header_start + len(pem_header))

  except ValueError:
    return False

  return True




def is_pem_private(pem, keytype='rsa'):
  """
  <Purpose>
    Checks if a passed PEM formatted string is a PRIVATE key, by looking for
    the following patterns:

    '-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----'
    '-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----'

    >>> rsa_key = generate_rsa_key()
    >>> private = rsa_key['keyval']['private']
    >>> public = rsa_key['keyval']['public']
    >>> is_pem_private(private)
    True
    >>> is_pem_private(public)
    False

  <Arguments>
    pem:
      A string in PEM format.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if any of the arguments are improperly
    formatted.

  <Side Effects>
    None

  <Returns>
    True if 'pem' is private and false otherwise.
  """

  # Do the arguments have the correct format?
  # This check will ensure arguments have the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMRSA_SCHEMA.check_match(pem)
  securesystemslib.formats.NAME_SCHEMA.check_match(keytype)

  if keytype == 'rsa':
    pem_header = '-----BEGIN RSA PRIVATE KEY-----'
    pem_footer = '-----END RSA PRIVATE KEY-----'

  elif keytype == 'ec':
    pem_header = '-----BEGIN EC PRIVATE KEY-----'
    pem_footer = '-----END EC PRIVATE KEY-----'

  else:
    raise securesystemslib.exceptions.FormatError('Unsupported key'
      ' type: ' + repr(keytype) + '.  Supported keytypes: ["rsa", "ec"]')

  try:
    header_start = pem.index(pem_header)
    pem.index(pem_footer, header_start + len(pem_header))

  except ValueError:
    return False

  return True





def import_ecdsakey_from_private_pem(pem, password=None):
  """
  <Purpose>
    Import the private ECDSA key stored in 'pem', and generate its public key
    (which will also be included in the returned ECDSA key object).  In addition,
    a keyid identifier for the ECDSA key is generated.  The object returned
    conforms to:

    {'keytype': 'ecdsa-sha2-nistp256',
     'keyid': keyid,
     'keyval': {'public': '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----',
                'private': '-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----'}}

    The private key is a string in PEM format.

    >>> ecdsa_key = generate_ecdsa_key()
    >>> private_pem = ecdsa_key['keyval']['private']
    >>> ecdsa_key = import_ecdsakey_from_private_pem(private_pem)
    >>> securesystemslib.formats.ECDSAKEY_SCHEMA.matches(ecdsa_key)
    True

  <Arguments>
    pem:
      A string in PEM format.  The private key is extracted and returned in
      an ecdsakey object.

    password: (optional)
      The password, or passphrase, to decrypt the private part of the ECDSA
      key if it is encrypted.  'password' is not used directly as the encryption
      key, a stronger encryption key is derived from it.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.UnsupportedLibraryError, if any of the cryptography
    libraries specified in 'settings.py' are unsupported or unavailable.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the ECDSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.ECDSAKEY_SCHEMA'.
  """

  # Does 'pem' have the correct format?
  # This check will ensure 'pem' conforms to
  # 'securesystemslib.formats.ECDSARSA_SCHEMA'.
  securesystemslib.formats.PEMECDSA_SCHEMA.check_match(pem)

  if password is not None:
    securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)

  else:
    logger.debug('The password/passphrase is unset.  The PEM is expected'
      ' to be unencrypted.')

  # Begin building the ECDSA key dictionary.
  ecdsakey_dict = {}
  keytype = 'ecdsa-sha2-nistp256'
  public = None
  private = None

  public, private = \
    securesystemslib.ecdsa_keys.create_ecdsa_public_and_private_from_pem(pem, password)

  # Generate the keyid of the ECDSA key.  'key_value' corresponds to the
  # 'keyval' entry of the 'ECDSAKEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  key_value = {'public': public,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  # Build the 'ecdsakey_dict' dictionary.  Update 'key_value' with the ECDSA
  # private key prior to adding 'key_value' to 'ecdsakey_dict'.
  key_value['private'] = private

  ecdsakey_dict['keytype'] = keytype
  ecdsakey_dict['keyid'] = keyid
  ecdsakey_dict['keyval'] = key_value

  # Add "keyid_hash_algorithms" so equal ECDSA keys with
  # different keyids can be associated using supported keyid_hash_algorithms
  ecdsakey_dict['keyid_hash_algorithms'] = \
    securesystemslib.settings.HASH_ALGORITHMS

  return ecdsakey_dict





def import_ecdsakey_from_public_pem(pem):
  """
  <Purpose>
    Generate an ECDSA key object from 'pem'.  In addition, a keyid identifier
    for the ECDSA key is generated.  The object returned conforms to
    'securesystemslib.formats.ECDSAKEY_SCHEMA' and has the form:

    {'keytype': 'ecdsa-sha2-nistp256',
     'keyid': keyid,
     'keyval': {'public': '-----BEGIN PUBLIC KEY----- ...',
                'private': ''}}

    The public portion of the ECDSA key is a string in PEM format.

    >>> ecdsa_key = generate_ecdsa_key()
    >>> public = ecdsa_key['keyval']['public']
    >>> ecdsa_key['keyval']['private'] = ''
    >>> ecdsa_key2 = import_ecdsakey_from_public_pem(public)
    >>> securesystemslib.formats.ECDSAKEY_SCHEMA.matches(ecdsa_key)
    True
    >>> securesystemslib.formats.ECDSAKEY_SCHEMA.matches(ecdsa_key2)
    True

  <Arguments>
    pem:
      A string in PEM format (it should contain a public ECDSA key).

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'pem' is improperly formatted.

  <Side Effects>
    Only the public portion of the PEM is extracted.  Leading or trailing
    whitespace is not included in the PEM string stored in the rsakey object
    returned.

  <Returns>
    A dictionary containing the ECDSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.ECDSAKEY_SCHEMA'.
  """

  # Does 'pem' have the correct format?
  # This check will ensure arguments has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMECDSA_SCHEMA.check_match(pem)

  # Ensure the PEM string has a public header and footer.  Although a simple
  # validation of 'pem' is performed here, a fully valid PEM string is needed
  # later to successfully verify signatures.  Performing stricter validation of
  # PEMs are left to the external libraries that use 'pem'.

  if is_pem_public(pem):
    public_pem = extract_pem(pem, private_pem=False)

  else:
    raise securesystemslib.exceptions.FormatError('Invalid public pem: ' + repr(pem))

  # Begin building the ECDSA key dictionary.
  ecdsakey_dict = {}
  keytype = 'ecdsa-sha2-nistp256'

  # Generate the keyid of the ECDSA key.  'key_value' corresponds to the
  # 'keyval' entry of the 'ECDSAKEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  key_value = {'public': public_pem,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  ecdsakey_dict['keytype'] = keytype
  ecdsakey_dict['keyid'] = keyid
  ecdsakey_dict['keyval'] = key_value

  # Add "keyid_hash_algorithms" so that equal ECDSA keys with different keyids
  # can be associated using supported keyid_hash_algorithms.
  ecdsakey_dict['keyid_hash_algorithms'] = \
      securesystemslib.settings.HASH_ALGORITHMS

  return ecdsakey_dict





def import_ecdsakey_from_pem(pem):
  """
  <Purpose>
    Import either a public or private ECDSA PEM.  In contrast to the other
    explicit import functions (import_ecdsakey_from_public_pem and
    import_ecdsakey_from_private_pem), this function is useful for when it is
    not known whether 'pem' is private or public.

  <Arguments>
    pem:
      A string in PEM format.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'pem' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the ECDSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.ECDSAKEY_SCHEMA'.
  """

  # Does 'pem' have the correct format?
  # This check will ensure arguments has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMECDSA_SCHEMA.check_match(pem)

  public_pem = ''
  private_pem = ''

  # Ensure the PEM string has a public or private header and footer.  Although
  # a simple validation of 'pem' is performed here, a fully valid PEM string is
  # needed later to successfully verify signatures.  Performing stricter
  # validation of PEMs are left to the external libraries that use 'pem'.
  if is_pem_public(pem):
    public_pem = extract_pem(pem, private_pem=False)

  elif is_pem_private(pem, 'ec'):
    # Return an ecdsakey object (ECDSAKEY_SCHEMA) with the private key included.
    return import_ecdsakey_from_private_pem(pem, password=None)

  else:
    raise securesystemslib.exceptions.FormatError('PEM contains neither a public'
      ' nor private key: ' + repr(pem))

  # Begin building the ECDSA key dictionary.
  ecdsakey_dict = {}
  keytype = 'ecdsa-sha2-nistp256'

  # Generate the keyid of the ECDSA key.  'key_value' corresponds to the
  # 'keyval' entry of the 'ECDSAKEY_SCHEMA' dictionary.  The private key
  # information is not included in the generation of the 'keyid' identifier.
  # If a PEM is found to contain a private key, the generated rsakey object
  # should be returned above.  The following key object is for the case of a
  # PEM with only a public key.
  key_value = {'public': public_pem,
               'private': ''}
  keyid = _get_keyid(keytype, key_value)

  ecdsakey_dict['keytype'] = keytype
  ecdsakey_dict['keyid'] = keyid
  ecdsakey_dict['keyval'] = key_value

  return ecdsakey_dict





if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'keys.py' as a standalone module:
  # $ python keys.py
  import doctest
  doctest.testmod()
