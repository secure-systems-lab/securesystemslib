"""
<Program Name>
  spx_keys.py

<Author>
  Peter Schwabe <peter@cryptojedi.org>

<Started>
  October 31, 2018.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to support SPINCS+ ("SPX") signatures. SPHINCS+ is an
  a framework for creating stateless hash-based signatures. 
  The concrete instantiation of this framework used here is the "shake256-192s"
  parameter set as defined in the SPHINCS+ submission to NIST; see
  http://sphincs.org/resources.html

  'securesystemslib/spx_keys.py' calls 'pyspx.py', which is a wrapper
  around the C reference implementation of SPHINCS+ submitted to NIST. See
  https://github.com/sphincs/pyspx and
  https://github.com/sphincs/sphincsplus.
 """

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# 'binascii' required for hexadecimal conversions.  Signatures and
# public/private keys are hexlified.
import binascii

# 'os' required to generate OS-specific randomness (os.urandom) suitable for
# cryptographic use.
# http://docs.python.org/2/library/os.html#miscellaneous-functions
import os

# Import the pyspx library, if available. This library is required to use
# spx signatures.
import pyspx.shake256_192s as pyspx

import securesystemslib.formats
import securesystemslib.exceptions
import securesystemslib.schema as SCHEMA

# Supported spx signing schemes: 'spx'.  
_SUPPORTED_SPX_SIGNING_SCHEMES = ['spx']

# Define lengths of SPX keys and signature bytes
# NOTE: Define module scope schemas here to avoid conditional imports of
# optional 'pyspx' package in 'formats' module. ImportError and IOError should
# be handled by whoever imports this 'spx_keys' module.
SPX_PUBLIC_BYTES_SCHEMA = SCHEMA.LengthBytes(pyspx.crypto_sign_PUBLICKEYBYTES)
SPX_PRIVATE_BYTES_SCHEMA = SCHEMA.LengthBytes(pyspx.crypto_sign_SECRETKEYBYTES)
SPX_SIG_BYTES_SCHEMA = SCHEMA.LengthBytes(pyspx.crypto_sign_BYTES)

def generate_public_and_private():
  """
  <Purpose>
    Generate a pair of spx public and private keys with pyspx.  The public
    and private keys returned conform to 'SPX_PUBLIC_BYTES_SCHEMA' and
    'SPX_PRIVATE_BYTES_SCHEMA', respectively.

    An spx seed key is a random 128-byte string. Public keys are 64 bytes.

    >>> public, private = generate_public_and_private()
    >>> SPX_PUBLIC_BYTES_SCHEMA.matches(public)
    True
    >>> SPX_PRIVATE_BYTES_SCHEMA.matches(private)
    True

  <Arguments>
    None.

  <Exceptions>
    securesystemslib.exceptions.UnsupportedLibraryError, if the pyspx
    module is unavailable.

    NotImplementedError, if a randomness source is not found by 'os.urandom'.

  <Side Effects>
    The spx keys are generated by first creating a random seed
    with os.urandom() and then calling pyspx's pyspx.signing.SigningKey().

  <Returns>
    A (public, private) tuple that conform to
    'SPX_PUBLIC_BYTES_SCHEMA' and
    'SPX_PRIVATE_BYTES_SCHEMA', respectively.
  """

  # Generate spx's seed key by calling os.urandom().  The random bytes
  # returned should be suitable for cryptographic use and is OS-specific.
  # Raise 'NotImplementedError' if a randomness source is not found.
  seed = os.urandom(pyspx.crypto_sign_SEEDBYTES)
  public = None

  # Generate the public key.  pyspx performs the actual key generation.
  try:
    public, private = pyspx.generate_keypair(seed)

  except NameError: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('The pyspx'
        ' library and/or its dependencies unavailable.')

  return public, private





def create_signature(private_key, data, scheme):
  """
  <Purpose>
    Return a (signature, scheme) tuple, where the signature scheme is 'spx'
    and is always generated by pyspx.  The signature returned
    conforms to 'SPX_SIG_BYTES_SCHEMA'.

    >>> public, private = generate_public_and_private()
    >>> data = b'The quick brown fox jumps over the lazy dog'
    >>> scheme = 'spx'
    >>> signature, scheme = \
        create_signature(private, data, scheme)
    >>> SPX_SIG_BYTES_SCHEMA.matches(signature)
    True
    >>> scheme == 'spx'
    True
    >>> signature, scheme = \
        create_signature(private, data, scheme)
    >>> SPX_SIG_BYTES_SCHEMA.matches(signature)
    True
    >>> scheme == 'spx'
    True

  <Arguments>
    private:
      The spx private key, a simple byte string

    data:
      Data object used by create_signature() to generate the signature.

    scheme:
      The signature scheme used to generate the signature.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if a signature cannot be created.

  <Side Effects>
    spx.signing.SigningKey.sign() called to generate the actual signature.

  <Returns>
    A signature dictionary conformat to 'securesystemslib.format.SIGNATURE_SCHEMA'.  
  """
  # Validate arguments
  SPX_PRIVATE_BYTES_SCHEMA.check_match(private_key)
  securesystemslib.formats.SPX_SIG_SCHEMA.check_match(scheme)

  private = private_key

  signature = None

  # An if-clause is not strictly needed here, since 'spx' is the only
  # currently supported scheme.  Nevertheless, include the conditional
  # statement to accommodate schemes that might be added in the future.
  if scheme == 'spx':
    try:
        signature = pyspx.sign(data, private)

    # The unit tests expect required libraries to be installed.
    except NameError: # pragma: no cover
      raise securesystemslib.exceptions.UnsupportedLibraryError('The pyspx'
          ' library and/or its dependencies unavailable.')

    except (ValueError, TypeError) as e:
      raise securesystemslib.exceptions.CryptoError('An "spx" signature'
          ' could not be created with pyspx.' + str(e))

  # This is a defensive check for a valid 'scheme', which should have already
  # been validated in the check_match() above.
  else: #pragma: no cover
    raise securesystemslib.exceptions.UnsupportedAlgorithmError('Unsupported'
      ' signature scheme is specified: ' + repr(scheme))

  return signature, scheme





def verify_signature(public_key, scheme, signature, data):
  """
  <Purpose>
    Determine whether the private key corresponding to 'public_key' produced
    'signature'.  verify_signature() will use the public key, the 'scheme' and
    'sig', and 'data' arguments to complete the verification.

    >>> public, private = generate_public_and_private()
    >>> data = b'The quick brown fox jumps over the lazy dog'
    >>> scheme = 'spx'
    >>> signature, scheme = \
        create_signature(public, private, data, scheme)
    >>> verify_signature(public, scheme, signature, data)
    True
    >>> bad_data = b'The sly brown fox jumps over the lazy dog'
    >>> bad_signature, scheme = \
        create_signature(public, private, bad_data, scheme)
    >>> verify_signature(public, scheme, bad_signature, data)
    False

  <Arguments>
    public_key:
      The public key is a simple byte string of length SPX_PUBLIC_BYTES_SCHEMA.

    scheme:
      'spx' signature scheme

    signature:
      The signature is a simple byte string of length SPX_SIG_BYTES_SCHEMA.

    data:
      Data object used by securesystemslib.spx_keys.create_signature() to
      generate 'signature'.  'data' is needed here to verify the signature.

  <Exceptions>
    securesystemslib.exceptions.UnsupportedAlgorithmError.  Raised if the
    signature scheme 'scheme' is not one supported by
    securesystemslib.spx_keys.create_signature().

    securesystemslib.exceptions.FormatError. Raised if the arguments are
    improperly formatted.

  <Side Effects>
    pyspx.signing.VerifyKey.verify() called

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """
  # Validate arguments
  SPX_PUBLIC_BYTES_SCHEMA.check_match(public_key)
  SPX_SIG_BYTES_SCHEMA.check_match(signature)
  securesystemslib.formats.SPX_SIG_SCHEMA.check_match(scheme)


  # Verify 'signature'.  Before returning the Boolean result, ensure 'spx'
  # was used as the signature scheme.  Raise
  # 'securesystemslib.exceptions.UnsupportedLibraryError' if 'pyspx' is unavailable.
  public = public_key
  valid_signature = False

  if scheme in _SUPPORTED_SPX_SIGNING_SCHEMES:
    try:
      valid_signature = pyspx.verify(data, signature, public)

      # The unit tests expect PyNaCl to be installed.
    except NameError: # pragma: no cover
      raise securesystemslib.exceptions.UnsupportedLibraryError('The pyspx'
          ' library and/or its dependencies unavailable.')


  # This is a defensive check for a valid 'scheme', which should have already
  # been validated in the SPX_SIG_SCHEMA.check_match(scheme) above.
  else: #pragma: no cover
    message = 'Unsupported spx signature scheme: ' + repr(scheme) + '.\n' + \
      'Supported schemes: ' + repr(_SUPPORTED_SPX_SIGNING_SCHEMES) + '.'
    raise securesystemslib.exceptions.UnsupportedAlgorithmError(message)

  return valid_signature



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'spx_keys.py' as a standalone module.
  # python -B spx_keys.py
  import doctest
  doctest.testmod()
