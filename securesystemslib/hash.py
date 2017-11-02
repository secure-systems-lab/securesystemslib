#!/usr/bin/env python2
"""
<Program Name>
  hash.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 28, 2012.  Based on a previous version of this module.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Support secure hashing and message digests. Any hash-related routines that
  TUF requires should be located in this module.  Simplifying the creation of
  digest objects, and providing a central location for hash routines are the
  main goals of this module.  Support routines implemented include functions to
  create digest objects given a filename or file object.  Only the standard
  hashlib library is currently supported, but pyca/cryptography support will be
  added in the future.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import logging
import hashlib

import six

import securesystemslib.exceptions
import securesystemslib.formats

# Import securesystemslib logger to log warning messages.
logger = logging.getLogger('securesystemslib.hash')

DEFAULT_HASH_ALGORITHM = 'sha256'
DEFAULT_HASH_LIBRARY = 'hashlib'
SUPPORTED_LIBRARIES = ['hashlib']


def digest(algorithm=DEFAULT_HASH_ALGORITHM, hash_library=DEFAULT_HASH_LIBRARY):
  """
  <Purpose>
    Provide the caller with the ability to create digest objects without having
    to worry about crypto library availability or which library to use.  The
    caller also has the option of specifying which hash algorithm and/or
    library to use.

    # Creation of a digest object using defaults or by specifying hash
    # algorithm and library.
    digest_object = securesystemslib.hash.digest()
    digest_object = securesystemslib.hash.digest('sha384')
    digest_object = securesystemslib.hash.digest('sha256', 'hashlib')

    # The expected interface for digest objects.
    digest_object.digest_size
    digest_object.hexdigest()
    digest_object.update('data')
    digest_object.digest()

    # Added hash routines by this module.
    digest_object = securesystemslib.hash.digest_fileobject(file_object)
    digest_object = securesystemslib.hash.digest_filename(filename)

  <Arguments>
    algorithm:
      The hash algorithm (e.g., 'md5', 'sha1', 'sha256').

    hash_library:
      The crypto library to use for the given hash algorithm (e.g., 'hashlib').

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are
    improperly formatted.

    securesystemslib.exceptions.UnsupportedAlgorithmError, if an unsupported
    hashing algorithm is specified, or digest could not be generated with given
    the algorithm.

    securesystemslib.exceptions.UnsupportedLibraryError, if an unsupported
    library was requested via 'hash_library'.

  <Side Effects>
    None.

  <Returns>
    Digest object (e.g., hashlib.new(algorithm)).
  """

  # Are the arguments properly formatted?  If not, raise
  # 'securesystemslib.exceptions.FormatError'.
  securesystemslib.formats.NAME_SCHEMA.check_match(algorithm)
  securesystemslib.formats.NAME_SCHEMA.check_match(hash_library)

  # Was a hashlib digest object requested and is it supported?
  # If so, return the digest object.
  if hash_library == 'hashlib' and hash_library in SUPPORTED_LIBRARIES:
    try:
      return hashlib.new(algorithm)

    except ValueError:
      raise securesystemslib.exceptions.UnsupportedAlgorithmError(algorithm)

  # Was a pyca_crypto digest object requested and is it supported?
  elif hash_library == 'pyca_crypto' and hash_library in SUPPORTED_LIBRARIES: #pragma: no cover
    # TODO: Add support for pyca/cryptography's hashing routines.
    pass

  # The requested hash library is not supported.
  else:
    raise securesystemslib.exceptions.UnsupportedLibraryError('Unsupported'
        ' library requested.  Supported hash'
        ' libraries: ' + repr(SUPPORTED_LIBRARIES))





def digest_fileobject(file_object, algorithm=DEFAULT_HASH_ALGORITHM,
    hash_library=DEFAULT_HASH_LIBRARY):
  """
  <Purpose>
    Generate a digest object given a file object.  The new digest object
    is updated with the contents of 'file_object' prior to returning the
    object to the caller.

  <Arguments>
    file_object:
      File object whose contents will be used as the data
      to update the hash of a digest object to be returned.

    algorithm:
      The hash algorithm (e.g., 'md5', 'sha1', 'sha256').

    hash_library:
      The library providing the hash algorithms (e.g., 'hashlib').

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are
    improperly formatted.

    securesystemslib.exceptions.UnsupportedAlgorithmError, if an unsupported
    hashing algorithm was specified via 'algorithm'.

    securesystemslib.exceptions.UnsupportedLibraryError, if an unsupported
    crypto library was specified via 'hash_library'.

  <Side Effects>
    None.

  <Returns>
    Digest object (e.g., hashlib.new(algorithm)).
  """

  # Are the arguments properly formatted?  If not, raise
  # 'securesystemslib.exceptions.FormatError'.
  securesystemslib.formats.NAME_SCHEMA.check_match(algorithm)
  securesystemslib.formats.NAME_SCHEMA.check_match(hash_library)

  # Digest object returned whose hash will be updated using 'file_object'.
  # digest() raises:
  # securesystemslib.exceptions.UnsupportedAlgorithmError
  # securesystemslib.exceptions.UnsupportedLibraryError
  digest_object = digest(algorithm, hash_library)

  # Defensively seek to beginning, as there's no case where we don't
  # intend to start from the beginning of the file.
  file_object.seek(0)

  # Read the contents of the file object in at most 4096-byte chunks.
  # Update the hash with the data read from each chunk and return after
  # the entire file is processed.
  while True:
    chunksize = 4096
    data = file_object.read(chunksize)
    if not data:
      break

    if not isinstance(data, six.binary_type):
      digest_object.update(data.encode('utf-8'))

    else:
      digest_object.update(data)

  return digest_object





def digest_filename(filename, algorithm=DEFAULT_HASH_ALGORITHM,
    hash_library=DEFAULT_HASH_LIBRARY):
  """
  <Purpose>
    Generate a digest object, update its hash using a file object
    specified by filename, and then return it to the caller.

  <Arguments>
    filename:
      The filename belonging to the file object to be used.

    algorithm:
      The hash algorithm (e.g., 'md5', 'sha1', 'sha256').

    hash_library:
      The library providing the hash algorithms (e.g., 'hashlib').

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are
    improperly formatted.

    securesystemslib.exceptions.UnsupportedAlgorithmError, if the given
    'algorithm' is unsupported.

    securesystemslib.exceptions.UnsupportedLibraryError, if the given
    'hash_library' is unsupported.

  <Side Effects>
    None.

  <Returns>
    Digest object (e.g., hashlib.new(algorithm)).
  """
  # Are the arguments properly formatted?  If not, raise
  # 'securesystemslib.exceptions.FormatError'.
  securesystemslib.formats.RELPATH_SCHEMA.check_match(filename)
  securesystemslib.formats.NAME_SCHEMA.check_match(algorithm)
  securesystemslib.formats.NAME_SCHEMA.check_match(hash_library)

  digest_object = None

  # Open 'filename' in read+binary mode.
  with open(filename, 'rb') as file_object:
    # Create digest_object and update its hash data from file_object.
    # digest_fileobject() raises:
    # securesystemslib.exceptions.UnsupportedAlgorithmError
    # securesystemslib.exceptions.UnsupportedLibraryError
    digest_object = digest_fileobject(file_object, algorithm, hash_library)

  return digest_object
