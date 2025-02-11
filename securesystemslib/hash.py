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
  securesystemslib requires should be located in this module.  Simplifying the
  creation of digest objects, and providing a central location for hash
  routines are the main goals of this module.  Support routines implemented
  include functions to create digest objects given a filename or file object.
  This is a thin wrapper over hashlib.
"""

from __future__ import annotations

import hashlib
from typing import IO, cast

from securesystemslib import exceptions
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface

DEFAULT_CHUNK_SIZE = 4096
DEFAULT_HASH_ALGORITHM = "sha256"


def digest(algorithm: str = DEFAULT_HASH_ALGORITHM) -> hashlib._Hash:
    """
    <Purpose>
      Provide the caller with the ability to create digest objects.  The
      caller also has the option of specifying which hash algorithm to use.
      This is a thin wrapper over hashlib.

      # Creation of a digest object using defaults or by specifying hash
      # algorithm.
      digest_object = securesystemslib.hash.digest()
      digest_object = securesystemslib.hash.digest('sha384')

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
        The hash algorithm (e.g., 'sha256', 'sha512').

    <Exceptions>
      securesystemslib.exceptions.UnsupportedAlgorithmError, if an unsupported
      hashing algorithm is specified, or digest could not be generated with given
      the algorithm.

    <Side Effects>
      None.

    <Returns>
      Digest object
    """

    try:
        if algorithm == "blake2b-256":
            return cast(hashlib._Hash, hashlib.blake2b(digest_size=32))
        return hashlib.new(algorithm)

    except (ValueError, TypeError):
        # ValueError: the algorithm value was unknown
        # TypeError: unexpected argument digest_size (on old python)
        raise exceptions.UnsupportedAlgorithmError(algorithm)


def digest_fileobject(
    file_object: IO,
    algorithm: str = DEFAULT_HASH_ALGORITHM,
    normalize_line_endings: bool = False,
) -> hashlib._Hash:
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
        The hash algorithm (e.g., 'sha256', 'sha512').

      normalize_line_endings: (default False)
        Whether or not to normalize line endings for cross-platform support.
        Note that this results in ambiguous hashes (e.g. 'abc\n' and 'abc\r\n'
        will produce the same hash), so be careful to only apply this to text
        files (not binary), when that equivalence is desirable and cannot result
        in easily-maliciously-corrupted files producing the same hash as a valid
        file.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the arguments are
      improperly formatted.

      securesystemslib.exceptions.UnsupportedAlgorithmError, if an unsupported
      hashing algorithm was specified via 'algorithm'.

    <Side Effects>
      None.

    <Returns>
      Digest object
    """
    # Digest object returned whose hash will be updated using 'file_object'.
    # digest() raises:
    # securesystemslib.exceptions.UnsupportedAlgorithmError
    digest_object = digest(algorithm)

    # Defensively seek to beginning, as there's no case where we don't
    # intend to start from the beginning of the file.
    file_object.seek(0)

    # Read the contents of the file object in at most 4096-byte chunks.
    # Update the hash with the data read from each chunk and return after
    # the entire file is processed.
    while True:
        data = file_object.read(DEFAULT_CHUNK_SIZE)
        if not data:
            break

        if normalize_line_endings:
            while data[-1:] == b"\r":
                c = file_object.read(1)
                if not c:
                    break

                data += c

            data = (
                data
                # First Windows
                .replace(b"\r\n", b"\n")
                # Then Mac
                .replace(b"\r", b"\n")
            )

        if not isinstance(data, bytes):
            digest_object.update(data.encode("utf-8"))

        else:
            digest_object.update(data)

    return digest_object


def digest_filename(
    filename: str,
    algorithm: str = DEFAULT_HASH_ALGORITHM,
    normalize_line_endings: bool = False,
    storage_backend: StorageBackendInterface | None = None,
) -> hashlib._Hash:
    """
    <Purpose>
      Generate a digest object, update its hash using a file object
      specified by filename, and then return it to the caller.

    <Arguments>
      filename:
        The filename belonging to the file object to be used.

      algorithm:
        The hash algorithm (e.g., 'sha256', 'sha512').

      normalize_line_endings:
        Whether or not to normalize line endings for cross-platform support.

      storage_backend:
        An object which implements
        securesystemslib.storage.StorageBackendInterface. When no object is
        passed a FilesystemBackend will be instantiated and used.

    <Exceptions>
      securesystemslib.exceptions.UnsupportedAlgorithmError, if the given
      'algorithm' is unsupported.

      securesystemslib.exceptions.StorageError, if the file cannot be opened.

    <Side Effects>
      None.

    <Returns>
      Digest object
    """
    digest_object = None

    if storage_backend is None:
        storage_backend = FilesystemBackend()

    # Open 'filename' in read+binary mode.
    with storage_backend.get(filename) as file_object:
        # Create digest_object and update its hash data from file_object.
        # digest_fileobject() raises:
        # securesystemslib.exceptions.UnsupportedAlgorithmError
        digest_object = digest_fileobject(
            file_object, algorithm, normalize_line_endings
        )

    return digest_object
