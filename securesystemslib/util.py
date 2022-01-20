"""
<Program Name>
  util.py

<Author>
  Konstantin Andrianov

<Started>
  March 24, 2012.  Derived from original util.py written by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides utility services.  This module supplies utility functions such as:
  get_file_details() that computes the length and hash of a file, import_json
  that tries to import a working json module, load_json_* functions, etc.
"""

import json
import os
import logging

from securesystemslib import exceptions
from securesystemslib import formats
from securesystemslib.hash import digest_fileobject
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface

from typing import Any, Dict, IO, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


def get_file_details(
    filepath: str,
    hash_algorithms: List[str] = ['sha256'],
    storage_backend: Optional[StorageBackendInterface] = None
) -> Tuple[int, Dict[str, str]]:
  """
  <Purpose>
    To get file's length and hash information.  The hash is computed using the
    sha256 algorithm.  This function is used in the signerlib.py and updater.py
    modules.

  <Arguments>
    filepath:
      Absolute file path of a file.

    hash_algorithms:
      A list of hash algorithms with which the file's hash should be computed.
      Defaults to ['sha256']

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

  <Exceptions>
    securesystemslib.exceptions.FormatError: If hash of the file does not match
    HASHDICT_SCHEMA.

    securesystemslib.exceptions.StorageError: The file at "filepath" cannot be
    opened or found.

  <Returns>
    A tuple (length, hashes) describing 'filepath'.
  """

  # Making sure that the format of 'filepath' is a path string.
  # 'securesystemslib.exceptions.FormatError' is raised on incorrect format.
  formats.PATH_SCHEMA.check_match(filepath)
  formats.HASHALGORITHMS_SCHEMA.check_match(hash_algorithms)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  file_length = get_file_length(filepath, storage_backend)
  file_hashes = get_file_hashes(filepath, hash_algorithms, storage_backend)

  return file_length, file_hashes


def get_file_hashes(
    filepath: str,
    hash_algorithms: List[str] = ['sha256'],
    storage_backend: Optional[StorageBackendInterface] = None
) -> Dict[str, str]:
  """
  <Purpose>
    Compute hash(es) of the file at filepath using each of the specified
    hash algorithms. If no algorithms are specified, then the hash is
    computed using the SHA-256 algorithm.

  <Arguments>
    filepath:
      Absolute file path of a file.

    hash_algorithms:
      A list of hash algorithms with which the file's hash should be computed.
      Defaults to ['sha256']

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

  <Exceptions>
    securesystemslib.exceptions.FormatError: If hash of the file does not match
    HASHDICT_SCHEMA.

    securesystemslib.exceptions.StorageError: The file at "filepath" cannot be
    opened or found.

  <Returns>
    A dictionary conforming to securesystemslib.formats.HASHDICT_SCHEMA
    containing information about the hashes of the file at "filepath".
  """

  # Making sure that the format of 'filepath' is a path string.
  # 'securesystemslib.exceptions.FormatError' is raised on incorrect format.
  formats.PATH_SCHEMA.check_match(filepath)
  formats.HASHALGORITHMS_SCHEMA.check_match(hash_algorithms)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  file_hashes = {}

  with storage_backend.get(filepath) as fileobj:
    # Obtaining hash of the file.
    for algorithm in hash_algorithms:
      digest_object = digest_fileobject(fileobj, algorithm)
      file_hashes.update({algorithm: digest_object.hexdigest()})

  # Performing a format check to ensure 'file_hash' corresponds HASHDICT_SCHEMA.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  formats.HASHDICT_SCHEMA.check_match(file_hashes)

  return file_hashes



def get_file_length(
    filepath: str,
    storage_backend: Optional[StorageBackendInterface] = None
) -> int:
  """
  <Purpose>
    To get file's length information.

  <Arguments>
    filepath:
      Absolute file path of a file.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

  <Exceptions>
    securesystemslib.exceptions.StorageError: The file at "filepath" cannot be
    opened or found.

  <Returns>
    The length, in bytes, of the file at 'filepath'.
  """

  # Making sure that the format of 'filepath' is a path string.
  # 'securesystemslib.exceptions.FormatError' is raised on incorrect format.
  formats.PATH_SCHEMA.check_match(filepath)

  if storage_backend is None:
      storage_backend = FilesystemBackend()

  return storage_backend.getsize(filepath)


def persist_temp_file(
    temp_file: IO,
    persist_path: str,
    storage_backend: Optional[StorageBackendInterface] = None,
    should_close: bool = True
) -> None:
  """
  <Purpose>
    Copies 'temp_file' (a file like object) to a newly created non-temp file at
    'persist_path'.

  <Arguments>
    temp_file:
      File object to persist, typically a file object returned by one of the
      interfaces in the tempfile module of the standard library.

    persist_path:
      File path to create the persistent file in.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

    should_close:
      A boolean indicating whether the file should be closed after it has been
      persisted. Default is True, the file is closed.

  <Exceptions>
    securesystemslib.exceptions.StorageError: If file cannot be written.

  <Return>
    None.
  """

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  storage_backend.put(temp_file, persist_path)

  if should_close:
    temp_file.close()


def ensure_parent_dir(
    filename: str,
    storage_backend: Optional[StorageBackendInterface] = None
) -> None:
  """
  <Purpose>
    To ensure existence of the parent directory of 'filename'.  If the parent
    directory of 'name' does not exist, create it.

    Example: If 'filename' is '/a/b/c/d.txt', and only the directory '/a/b/'
    exists, then directory '/a/b/c/d/' will be created.

  <Arguments>
    filename:
      A path string.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

  <Exceptions>
    securesystemslib.exceptions.FormatError: If 'filename' is improperly
    formatted.
    securesystemslib.exceptions.StorageError: When folder cannot be created.

  <Side Effects>
    A directory is created whenever the parent directory of 'filename' does not
    exist.

  <Return>
    None.
  """

  # Ensure 'filename' corresponds to 'PATH_SCHEMA'.
  # Raise 'securesystemslib.exceptions.FormatError' on a mismatch.
  formats.PATH_SCHEMA.check_match(filename)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  # Split 'filename' into head and tail, check if head exists.
  directory = os.path.split(filename)[0]

  # Check for cases where filename is without directory like 'file.txt'
  # and as a result directory is an empty string
  if directory:
    storage_backend.create_folder(directory)


def file_in_confined_directories(
    filepath: str,
    confined_directories: Sequence[str]
) -> bool:
  """
  <Purpose>
    Check if the directory containing 'filepath' is in the list/tuple of
    'confined_directories'.

  <Arguments>
    filepath:
      A string representing the path of a file.  The following example path
      strings are viewed as files and not directories: 'a/b/c', 'a/b/c.txt'.

    confined_directories:
      A sequence (such as list, or tuple) of directory strings.

  <Exceptions>
   securesystemslib.exceptions.FormatError: On incorrect format of the input.

  <Return>
    Boolean.  True, if path is either the empty string
    or in 'confined_paths'; False, otherwise.
  """

  # Do the arguments have the correct format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  formats.PATH_SCHEMA.check_match(filepath)
  formats.NAMES_SCHEMA.check_match(confined_directories)

  for confined_directory in confined_directories:
    # The empty string (arbitrarily chosen) signifies the client is confined
    # to all directories and subdirectories.  No need to check 'filepath'.
    if confined_directory == '':
      return True

    # Normalized paths needed, to account for up-level references, etc.
    # callers have the option of setting the list of directories in
    # 'confined_directories'.
    filepath = os.path.normpath(filepath)
    confined_directory = os.path.normpath(confined_directory)

    # A caller may restrict himself to specific directories on the
    # remote repository.  The list of paths in 'confined_path', not including
    # each path's subdirectories, are the only directories the client will
    # download targets from.
    if os.path.dirname(filepath) == confined_directory:
      return True

  return False


def load_json_string(data: Union[str, bytes]) -> Any:
  """
  <Purpose>
    Deserialize 'data' (JSON string) to a Python object.

  <Arguments>
    data:
      A JSON string.

  <Exceptions>
    securesystemslib.exceptions.Error, if 'data' cannot be deserialized to a
    Python object.

  <Side Effects>
    None.

  <Returns>
    Deserialized object.  For example, a dictionary.
  """

  deserialized_object = None

  try:
    deserialized_object = json.loads(data)

  except TypeError:
    message = 'Invalid JSON string: ' + repr(data)
    raise exceptions.Error(message)

  except ValueError:
    message = 'Cannot deserialize to a Python object: ' + repr(data)
    raise exceptions.Error(message)

  else:
    return deserialized_object


def load_json_file(
    filepath: str,
    storage_backend: Optional[StorageBackendInterface] = None
) -> Any:
  """
  <Purpose>
    Deserialize a JSON object from a file containing the object.

  <Arguments>
    filepath:
      Absolute path of JSON file.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

  <Exceptions>
    securesystemslib.exceptions.FormatError: If 'filepath' is improperly
    formatted.

    securesystemslib.exceptions.Error: If 'filepath' cannot be deserialized to
    a Python object.

    securesystemslib.exceptions.StorageError: If file cannot be loaded.

    IOError in case of runtime IO exceptions.

  <Side Effects>
    None.

  <Return>
    Deserialized object.  For example, a dictionary.
  """

  # Making sure that the format of 'filepath' is a path string.
  # securesystemslib.exceptions.FormatError is raised on incorrect format.
  formats.PATH_SCHEMA.check_match(filepath)

  if storage_backend is None:
    storage_backend = FilesystemBackend()

  deserialized_object = None
  with storage_backend.get(filepath) as file_obj:
    raw_data = file_obj.read().decode('utf-8')

    try:
      deserialized_object = json.loads(raw_data)

    except (ValueError, TypeError):
      raise exceptions.Error('Cannot deserialize to a'
          ' Python object: ' + filepath)

    else:
      return deserialized_object


def digests_are_equal(digest1: str, digest2: str) -> bool:
  """
  <Purpose>
    While protecting against timing attacks, compare the hexadecimal arguments
    and determine if they are equal.

  <Arguments>
    digest1:
      The first hexadecimal string value to compare.

    digest2:
      The second hexadecimal string value to compare.

  <Exceptions>
    securesystemslib.exceptions.FormatError: If the arguments are improperly
    formatted.

  <Side Effects>
    None.

  <Return>
    Return True if 'digest1' is equal to 'digest2', False otherwise.
  """

  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  formats.HEX_SCHEMA.check_match(digest1)
  formats.HEX_SCHEMA.check_match(digest2)

  if len(digest1) != len(digest2):
    return False

  are_equal = True

  for element in range(len(digest1)):
    if digest1[element] != digest2[element]:
      are_equal = False

  return are_equal
