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

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import gzip
import shutil
import logging
import tempfile
import warnings

import securesystemslib.exceptions
import securesystemslib.settings
import securesystemslib.hash
import securesystemslib.formats

import six

logger = logging.getLogger('securesystemslib_util')


def get_file_details(filepath, hash_algorithms=['sha256']):
  """
  <Purpose>
    To get file's length and hash information.  The hash is computed using the
    sha256 algorithm.  This function is used in the signerlib.py and updater.py
    modules.

  <Arguments>
    filepath:
      Absolute file path of a file.

    hash_algorithms:

  <Exceptions>
    securesystemslib.exceptions.FormatError: If hash of the file does not match
    HASHDICT_SCHEMA.

    securesystemslib.exceptions.Error: If 'filepath' does not exist.

  <Returns>
    A tuple (length, hashes) describing 'filepath'.
  """

  # Making sure that the format of 'filepath' is a path string.
  # 'securesystemslib.exceptions.FormatError' is raised on incorrect format.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)
  securesystemslib.formats.HASHALGORITHMS_SCHEMA.check_match(hash_algorithms)

  # The returned file hashes of 'filepath'.
  file_hashes = {}

  # Does the path exists?
  if not os.path.exists(filepath):
    raise securesystemslib.exceptions.Error('Path ' + repr(filepath) + ' doest'
        ' not exist.')

  filepath = os.path.abspath(filepath)

  # Obtaining length of the file.
  file_length = os.path.getsize(filepath)

  # Obtaining hash of the file.
  for algorithm in hash_algorithms:
    digest_object = securesystemslib.hash.digest_filename(filepath, algorithm)
    file_hashes.update({algorithm: digest_object.hexdigest()})

  # Performing a format check to ensure 'file_hash' corresponds HASHDICT_SCHEMA.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.HASHDICT_SCHEMA.check_match(file_hashes)

  return file_length, file_hashes


def persist_temp_file(temp_file, persist_path):
  """
  <Purpose>
    Copies 'temp_file' (a file like object) to a newly created non-temp file at
    'persist_path' and closes 'temp_file' so that it is removed.

  <Arguments>
    temp_file:
      File object to persist, typically a file object returned by one of the
      interfaces in the tempfile module of the standard library.

    persist_path:
      File path to create the persistent file in.

  <Exceptions>
    None.

  <Return>
    None.
  """

  temp_file.flush()
  temp_file.seek(0)

  with open(persist_path, 'wb') as destination_file:
    shutil.copyfileobj(temp_file, destination_file)
    # Force the destination file to be written to disk from Python's internal
    # and the operation system's buffers.  os.fsync() should follow flush().
    destination_file.flush()
    os.fsync(destination_file.fileno())

  temp_file.close()

def ensure_parent_dir(filename):
  """
  <Purpose>
    To ensure existence of the parent directory of 'filename'.  If the parent
    directory of 'name' does not exist, create it.

    Example: If 'filename' is '/a/b/c/d.txt', and only the directory '/a/b/'
    exists, then directory '/a/b/c/d/' will be created.

  <Arguments>
    filename:
      A path string.

  <Exceptions>
    securesystemslib.exceptions.FormatError: If 'filename' is improperly
    formatted.

  <Side Effects>
    A directory is created whenever the parent directory of 'filename' does not
    exist.

  <Return>
    None.
  """

  # Ensure 'filename' corresponds to 'PATH_SCHEMA'.
  # Raise 'securesystemslib.exceptions.FormatError' on a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filename)

  # Split 'filename' into head and tail, check if head exists.
  directory = os.path.split(filename)[0]

  if directory and not os.path.exists(directory):
    # mode = 'rwx------'. 448 (decimal) is 700 in octal.
    os.makedirs(directory, 448)


def file_in_confined_directories(filepath, confined_directories):
  """
  <Purpose>
    Check if the directory containing 'filepath' is in the list/tuple of
    'confined_directories'.

  <Arguments>
    filepath:
      A string representing the path of a file.  The following example path
      strings are viewed as files and not directories: 'a/b/c', 'a/b/c.txt'.

    confined_directories:
      A list, or a tuple, of directory strings.

  <Exceptions>
   securesystemslib.exceptions.FormatError: On incorrect format of the input.

  <Return>
    Boolean.  True, if path is either the empty string
    or in 'confined_paths'; False, otherwise.
  """

  # Do the arguments have the correct format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)
  securesystemslib.formats.PATHS_SCHEMA.check_match(confined_directories)

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





_json_module = None

def import_json():
  """
  <Purpose>
    Tries to import json module. We used to fall back to the simplejson module,
    but we have dropped support for that module. We are keeping this interface
    intact for backwards compatibility.

  <Arguments>
    None.

  <Exceptions>
    ImportError: on failure to import the json module.

  <Side Effects>
    None.

  <Return>
    json module
  """

  global _json_module

  if _json_module is not None:
    return _json_module

  else:
    # TODO: Drop Python < 2.6 case handling
    try:
      module = __import__('json')
    # The 'json' module is available in Python > 2.6, and thus this exception
    # should not occur in all supported Python installations (> 2.6).
    except ImportError: #pragma: no cover
      raise ImportError('Could not import the json module')

    else:
      _json_module = module
      return module

json = import_json()


def load_json_string(data):
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
    raise securesystemslib.exceptions.Error(message)

  except ValueError:
    message = 'Cannot deserialize to a Python object: ' + repr(data)
    raise securesystemslib.exceptions.Error(message)

  else:
    return deserialized_object


def load_json_file(filepath):
  """
  <Purpose>
    Deserialize a JSON object from a file containing the object.

  <Arguments>
    filepath:
      Absolute path of JSON file.

  <Exceptions>
    securesystemslib.exceptions.FormatError: If 'filepath' is improperly
    formatted.

    securesystemslib.exceptions.Error: If 'filepath' cannot be deserialized to
    a Python object.

    IOError in case of runtime IO exceptions.

  <Side Effects>
    None.

  <Return>
    Deserialized object.  For example, a dictionary.
  """

  # Making sure that the format of 'filepath' is a path string.
  # securesystemslib.exceptions.FormatError is raised on incorrect format.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  deserialized_object = None

  # The file is mostly likely gzipped.
  if filepath.endswith('.gz'):
    logger.debug('gzip.open(' + str(filepath) + ')')
    fileobject = six.StringIO(gzip.open(filepath).read().decode('utf-8'))

  else:
    logger.debug('open(' + str(filepath) + ')')
    fileobject = open(filepath)

  try:
    deserialized_object = json.load(fileobject)

  except (ValueError, TypeError) as e:
    raise securesystemslib.exceptions.Error('Cannot deserialize to a'
      ' Python object: ' + repr(filepath))

  else:
    fileobject.close()
    return deserialized_object

  finally:
    fileobject.close()


def digests_are_equal(digest1, digest2):
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
  securesystemslib.formats.HEX_SCHEMA.check_match(digest1)
  securesystemslib.formats.HEX_SCHEMA.check_match(digest2)

  if len(digest1) != len(digest2):
    return False

  are_equal = True

  for element in range(len(digest1)):
    if digest1[element] != digest2[element]:
      are_equal = False

  return are_equal
