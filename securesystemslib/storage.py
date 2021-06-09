"""
<Program Name>
  storage.py

<Author>
  Joshua Lock <jlock@vmware.com>

<Started>
  April 9, 2020

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides an interface for filesystem interactions, StorageBackendInterface.
"""

import abc
import errno
import logging
import os
import shutil
from contextlib import contextmanager
from securesystemslib import exceptions
from typing import BinaryIO, IO, Iterator, List

logger = logging.getLogger(__name__)


class StorageBackendInterface():
  """
  <Purpose>
  Defines an interface for abstract storage operations which can be implemented
  for a variety of storage solutions, such as remote and local filesystems.
  """

  __metaclass__ = abc.ABCMeta


  @abc.abstractmethod
  @contextmanager
  def get(self, filepath: str) -> Iterator[BinaryIO]:
    """
    <Purpose>
      A context manager for 'with' statements that is used for retrieving files
      from a storage backend and cleans up the files upon exit.

        with storage_backend.get('/path/to/file') as file_object:
          # operations
        # file is now closed

    <Arguments>
      filepath:
        The full path of the file to be retrieved.

    <Exceptions>
      securesystemslib.exceptions.StorageError, if the file does not exist or is
      no accessible.

    <Returns>
      A ContextManager object that emits a file-like object for the file at
      'filepath'.
    """
    raise NotImplementedError # pragma: no cover


  @abc.abstractmethod
  def put(self, fileobj: IO, filepath: str) -> None:
    """
    <Purpose>
      Store a file-like object in the storage backend.
      The file-like object is read from the beginning, not its current
      offset (if any).

    <Arguments>
      fileobj:
        The file-like object to be stored.

      filepath:
        The full path to the location where 'fileobj' will be stored.

    <Exceptions>
      securesystemslib.exceptions.StorageError, if the file can not be stored.

    <Returns>
      None
    """
    raise NotImplementedError # pragma: no cover


  @abc.abstractmethod
  def remove(self, filepath: str) -> None:
    """
    <Purpose>
      Remove the file at 'filepath' from the storage.

    <Arguments>
      filepath:
        The full path to the file.

    <Exceptions>
      securesystemslib.exceptions.StorageError, if the file can not be removed.

    <Returns>
      None
    """
    raise NotImplementedError # pragma: no cover


  @abc.abstractmethod
  def getsize(self, filepath: str) -> int:
    """
    <Purpose>
      Retrieve the size, in bytes, of the file at 'filepath'.

    <Arguments>
      filepath:
        The full path to the file.

    <Exceptions>
      securesystemslib.exceptions.StorageError, if the file does not exist or is
      not accessible.

    <Returns>
      The size in bytes of the file at 'filepath'.
    """
    raise NotImplementedError # pragma: no cover


  @abc.abstractmethod
  def create_folder(self, filepath: str) -> None:
    """
    <Purpose>
      Create a folder at filepath and ensure all intermediate components of the
      path exist.
      Passing an empty string for filepath does nothing and does not raise an
      exception.

    <Arguments>
      filepath:
        The full path of the folder to be created.

    <Exceptions>
      securesystemslib.exceptions.StorageError, if the folder can not be
      created.

    <Returns>
      None
    """
    raise NotImplementedError # pragma: no cover


  @abc.abstractmethod
  def list_folder(self, filepath: str) -> List[str]:
    """
    <Purpose>
      List the contents of the folder at 'filepath'.

    <Arguments>
      filepath:
        The full path of the folder to be listed.

    <Exceptions>
      securesystemslib.exceptions.StorageError, if the file does not exist or is
      not accessible.

    <Returns>
      A list containing the names of the files in the folder. May be an empty
      list.
    """
    raise NotImplementedError # pragma: no cover





class FilesystemBackend(StorageBackendInterface):
  """
  <Purpose>
    A concrete implementation of StorageBackendInterface which interacts with
    local filesystems using Python standard library functions.
  """

  # As FilesystemBackend is effectively a stateless wrapper around various
  # standard library operations, we only ever need a single instance of it.
  # That single instance is safe to be (re-)used by all callers. Therefore
  # implement the singleton pattern to avoid uneccesarily creating multiple
  # objects.
  _instance = None

  def __new__(cls, *args, **kwargs):
    if cls._instance is None:
      cls._instance = object.__new__(cls, *args, **kwargs)
    return cls._instance


  @contextmanager
  def get(self, filepath:str) -> Iterator[BinaryIO]:
    file_object = None
    try:
      file_object = open(filepath, 'rb')
      yield file_object
    except OSError:
      raise exceptions.StorageError(
          "Can't open %s" % filepath)
    finally:
      if file_object is not None:
        file_object.close()


  def put(self, fileobj: IO, filepath: str) -> None:
    # If we are passed an open file, seek to the beginning such that we are
    # copying the entire contents
    if not fileobj.closed:
      fileobj.seek(0)

    try:
      with open(filepath, 'wb') as destination_file:
        shutil.copyfileobj(fileobj, destination_file)
        # Force the destination file to be written to disk from Python's internal
        # and the operating system's buffers.  os.fsync() should follow flush().
        destination_file.flush()
        os.fsync(destination_file.fileno())
    except OSError:
      raise exceptions.StorageError(
          "Can't write file %s" % filepath)


  def remove(self, filepath: str) -> None:
    try:
      os.remove(filepath)
    except (FileNotFoundError, PermissionError, OSError):  # pragma: no cover
      raise exceptions.StorageError(
          "Can't remove file %s" % filepath)


  def getsize(self, filepath: str) -> int:
    try:
      return os.path.getsize(filepath)
    except OSError:
      raise exceptions.StorageError(
          "Can't access file %s" % filepath)


  def create_folder(self, filepath: str) -> None:
    try:
      os.makedirs(filepath)
    except OSError as e:
      # 'OSError' raised if the leaf directory already exists or cannot be
      # created. Check for case where 'filepath' has already been created and
      # silently ignore.
      if e.errno == errno.EEXIST:
        pass
      elif e.errno == errno.ENOENT and not filepath:
        raise exceptions.StorageError(
            "Can't create a folder with an empty filepath!")
      else:
        raise exceptions.StorageError(
            "Can't create folder at %s" % filepath)


  def list_folder(self, filepath: str) -> List[str]:
    try:
      return os.listdir(filepath)
    except FileNotFoundError:
      raise exceptions.StorageError(
          "Can't list folder at %s" % filepath)
