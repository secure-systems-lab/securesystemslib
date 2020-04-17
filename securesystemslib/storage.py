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

from __future__ import absolute_import
from __future__ import unicode_literals

import abc
import errno
import logging
import os
import shutil

import securesystemslib.exceptions

logger = logging.getLogger(__name__)



class StorageBackendInterface():
  """
  <Purpose>
  Defines an interface for abstract storage operations which can be implemented
  for a variety of storage solutions, such as remote and local filesystems.
  """

  __metaclass__ = abc.ABCMeta


  @abc.abstractmethod
  def get(self, filepath):
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
  def put(self, fileobj, filepath):
    """
    <Purpose>
      Store a file-like object in the storage backend.

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
  def getsize(self, filepath):
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
  def create_folder(self, filepath):
    """
    <Purpose>
      Create a folder at filepath and ensure all intermediate components of the
      path exist.

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
  def list_folder(self, filepath):
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
