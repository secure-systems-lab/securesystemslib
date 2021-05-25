"""
<Program Name>
  exceptions.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  VD: April 4, 2012 Revision.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Define exceptions.  The names chosen for exception classes should end in
  'Error' (except where there is a good reason not to).
"""

class Error(Exception):
  """Indicate a generic error."""
  pass


class Warning(Warning):
  """Generic warning.  It is used by the 'warnings' module."""
  pass


class FormatError(Error):
  """Indicate an error while validating an object's format."""
  pass


class InvalidMetadataJSONError(FormatError):
  """Indicate that a metadata file is not valid JSON."""

  def __init__(self, exception):
    # Store the original exception.
    self.exception = exception

  def __str__(self):
    # Show the original exception.
    return repr(self.exception)

class UnsupportedAlgorithmError(Error):
  """Indicate an error while trying to identify a user-specified algorithm."""
  pass


class BadHashError(Error):
  """Indicate an error while checking the value a hash object."""

  def __init__(self, expected_hash, observed_hash):
    self.expected_hash = expected_hash
    self.observed_hash = observed_hash

  def __str__(self):
    return 'Observed hash (' + repr(self.observed_hash)+\
           ') != expected hash (' + repr(self.expected_hash)+')'


class BadPasswordError(Error):
  """Indicate an error after encountering an invalid password."""
  pass


class CryptoError(Error):
  """Indicate any cryptography-related errors."""
  pass


class BadSignatureError(CryptoError):
  """Indicate that some metadata has a bad signature."""

  def __init__(self, metadata_role_name):
    self.metadata_role_name = metadata_role_name

  def __str__(self):
    return repr(self.metadata_role_name) + ' metadata has bad signature.'


class UnknownMethodError(CryptoError):
  """Indicate that a user-specified cryptograpthic method is unknown."""
  pass


class UnsupportedLibraryError(Error):
  """Indicate that a supported library could not be located or imported."""
  pass


class InvalidNameError(Error):
  """Indicate an error while trying to validate any type of named object."""
  pass


class NotFoundError(Error):
  """If a required configuration or resource is not found."""
  pass


class URLMatchesNoPatternError(Error):
  """If a URL does not match a user-specified regular expression."""
  pass


class InvalidConfigurationError(Error):
  """If a configuration object does not match the expected format."""
  pass

class StorageError(Error):
  """Indicate an error occured during interaction with an abstracted storage
     backend."""
  pass
