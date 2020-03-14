#!/usr/bin/env python

"""
<Program Name>
  hsm.py

<Author>
  Tanishq Jasoria <jasoriatanishq@gmail.com>

<Purpose>
  The goal of this module is to support hardware security modules through
  the PKCS#11 standard.

  This module uses PyKCS11, a python wrapper (SWIG) for PKCS#11 modules
  to communicate with the cryptographic tokens
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import logging
import securesystemslib.exceptions

logger = logging.getLogger(__name__)

# Import cryptography routines needed to retrieve cryptographic
# keys and certificates.
CRYPTO = True
NO_CRYPTO_MSG = "To retrieve cryptographic keys and certificates " \
                "cryptography library is needed."
try:
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.backends import default_backend
  from cryptography import x509
except ImportError:
  CRYPTO = False

# Import python wrapper for PKCS#11 to communicate with the tokens
HSM_SUPPORT = True
NO_HSM_MSG = "HSM support requires PyKCS11 library."
try:
  import PyKCS11
  PKCS11 = PyKCS11.PyKCS11Lib()

except ImportError:
  HSM_SUPPORT = False

# Load the library needed to interact with HSM using PKCS#11.
HSM_LIB = True
NO_HSM_LIB_MSG = "Env variable PYKCS11LIB must be set to interact with HSM " \
                 "using PKCS#11. Load the library using load_pkcs11_library()."
try:
  PKCS11.load()

except PyKCS11.PyKCS11Error:
  HSM_LIB = False

# Path to PKCS11 Library. Can be initialized using load_pkcs11_library function call.
# This variable would be used to keep track of the path of PKCS11LIB as it would be
# needed to refresh the list of available HSMs.
PKCS11LIB = None





def load_pkcs11_library(path=None):
  """
  <Purpose>
    To load the PKCS11 library if the corresponding environment variable is not set.

  <Arguments>
    path:
      path to the PKCS#11 library. This can be module specific or
      library by OpenSC(opensc-pkcs11.so) can be used.

  <Excepitions>
    securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
    library is not specified or the library is corrupt
  """

  if not HSM_SUPPORT: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

  global PKCS11LIB
  # Try to load the PKCS11 library
  try:
    # Load the PKCS#11 library and simulataneously update the list of available HSMs.
    PKCS11.load(path)
    PKCS11LIB = path
  except PyKCS11.PyKCS11Error as error:
    logger.error('PKS11 Library not found or is corrupt!')
    raise securesystemslib.exceptions.NotFoundError(error.__str__())
