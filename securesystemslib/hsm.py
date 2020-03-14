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


def get_available_HSMs():
  """
  <Purpose>
    Generate the list of available cryptographic tokens for the user

  <Returns>
    A list of dictionaries consisting of relevant information
    regarding all the available tokens
  """

  # Refresh the list of available slots for HSM
  _refresh()

  # Get the list of slots on which HSMs are available
  slot_list = PKCS11.getSlotList()
  slot_info_list = []

  # For all the available HSMs available, add relevant information
  # to the slots dictionary
  for slot in slot_list:
    slot_dict = dict()
    slot_dict['slot_id'] = slot
    slot_info = PKCS11.getSlotInfo(slot)
    slot_dict['flags'] = slot_info.flags2text()
    slot_dict['manufacturer_id'] = slot_info.manufacturerID
    slot_dict['slot_description'] = slot_info.slotDescription
    slot_info_list.append(slot_dict)

  return slot_info_list


def _refresh():
  """
  To refresh the list of available HSMs.
  """

  PKCS11.load(PKCS11LIB)


def _create_session(slot_info):
  """
  Open a session with the HSM corresponding to the slot_info provided
  by the user.
  """

  try:
    session = PKCS11.openSession(slot_info['slot_id'],
        PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
  except PyKCS11.PyKCS11Error as error:
    raise securesystemslib.exceptions.InvalidNameError(
        "The requested token is not available." + str(error))
  except KeyError:
    raise securesystemslib.exceptions.InvalidNameError(
        "Invalid Input, not a slot_info dictionary.")

  return session