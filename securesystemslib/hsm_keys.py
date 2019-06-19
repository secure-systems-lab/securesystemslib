#!/usr/bin/env python

"""
<Program Name>
  hsm_keys.py

<Author>
  Tanishq Jasoria <jasoriatanishq@gmail.com>

<Purpose>
  This module provides a high-level API for using hardware security modules
  for various cryptographic operations

  This module current supports
  1. Create and Verify signature using keys from a HSM
  2. Export public key and X509 certificates store in HSM in PEM format.
"""

from securesystemslib.hsm import HSM
from securesystemslib.settings import PKCS11LIB
import securesystemslib.interface
import securesystemslib.exceptions
import binascii

# Import cryptography routines needed to retrieve cryptographic
# keys and certificates in PEM format.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Create a global object of class HSM which would be used by
# all the methods to perform various operations.
smartcard = HSM(PKCS11LIB)


def load_HSMs():
  """
  <Purpose>
    To get list of all the available HSMs

  <Exceptions>
    securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
    library is not specified in 'settings.py' or the library is corrupt

  <Returns>
    list of dictionaries corresponding to all the available HSMs
  """

  # All the functions must use the same object of the HSM class,
  # to use same session for all the operations.
  global smartcard
  smartcard = HSM(PKCS11LIB)

  # Get information reagarding the available HSM
  available_HSM = smartcard.get_available_HSMs()
  return available_HSM