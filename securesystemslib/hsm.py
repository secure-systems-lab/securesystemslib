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

import binascii
import logging
import securesystemslib.exceptions
from securesystemslib.keys import extract_pem

logger = logging.getLogger(__name__)

# Import cryptography routines needed to retrieve cryptographic
# keys and certificates.
CRYPTO = True
NO_CRYPTO_MSG = "To retrieve cryptographic keys and certificates " \
                "cryptography library is needed."
try:
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
  from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
  from cryptography import x509
except ImportError:
  CRYPTO = False

# Default salt size, in bytes.  A 128-bit salt (i.e., a random sequence of data
# to protect against attacks that use precomputed rainbow tables to crack
# password hashes) is generated for PBKDF2.
_SALT_SIZE = 16

# Import python wrapper for PKCS#11 to communicate with the tokens
HSM_SUPPORT = True
NO_HSM_MSG = "HSM support requires PyKCS11 library."
try:
  import PyKCS11
  PKCS11 = PyKCS11.PyKCS11Lib()

  RSA_PKCS1V15_SHA256 = PyKCS11.RSA_PSS_Mechanism(
      PyKCS11.CKM_SHA256_RSA_PKCS,
      PyKCS11.CKM_SHA256,
      PyKCS11.CKG_MGF1_SHA256,
      _SALT_SIZE
  )

  RSASSA_PSS_SHA256 = PyKCS11.RSA_PSS_Mechanism(
      PyKCS11.CKM_SHA1_RSA_PKCS_PSS,
      PyKCS11.CKM_SHA256,
      PyKCS11.CKG_MGF1_SHA256,
      _SALT_SIZE
  )

  ECDSA_SIGN = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)

  MECHANISMS = {
    "rsa-pkcs1v15-sha256": RSA_PKCS1V15_SHA256,
    "rsassa-pss-sha256": RSASSA_PSS_SHA256,
    "ecdsa-sign": ECDSA_SIGN
  }

except ImportError:
  HSM_SUPPORT = False

# Load the library needed to interact with HSM if PyKCS11 is present.
if HSM_SUPPORT:
  HSM_LIB = True
  NO_HSM_LIB_MSG = "Env variable PYKCS11LIB must be set to interact with HSM " \
                   "using PKCS#11. Load the library using load_pkcs11_library(path)."
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
  global HSM_LIB
  # Try to load the PKCS11 library
  try:
    # Load the PKCS#11 library and simulataneously update the list of available HSMs.
    PKCS11.load(path)
    PKCS11LIB = path
    HSM_LIB = True
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

  if not HSM_SUPPORT: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

  if not HSM_LIB: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

  # Refresh the list of available slots for HSM
  _refresh()

  # Get the list of slots on which HSMs are available
  slot_list = PKCS11.getSlotList()
  hsm_info_list = []

  # For all the available HSMs available, add relevant information
  # to the slots dictionary
  for slot in slot_list:
    hsm_info = PKCS11.getSlotInfo(slot)
    hsm_dict = {
        'slot_id': slot,
        'slot_info': hsm_info,
        'flags': hsm_info.flags2text(),
        'manufacturer_id': hsm_info.manufacturerID,
        'slot_description': hsm_info.slotDescription.strip()
    }
    hsm_info_list.append(hsm_dict)

  return hsm_info_list


def get_private_key_objects(hsm_info, user_pin):
  """
  <Purpose>
    Get object handles of private keys stored on the HSM.
    login required before using this method.

  <Returns>
    List of all key_id and key_modulus for all the keys in HSM
  """

  if not HSM_SUPPORT: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

  if not HSM_LIB: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

  # Create an HSM session and login to access private objects.
  session = _create_session(hsm_info)
  _login(session, str(user_pin))

  # Retirve all the private key object present on the HSM
  private_key_objects = session.findObjects([(PyKCS11.CKA_CLASS,
      PyKCS11.CKO_PRIVATE_KEY)])

  # TODO: Find a better way to provide the details regarding the available keys.
  key_info = []
  for object_handle in private_key_objects:
    # Find and return the key_id(with resepect to the HSM) and the key modulus
    key_id, key_modulus = session.getAttributeValue(object_handle,
        [PyKCS11.CKA_ID, PyKCS11.CKA_MODULUS])
    key_info.append([key_id, key_modulus])

  return key_info


def get_public_key_objects(hsm_info):
  """
  <Purpose>
    Get object handles of public keys stored on the HSM.

  <Returns>
    List of  key_id and key_modulus for all the public keys in HSM
  """

  if not HSM_SUPPORT: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

  if not HSM_LIB: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

  # Create an HSM session to access private objects.
  session = _create_session(hsm_info)

  # Retirve all the public key object present on the HSM.
  public_key_objects = session.findObjects([(PyKCS11.CKA_CLASS,
      PyKCS11.CKO_PUBLIC_KEY)])

  # TODO: Find a better way to provide the details regarding the available keys.
  key_info = []
  for object_handle in public_key_objects:
    # Find and return the key_id(with resepect to the HSM) and the key modulus
    key_id, key_modulus = session.getAttributeValue(object_handle,
        [PyKCS11.CKA_ID, PyKCS11.CKA_MODULUS])
    key_info.append([key_id, key_modulus])

  return key_info


def export_pubkey(hsm_info, public_key_info):
  """
  <Purpose>
    Get the public key value corresponding to the 'public_key_handle'

  <Arguments>
    public_key_info:
      element of the list returned by get_public_key_objects().

  <Exceptions>
    securesystemslib.exceptions.UnsupportedLibraryError, if the cryptography
    module is not available.

  <Returns>
    A dictionary containing the public key value and other identifying information.
    Conforms to 'securesystemslib.formats.PUBLIC_KEY_SCHEMA'.
  """

  if not HSM_SUPPORT: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

  if not HSM_LIB: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

  if not CRYPTO: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

  # Create session with the HSM(corresponding to hsm_info) to retrieve public key value.
  session = _create_session(hsm_info)

  # Find the public key handle corresponding to the key_id.
  public_key_object = session.findObjects([(PyKCS11.CKA_CLASS,
      PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, public_key_info[0])])[0]

  # Retrieve the public key bytes for the required public key
  public_key_value, public_key_type = session.getAttributeValue(public_key_object,
      [PyKCS11.CKA_VALUE, PyKCS11.CKA_KEY_TYPE])

  public_key =""
  if public_key_value:
    public_key_value = bytes(public_key_value)
    # Public key value exported from the HSM is der encoded
    public_key = serialization.load_der_public_key(public_key_value,
        default_backend())
  else:
    if PyKCS11.CKK[public_key_type] == 'CKK_RSA':
      public_key_modulus, public_key_exponent = session.getAttributeValue(public_key_object,
          [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT])
      public_key_modulus = _to_hex(public_key_modulus)
      public_key_exponent = _to_hex(public_key_exponent)
      public_numbers = RSAPublicNumbers( int(public_key_exponent,16),
          int(public_key_modulus,16))
      public_key = public_numbers.public_key(default_backend())
    elif PyKCS11.CKK[public_key_type] == 'CKK_EC' or PyKCS11.CKK[public_key_type] == 'CKK_ECDSA':
      raise securesystemslib.exceptions.UnsupportedAlgorithmError(
          "The public key for " + repr(PyKCS11.CKK[public_key_type]) + " cannot be generated "
          "using parameters. This functionality is yet not supported"
      )
    else:
      raise securesystemslib.exceptions.UnsupportedAlgorithmError(
          "The Key type " + repr(PyKCS11.CKK[public_key_type]) + " is currently not supported!")

  logger.error(public_key)
  public = public_key.public_bytes(encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo)
  # Strip any leading or trailing new line characters.
  public = extract_pem(public.decode('utf-8'), private_pem=False)

  key_value = {'public': public.replace('\r\n', '\n'),
               'private': ''}

  # Return the public key conforming to the securesystemslib.format.PUBLIC_KEY_SCHEMA
  key_dict = {}
  key_dict['keyval'] = key_value

  if PyKCS11.CKK[public_key_type] == 'CKK_RSA':
    key_dict['keytype'] = 'rsa'
    # Currently keeping a default scheme
    # TODO: Decide a way to provide user with options regarding various schemes available
    key_dict['scheme'] = "rsa-pkcs1v15-sha256"
  elif PyKCS11.CKK[public_key_type] == 'CKK_EC' or PyKCS11.CKK[public_key_type] == 'CKK_ECDSA':
    key_dict['keytype'] = 'ecdsa'
    key_dict['scheme'] = 'ecdsa-sign'
  else:
    raise securesystemslib.exceptions.UnsupportedAlgorithmError(
        "The Key type " + repr(PyKCS11.CKK[public_key_type]) + " is currently not supported!")

  return key_dict


def create_signature(data, hsm_info, private_key_info, user_pin):
  """
  <Purpose>
    Calculate signature over 'data' using the private key corresponding
    to the 'private_key_info'

    Supported Keys
    1. RSA - rsassa-pss-sha256
    2. ECDSA

  <Arguments>
    data:
      bytes over which the signature is to be calculated
      'data' should be encoded/serialized before it is passed here.

    private_key_info:
      element from the list returned by the get_private_key_objects()

    user_pin:
      PIN for the CKU_USER login.

  <Exceptions>
    securesystemslib.exceptions.UnsupportedAlgorithmError, when the
    key type of the 'private_key_handle' is not supported

  <Returns>
    A signature dictionary conformant to
    'securesystemslib_format.SIGNATURE_SCHEMA'.
  """

  if not HSM_SUPPORT: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

  if not HSM_LIB: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

  # Create a session and login to generate signature using keys stored in hsm
  session = _create_session(hsm_info)
  _login(session, str(user_pin))

  mechanism = None
  private_key_object = session.findObjects([(PyKCS11.CKA_CLASS,
      PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, private_key_info[0])])[0]
  key_type = session.getAttributeValue(private_key_object,
      [PyKCS11.CKA_KEY_TYPE])[0]

  if PyKCS11.CKK[key_type] == 'CKK_RSA':
    mechanism = MECHANISMS["rsa-pkcs1v15-sha256"]

  elif PyKCS11.CKK[key_type] == 'CKK_EC' or PyKCS11.CKK[key_type] == 'CKK_ECDSA':
    mechanism = MECHANISMS["ecdsa-sign"]

  if mechanism is None:
    raise securesystemslib.exceptions.UnsupportedAlgorithmError(
      "The Key type " + repr(key_type) + " is currently not supported!")


  signature = session.sign(private_key_object, data, mechanism)

  signature_dict = {}
  # TODO: This is not a key id, change this.
  keyid = _to_hex(private_key_info[0])
  sig = _to_hex(signature)

  signature_dict['keyid'] = keyid
  signature_dict['sig'] = sig

  return signature_dict


def _refresh():
  """
  To refresh the list of available HSMs.
  """

  PKCS11.load(PKCS11LIB)


def _create_session(hsm_info):
  """
  Open a session with the HSM corresponding to the slot_info provided
  by the user.
  """

  try:
    session = PKCS11.openSession(hsm_info['slot_id'],
        PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
  except PyKCS11.PyKCS11Error as error:
    raise securesystemslib.exceptions.InvalidNameError(
        "The requested token is not available." + str(error))
  except KeyError:
    raise securesystemslib.exceptions.InvalidNameError(
        "Invalid Input, not a slot_info dictionary.")

  return session


def _login(session, user_pin):
  """
  User Login into the HSM. Required to access private objects.
  """

  try:
    session.login(user_pin)
  except PyKCS11.PyKCS11Error as error:
    if PyKCS11.CKR[error.value] == "CKR_USER_ALREADY_LOGGED_IN":
      logger.warning('Already logged in as CKU_USER.')
    else:
      raise securesystemslib.exceptions.BadPasswordError("Wrong User Pin!")


def _logout(session):
  """
  Logout from the CKU_USER session
  """

  session.logout()


def _destroy_session(session):
  """
  To logout and terminate the session with the HSM completely.
  """

  # Logout form the admin session
  try:
    _logout(session)
  except PyKCS11.PyKCS11Error as error:
    # Error is raised when user does not have an active admin session
    logger.warning(error)

  # After logout, completely terminate the session with the HSM.
  try:
    session.closeSession()
  except PyKCS11.PyKCS11Error as error:
    # Error is raised when there is no active session with the HSM.
    logger.warning(str(error))


def _to_hex(data_tuple):
  """
  To convert values returned by HSM, in tuples, to HEX string
  """

  return binascii.hexlify(bytes(data_tuple)).decode('utf-8')
