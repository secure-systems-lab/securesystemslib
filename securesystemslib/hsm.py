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

# Import python wrapper for PKCS#11 to communicate with the tokens
import PyKCS11

import binascii
import logging
import securesystemslib.exceptions

# Import cryptography routines needed to retrieve cryptographic
# keys and certificates in PEM format.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509

# RSA-PSS with SHA256 hash to be used for signature generation.
RSA_PSS_MECH = PyKCS11.CKM_SHA256_RSA_PKCS_PSS
# SHA256 hash to be used to digest the data.
RSA_PSS_HASH_SHA256 = PyKCS11.CKM_SHA256
# Mask generating function for SHA256 Hash.
RSA_PSS_MGF_SHA256 = PyKCS11.CKG_MGF1_SHA256
# Length of salt to be used for hashing.
RSA_PSS_SALT_LENGTH = 32

logger = logging.getLogger('securesystemslib_hsm')

class HSM(object):
  """
  <Purpose>
    Provides an interface to use cryptographic tokens for various
    cryptographic operations.

  <Arguments>
    PKCS11Lib_path:
       path to the PKCS#11 library. This can be module specific or
       library by OpenSC(opensc-pkcs11.so) can be used.
  <Exceptions>
    securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
    library is not specified or the library is corrupt
  """

  def __init__(self, PKCS11Lib_path):

    self.PKCS11LIB = PKCS11Lib_path

    # Initialize the PyKCS11Lib, wrapper of PKCS#11 in Python.
    self.PKCS11 = PyKCS11.PyKCS11Lib()

    self.session = None

    # Load the PKCS11 shared library file.
    self.refresh()





  def refresh(self):
    """
    <Purpose>
      This method refreshes the list of available cryptographic tokens.

    <Exceptions>
      securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
      library is not specified or the library is corrupt
    """

    # Try to load the PKCS11 library
    try:
      # Load the PKCS#11 library and simultaneously update the list
      # of available HSM.
      self.PKCS11.load(self.PKCS11LIB)
    except PyKCS11.PyKCS11Error as error:
      logger.info('PKS11 Library not found or is corrupt!')
      raise securesystemslib.exceptions.NotFoundError(error.__str__())





  def get_available_HSMs(self):
    """
    <Purpose>
      Generate the list of available cryptographic tokens for the user

    <Exceptions>
      securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
      library is not specified or the library is corrupt

    <Returns>
      A list of dictionaries consisting of relevant information
      regarding all the available tokens
    """

    # Refresh the list of available slots for HSM
    self.refresh()

    # Get the list of slots on which HSMs are available
    slot_list = self.PKCS11.getSlotList()
    slot_info_list = []

    # For all the available HSMs available, add relevant information
    # to the slots dictionary
    for slot in slot_list:
      slot_dict = dict()
      slot_dict['slot_id'] = slot
      slot_info = self.PKCS11.getSlotInfo(slot)
      slot_dict['flags'] = slot_info.flags2text()
      slot_dict['manufacturer_id'] = slot_info.manufacturerID
      slot_dict['slot_description'] = slot_info.slotDescription
      slot_info_list.append(slot_dict)

    return slot_info_list





  def get_HSM_session(self, slot_info):
    """
    <Purpose>
      Open a session with the HSM of the given 'slot_info'

    <Arguments>
      slot_info:
        element from the list returned by get_available_HSMs().

    <Exceptions>
      securesystemlib.exceptions.InvalidNameError, if the requested token
      is either not present or cannot be used.
    """
    try:
      self.session = self.PKCS11.openSession(slot_info['slot_id'],
          PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    except PyKCS11.PyKCS11Error as error:
      raise securesystemslib.exceptions.InvalidNameError(
          "The requested token is not available." + str(error))
    except KeyError:
      raise securesystemslib.exceptions.InvalidNameError(
          "Invalid Input, not a slot_info dictionary.")





  def login(self, user_pin):
    """
    <Purpose>
      User Login into the HSM. Required to access private objects.

    <Arguments>
      user_pin:
        PIN for the CKU_USER login.

    <Exceptions>
      securesystemslib.exceptions.BadPasswordError, if the entered
      user pin is invalid.
    """

    try:
      self.session.login(user_pin)
    except PyKCS11.PyKCS11Error as error:
      if error.__str__() == 'CKR_USER_ALREADY_LOGGED_IN (0x00000100)':
        logger.info('Already logged in as CKU_USER.')
      else:
        raise securesystemslib.exceptions.BadPasswordError("Wrong User Pin!")






  def get_private_key_objects(self):
    """
    <Purpose>
      Get object handles of private keys stored on the HSM.
      login required before using this method.

    <Returns>
      List of all available private key handles.
    """

    private_key_objects = self.session.findObjects([(PyKCS11.CKA_CLASS,
        PyKCS11.CKO_PRIVATE_KEY)])
    return private_key_objects





  def get_public_key_objects(self):
    """
    <Purpose>
      Get object handles of public keys stored on the HSM.

    <Returns>
      List of all available public key handles.
    """

    public_key_objects = self.session.findObjects([(PyKCS11.CKA_CLASS,
        PyKCS11.CKO_PUBLIC_KEY)])

    return public_key_objects





  def get_public_key_value(self, public_key_handle):
    """
    <Purpose>
      Get the public key value corresponding to the 'public_key_handle'

    <Arguments>
      public_key_handle:
        element of the list returned by get_public_key_objects().

    <Returns>
      'cryptography' public key object
    """

    public_key_value = self.session.getAttributeValue(public_key_handle,
        [PyKCS11.CKA_VALUE])[0]
    public_key_value = bytes(public_key_value)

    # Public key value exported from the HSM is der encoded
    public_key = serialization.load_der_public_key(public_key_value,
        default_backend())
    return public_key





  def get_X509_objects(self):
    """
    <Purpose>
      Get object handle of the X509 certificates stored on the HSM.

    <Returns>
      List of all the available certificate handles.
    """

    x509_objects = self.session.findObjects([(PyKCS11.CKA_CLASS,
        PyKCS11.CKO_CERTIFICATE)])
    return x509_objects





  def get_X509_value(self, x509_handle):
    """
    <Purpose>
      Get the certificate value corresponding to the 'x509_handle'.

    <Arguments>
      x509_handle:
        element from the list returned by get_X509_objects().

    <Returns>
      'cryptography' public key object.
    """

    x509_value = self.session.getAttributeValue(x509_handle,
        [PyKCS11.CKA_VALUE])[0]
    x509_certificate = x509.load_der_x509_certificate(
        bytes(x509_value), default_backend())

    return x509_certificate





  def generate_signature(self, data, private_key_handle):
    """
    <Purpose>
      Calculate signature over 'data' using the private key corresponding
      to the 'private_key_handle'

      Supported Keys
      1. RSA
      2. ECDSA

    <Arguments>
      data:
        bytes over which the signature is to be calculated
        'data' should be encoded/serialized before it is passed here.

      private_key_handle:
        element from the list returned by the get_private_key_objects()

    <Exceptions>
      securesystemslib.exceptions.UnsupportedAlgorithmError, when the
      key type of the 'private_key_handle' is not supported

    <Returns>
      HEX string of the generated signature
    """

    mechanism = None
    key_type = self.session.getAttributeValue(private_key_handle,
        [PyKCS11.CKA_KEY_TYPE])[0]

    if PyKCS11.CKK[key_type] == 'CKK_RSA':
      mechanism = PyKCS11.RSA_PSS_Mechanism(RSA_PSS_MECH,
          RSA_PSS_HASH_SHA256, RSA_PSS_MGF_SHA256, RSA_PSS_SALT_LENGTH)

    elif PyKCS11.CKK[key_type] == 'CKK_EC':
      mechanism = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)

    if mechanism is None:
      raise securesystemslib.exceptions.UnsupportedAlgorithmError(
        "The Key type " + repr(key_type) + " is currently not supported!")


    signature = self.session.sign(private_key_handle, data,
        mechanism)
    return binascii.hexlify(bytes(signature)).decode('utf-8')





  def verify_signature(self, signed_bytes, signature, public_key_handle):
    """
    <Purpose>
      Verify that the corresponding private key of the public_key
      generated 'signature' over 'signed_bytes'.

      Supported Keys
        1. RSA
        2. ECDSA

    <Arguments>
      signed_bytes:
        bytes over which the signature was calculated.
        should be encoded/serialized before it is passed here.

      signature:
        HEX string generated by generate_signature()

      private_key_handle:
        element form the list returned by the get_private_key_objects()

    <Exceptions>
      securesystemslib.exceptions.UnsupportedAlgorithmError, when the
      key type of the 'public_key_handle' is not supported

    <Returns>
      bool value for the correctness of the signature
    """

    # Convert HEX string to bytes
    signature_bytes = binascii.unhexlify(signature)
    mechanism = None
    key_type = self.session.getAttributeValue(public_key_handle,
        [PyKCS11.CKA_KEY_TYPE])[0]

    if PyKCS11.CKK[key_type] == 'CKK_RSA':
      mechanism = PyKCS11.RSA_PSS_Mechanism(RSA_PSS_MECH,
          RSA_PSS_HASH_SHA256, RSA_PSS_MGF_SHA256, RSA_PSS_SALT_LENGTH)

    elif PyKCS11.CKK[key_type] == 'CKK_EC':
      mechanism = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)

    if mechanism is None:
      raise securesystemslib.exceptions.UnsupportedAlgorithmError(
          "The Key type " + repr(key_type) + " is currently not supported!")

    result = self.session.verify(public_key_handle, signed_bytes, signature_bytes,
        mechanism)

    return result





  def logout(self):
    """
    <Purpose>
      Logout from the CKU_USER session
    """

    self.session.logout()





  def close_session(self):
    """
    <Purpose>
      Close the communication session with the token.
    """

    self.session.closeSession()





  def close(self):
    """
    <Purpose>
      To logout and terminate sessions with the HSM completely.
    """

    try:
      self.logout()
      self.close_session()
    except PyKCS11.PyKCS11Error as error:
      if error.__str__() == 'CKR_USER_NOT_LOGGED_IN (0x00000101)':
        # When the user is already logged out.
        logger.info(str(error))
        self.close_session()
      else:
        # When the session does not exists.
        logger.info(str(error))
