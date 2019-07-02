#!/usr/bin/env python

"""
<Program Name>
  test_hsm.py

<Author>
  Tansihq Jasoria

<Purpose>
  Test cases for hsm.py module
"""


# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import logging

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.hsm

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate

# To initialize SoftHSM for testing purposes!
import PyKCS11
# Library to interact with SoftHSM.
PKCS11LIB = '/usr/local/lib/softhsm/libsofthsm2.so'

logger = logging.getLogger('securesystemslib_test_hsm')

# Encoded data for generating signature
DATA_STR = 'SOME DATA REQUIRING AUTHENTICITY.'
DATA_STR_COMPROMISED = 'This one is also perfectly fine'
DATA = securesystemslib.formats.encode_canonical(DATA_STR).encode('utf-8')
DATA_COMPROMISED = securesystemslib.formats.encode_canonical(
  DATA_STR_COMPROMISED).encode('utf-8')

# Credentials fo the HSM initialization
_USER_PIN = '123456'
_SO_PIN = '654321'
_HSM_LABEL = 'TEST HSM SSL'

KEY_LABEL = 'Test Keys'

# RSA Key Parameters
RSA_KEY_ID = (0x22,)
RSA_BITS = 0x0800
RSA_EXPONENTS = (0x01, 0x00, 0x01)

# ECDSA Key Parameters. EC_PARAMS is generates using
# the elliptic curve 'SECP256R1'
EC_KEY_ID = (0x23,)
EC_PARAMS = b'\x06\x08*\x86H\xce=\x03\x01\x07'





class TestHSM(unittest.TestCase):



  @classmethod
  def setUpClass(cls):

    # To carry out the tests even when the hardware token is not connected,
    # we would be emulating the hardware token using softHSM 2.0.
    # To carry out all the tests, SoftHSM needs to be initialized and
    # RSD, ECDSA key pairs must be generated on the SoftHSM.

    # Initializing the HSM
    soft_pkcs11 = PyKCS11.PyKCS11Lib()
    soft_pkcs11.load(PKCS11LIB)
    available_hsm = soft_pkcs11.getSlotList()
    soft_pkcs11.initToken(available_hsm.pop(), _SO_PIN, _HSM_LABEL)

    # After initializing the SoftHSM, the slot number changes.
    soft_pkcs11.load(PKCS11LIB)
    available_hsm = soft_pkcs11.getSlotList()
    session = soft_pkcs11.openSession(available_hsm[0],
        PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    # Login as a SO User to initialize the pin.
    session.login(_SO_PIN, PyKCS11.CKU_SO)
    session.initPin(_USER_PIN)
    session.logout()
    # Login as admin to generate key pairs.
    session.login(_USER_PIN)

    # Generate RSA Key Pair on the HSM
    RSA_public_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_MODULUS_BITS, RSA_BITS),
        (PyKCS11.CKA_PUBLIC_EXPONENT, RSA_EXPONENTS),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_LABEL, KEY_LABEL),
        (PyKCS11.CKA_ID, RSA_KEY_ID),]
    RSA_private_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_LABEL, KEY_LABEL),
        (PyKCS11.CKA_ID, RSA_KEY_ID),]
    (cls.RSA_public_key, cls.RSA_private_key) = session.generateKeyPair(
      RSA_public_template, RSA_private_template, PyKCS11.MechanismRSAGENERATEKEYPAIR)

    # Generate ECDSA key pair on the HSM
    EC_public_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
        (PyKCS11.CKA_EC_PARAMS, EC_PARAMS),
        (PyKCS11.CKA_LABEL, KEY_LABEL),
        (PyKCS11.CKA_ID, EC_KEY_ID),]
    EC_private_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_LABEL, KEY_LABEL),
        (PyKCS11.CKA_ID, EC_KEY_ID),]
    (cls.EC_public_key, cls.EC_private_key) = session.generateKeyPair(
      EC_public_template, EC_private_template, PyKCS11.MechanismECGENERATEKEYPAIR)

    # Logout and close all sessions
    session.logout()
    session.closeSession()



  @classmethod
  def tearDownClass(cls):
    # TODO: Delete the initialized SoftHSM.
    pass



  def setUp(self):

    self.HSM = securesystemslib.hsm.HSM
    self.SMARTCARD = self.HSM(PKCS11LIB)



  def test_initialization(self):

    self.assertRaises(securesystemslib.exceptions.NotFoundError,
        self.HSM, None)

    # Initialize the library
    self.SMARTCARD = self.HSM(PKCS11LIB)



  def test_get_available_HSMs(self):

    slot_list = self.SMARTCARD.get_available_HSMs()

    self.assertIsInstance(slot_list, list)



  def test_get_HSM_session(self):
    # Use the first HSM in the list
    slot_info = self.SMARTCARD.get_available_HSMs()[0]

    # Test the function to start a session
    self.SMARTCARD.get_HSM_session(slot_info)

    self.assertIsInstance(slot_info, dict)

    # Modify slot_info to point to non existent token.
    slot_info['slot_id'] = 9

    # When the wrong token info is provided by the user
    self.assertRaises(securesystemslib.exceptions.InvalidNameError,
        self.SMARTCARD.get_HSM_session, slot_info)

    # When a wrong input object is provided by the user
    self.assertRaises(securesystemslib.exceptions.InvalidNameError,
        self.SMARTCARD.get_HSM_session, dict())



  def test_close_session(self):
    # Start the session with first HSM on the list
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)

    self.SMARTCARD.close_session()



  def test_close(self):
    # Start the session with first HSM on the list
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)

    self.SMARTCARD.close()

    # Using close() when you are not logged in
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.close()

    # Using close() when session is invalid
    self.SMARTCARD.close()



  def test_login_logout(self):
    # Start the session with first HSM on the list
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)

    # Assuming that the HSM attached have the default PIN!
    self.assertRaises(securesystemslib.exceptions.BadPasswordError,
                      self.SMARTCARD.login, '654321')
    self.SMARTCARD.login(_USER_PIN)

    # Login in again, prints a message on stdout.
    self.SMARTCARD.login(_USER_PIN)

    self.SMARTCARD.logout()
    self.SMARTCARD.close_session()



  def test_get_private_key_objects(self):
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)

    private_key_objects = self.SMARTCARD.get_private_key_objects()

    self.assertIsInstance(private_key_objects, list)

    self.SMARTCARD.close_session()



  def test_get_public_key_objects(self):
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)

    public_key_objects = self.SMARTCARD.get_public_key_objects()

    self.assertIsInstance(public_key_objects, list)

    self.SMARTCARD.close()



  def test_get_public_key_value(self):
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)

    # Assuming the there are already at least key pair stored.
    public_key_object = self.SMARTCARD.get_public_key_objects()[0]
    try:
      public_key = self.SMARTCARD.get_public_key_value(self.RSA_public_key)

      # Supporting operation with only two keys currently
      self.assertTrue(isinstance(public_key, RSAPublicKey) or
                      isinstance(public_key, EllipticCurvePublicKey))
    except:
      logger.debug('The public key object does not contain the DER encoded value'
                   'It needs to be calculated from the Modulus and Exponent.'
                   'But this functionality is not yet available!')

    self.SMARTCARD.close()


  def test_get_x509_objects(self):
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)

    x509_objects = self.SMARTCARD.get_X509_objects()

    self.assertIsInstance(x509_objects, list)
    self.SMARTCARD.close()



  def test_get_x509_value(self):
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)

    # Assuming the there are already a certificate stored
    # on the HSM.
    try:
      x509_objects = self.SMARTCARD.get_X509_objects()
      x509_value = self.SMARTCARD.get_X509_value(x509_objects)
      self.assertIsInstance(x509_value, Certificate)
    except:
      # Will fail, as the certificate file is not genererated on the HSM.
      pass
    self.SMARTCARD.close()



  def test_generate_signature(self):
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)

    # Assuming the there are already at least key pair stored.
    private_key = self.SMARTCARD.get_private_key_objects()[0]

    signature = self.SMARTCARD.generate_signature(DATA, private_key)

    # Returns a HEX encoded string.
    self.assertIsInstance(signature, str)
    self.SMARTCARD.close()



  def test_verify_signature(self):
    # First start a session with the first HSM on the list.
    slot_info = self.SMARTCARD.get_available_HSMs()[0]
    self.SMARTCARD.get_HSM_session(slot_info)
    self.SMARTCARD.login(_USER_PIN)
    # Generate the signature using a private key.
    private_key = self.SMARTCARD.get_private_key_objects()[0]
    signature = self.SMARTCARD.generate_signature(DATA, private_key)
    # Verify the signature with the corresponding public key
    public_key_object = self.SMARTCARD.get_public_key_objects()[0]

    # Verification with data using which the signature was generated.
    self.assertTrue(self.SMARTCARD.verify_signature(
      DATA, signature, public_key_object))

    # Verification with compromised data.
    self.assertFalse(self.SMARTCARD.verify_signature(
      DATA_COMPROMISED, signature, public_key_object))
    self.SMARTCARD.close()





# Run the unit tests.
if __name__ == '__main__':
  unittest.main()

