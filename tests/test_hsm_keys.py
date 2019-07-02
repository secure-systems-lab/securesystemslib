#!/usr/bin/env python

"""
<Program Name>
  test_hsm_keys.py

<Author>
  Tansihq Jasoria

<Purpose>
  Test cases for hsm_keys.py module
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
import securesystemslib.hsm_keys
from securesystemslib.settings import PKCS11LIB

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate

# To initialize SoftHSM for testing purposes!
import PyKCS11
# Library to interact with SoftHSM.
PKCS11LIB = '/usr/local/lib/softhsm/libsofthsm2.so'

logger = logging.getLogger('securesystemslib_test_hsm_keys')

HSM = securesystemslib.hsm_keys

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
    HSM.load_library(PKCS11LIB)



  def test_load_HSMs(self):

    available_HSM = HSM.load_HSMs()

    self.assertIsInstance(available_HSM, list)



  def test_load_private_keys(self):

    available_HSM = HSM.load_HSMs()[0]

    private_keys = HSM.load_private_keys(available_HSM, _USER_PIN)
    self.assertIsInstance(private_keys, list)



  def test_create_signature(self):

    available_HSM = HSM.load_HSMs()[0]
    private_key = HSM.load_private_keys(available_HSM, _USER_PIN)[0]

    signature = HSM.create_signature(DATA, private_key)

    self.assertIsInstance(signature, str)



  def test_load_public_keys(self):

    available_HSM = HSM.load_HSMs()[0]

    public_keys = HSM.load_public_keys(available_HSM)
    self.assertIsInstance(public_keys, list)



  def test_export_pblic_key_PEM(self):

    available_HSM = HSM.load_HSMs()[0]
    public_key = HSM.load_public_keys(available_HSM)[0]

    try:
      public_key_PEM = HSM.export_public_key_PEM(public_key)
    except:
      logger.debug('The public key object does not contain the DER encoded value'
                   'It needs to be calculated from the Modulus and Exponent.'
                   'But this functionality is not yet available!')
    


  def test_verify_signature(self):

    available_HSM = HSM.load_HSMs()[0]
    public_key = HSM.load_public_keys(available_HSM)[0]
    private_key = HSM.load_private_keys(available_HSM, _USER_PIN)[0]
    signature = HSM.create_signature(DATA, private_key)

    self.assertTrue(HSM.verify_signature(DATA,
        public_key, signature))

    self.assertTrue(HSM.verify_signature(DATA_COMPROMISED,
        public_key, signature))



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()

