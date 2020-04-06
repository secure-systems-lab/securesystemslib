#!/usr/bin/env python
"""
<Program Name>
  hsm.py

<Started>
  June 19, 2019.

<Author>
  Tanishq Jasoria <jasoriatanishq@gmail.com>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Purpose>
  The goal of this module is to support hardware security modules through
  the PKCS#11 standard.

  This module uses PyKCS11, a python wrapper (SWIG) for PKCS#11 modules
  to communicate with the cryptographic tokens


TODO: error handling
  - PKCS11 seems brittle: Make sure that there are no state problems (e.g.
    openSession on a slot requires prior call to get slots, etc.) and we always
    get back the values we expect, i.e. handle hsm return invalid/incomplete
    data (e.g. getAttributeValue), and fail gracefully if not
    hint: check CKR_<RETURN VALUE TYPE> constants
  - revise error messages and exception taxonomy
  - Add HSM_INFO_SCHEMA and HSM_INFO_SCHEMA, HSM_KEY_INFO_SCHEMA,
    HSM_KEY_ID_SCHEMA and check_match on them.

TODO: docs
  - flesh out function docstrings and add code comments
  - add links to PKCS11 specs
  - add installation and usage docs, e.g. replace
    test_hsm.TestECDSAOnLUKPUEHsYubiKey with some instructions for YubiKey in
    README.md

TODO: testing
  - check coverage
  - trigger edge cases (see error handling above)

TODO: sort out inline TODO notes

"""
import six
import logging
import binascii

if not six.PY2:
  import asn1crypto.keys

import securesystemslib.formats
import securesystemslib.hash
from securesystemslib.exceptions import UnsupportedLibraryError

logger = logging.getLogger(__name__)

#Boolean to indicate if optional pyca cryptography library is available
CRYPTO = True
# Module global to hold an instance of PyKCS11.PyKCS11Lib. If it remains 'None'
# it means that the PyKCS11 library is not available.
PKCS11 = None
# Boolean to indicate if we have loaded the required dynamic library on the
# 'PKCS11' instance. (Note: It would would nicer to get this information from
# the object, but there doesn't seem to be a straight-forward way to to this.)
PKCS11_DYN_LIB = False

# TODO: write proper message / usage instructions for load
NO_CRYPTO_MSG = "This operations requires cryptography."
NO_PKCS11_PY_LIB_MSG = "HSM support requires PyKCS11 library"
NO_PKCS11_DYN_LIB_MSG = "HSM support requires PKCS11 shared object"

try:
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives import serialization, asymmetric

except ImportError: # pragma: no cover
  CRYPTO = False

try:
  # Import python wrapper for PKCS#11 to communicate with the tokens
  import PyKCS11
  PKCS11 = PyKCS11.PyKCS11Lib()

except ImportError as e: # pragma: no cover
  # Missing PyKCS11 python library. PKCS11 must remain 'None'.
  logger.debug(e)

ECDSA_SHA2_NISTP256 = "ecdsa-sha2-nistp256"
ECDSA_SHA2_NISTP384 = "ecdsa-sha2-nistp384"

if PKCS11 is not None and CRYPTO:
  SIGNING_SCHEMES = {
    ECDSA_SHA2_NISTP256: {
      "mechanism": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256),
      "curve": asymmetric.ec.SECP256R1
      },
    ECDSA_SHA2_NISTP384: {
      "mechanism": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA384),
      "curve": asymmetric.ec.SECP384R1
      }
    }




def load_pkcs11_lib(path=None):
  """
  <Purpose>
    Load PKCS#11 dynamic library on 'PKCS11' instance (module global).

  <Arguments>
    path: (optional)
            Path to the PKCS#11 dynamic library shared object. If not passed
            the PyKCS11 will read the 'PYKCS11LIB' environment variable.

  <Exceptions>
    UnsupportedLibraryError if the PyKCS11 library is not available.

    PyKCS11.PyKCS11Error if the PKCS11 dynamic library cannot be loaded.

     FormatError if the argument is malformed.

  <Side Effects>
    Loads the PKCS#11 shared object on the PKCS11 module global.
    Set module global PKCS11_DYN_LIB to True if loading was successful and to
    False if it failed.

  """
  if PKCS11 is None: # pragma: no cover
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  global PKCS11_DYN_LIB

  try:
     # If path is not passed PyKCS11 consults the PYKCS11LIB env var
    if path is None:
      PKCS11.load()

    else:
      securesystemslib.formats.PATH_SCHEMA.check_match(path)
      PKCS11.load(path)

    PKCS11_DYN_LIB = True

  except PyKCS11.PyKCS11Error as e:
    PKCS11_DYN_LIB = False
    raise



def get_hsms():
  """
  <Purpose>
    Iterate over HSM slots and return list with info for each HSM.

  <Exceptions>
    UnsupportedLibraryError if the PyKCS11 library is not available or the
    PKCS#11 shared object could not be loaded.

  <Return>
    List of HSM info dictionaries conforming to HSM_INFO_SCHEMA.

  """
  if PKCS11 is None: # pragma: no cover
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  hsm_info_list = []
  for slot in PKCS11.getSlotList():
    slot_info = PKCS11.getSlotInfo(slot)
    hsm_info_list.append({
        "slot_id": slot,
        "slot_description": slot_info.slotDescription.strip(),
        "manufacturer_id": slot_info.manufacturerID.strip(),
        "hardware_version": slot_info.hardwareVersion,
        "firmware_version": slot_info.firmwareVersion,
        "flags": slot_info.flags2text(),
      })

  return hsm_info_list



def get_keys_on_hsm(hsm_info, user_pin=None):
  """
  <Purpose>
    Get handles of public and private keys stored on the HSM. To get private
    key handles this function requires a user_pin.

  <Argument>
    hsm_info:
            A dictionary to identify the HSM conforming to HSM_INFO_SCHEMA.

    user_pin:
            A string to log into the HSM. Only required for private key infos.

  <Exceptions>
    UnsupportedLibraryError if the PyKCS11 library is not available or the
    PKCS#11 shared object could not be loaded.

    FormatError if arguments are malformed.

  <Returns>
    List of dictionaries conforming to HSM_KEY_INFO_SCHEMA.

  """
  if PKCS11 is None: # pragma: no cover
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  # TODO: securesystemslib.formats.HSM_INFO_SCHEMA.check_match(hsm_info)

  if user_pin:
    securesystemslib.formats.PASSWORD_SCHEMA.check_match(user_pin)

  # Create HSM session and, if pin is passed, login to access private objects
  session = _setup_session(hsm_info, user_pin)

  hsm_key_info_list = []
  # Iterate over public and private (if logged in) keys and construct key info
  for obj in session.findObjects(
      [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]) + session.findObjects(
      [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)]):

    # TODO: Add more human readable info
    hsm_key_info_list.append({
        "key_id": session.getAttributeValue(obj, [PyKCS11.CKA_ID])[0],
        "label": session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])[0]
      })

  # Logout, if logged in, and close session
  _teardown_session(session)

  return hsm_key_info_list



def export_pubkey(hsm_info, hsm_key_id, scheme, sslib_key_id):
  """
  <Purpose>
    Export a public key identified by the passed hsm_info and key_info
    into a securesystemslib-like format.

  <Arguments>
    hsm_info:
            A dictionary to identify the HSM conforming to HSM_INFO_SCHEMA.

    hsm_key_id:
            A tuple to identify a public key on the HSM conforming to
            HSM_KEY_ID_SCHEMA.

    scheme:
          A signing scheme conforming to ECDSA_SCHEME_SCHEMA.

    sslib_key_id:
            The keyid to be assigned to the returned public key dictionary
            'keyid' field.

            NOTE: The HSM library currently does not generate keyids on public
            key export or signature creation, as other securesystemslib modules
            would do, as keyid flexibility is under discussion. Instead callers
            can assign any keyid they want.

  <Exceptions>
    UnsupportedLibraryError if the PyKCS11 or cryptography libraries are not
    available or the PKCS#11 shared object could not be loaded.

    FormatError if arguments are malformed.

  <Returns>
    An ECDSA public key dictionary conforming to PUBLIC_KEY_SCHEMA.

  """
  if PKCS11 is None: # pragma: no cover
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not CRYPTO: # pragma: no cover
    raise UnsupportedLibraryError(NO_CRYPTO_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  #TODO: securesystemslib.formats.HSM_INFO_SCHEMA.check_match(hsm_info)
  #TODO: securesystemslib.formats.HSM_KEY_ID_SCHEMA.check_match(hsm_key_id)
  securesystemslib.formats.ECDSA_SCHEME_SCHEMA.check_match(scheme)
  securesystemslib.formats.KEYID_SCHEMA.check_match(sslib_key_id)

  scheme_info = SIGNING_SCHEMES[scheme]

  session = _setup_session(hsm_info)

  key_objects = session.findObjects([
      (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
      (PyKCS11.CKA_ID, hsm_key_id)])

  _for_key_on_hsm = "for keyid '{}' on hsm '{}'".format(
      hsm_key_id, hsm_info["slot_id"])

  # TODO: is ValueError the right exception here?
  if len(key_objects) < 1:
    raise ValueError("cannot find key {}".format(_for_key_on_hsm))

  if len(key_objects) > 1:
    raise ValueError("found multiple keys {}".format(_for_key_on_hsm))

  key_object = key_objects.pop()
  hsm_key_type = session.getAttributeValue(
      key_object, [PyKCS11.CKA_KEY_TYPE])[0]

  if hsm_key_type != PyKCS11.CKK_EC:
    raise ValueError("passed scheme '{}' requires a key of type '{}', "
        "found key of type '{}' {}".format(
        scheme,
        PyKCS11.CKK[PyKCS11.CKK_EC],
        PyKCS11.CKK.get(hsm_key_type, None),
        _for_key_on_hsm))

  params, point = session.getAttributeValue(key_object, [
      PyKCS11.CKA_EC_PARAMS,
      PyKCS11.CKA_EC_POINT
    ])

  keytype = scheme
  ec_param_obj = asn1crypto.keys.ECDomainParameters.load(bytes(params))
  if ec_param_obj.chosen.native != scheme_info["curve"].name:
    raise ValueError("passed scheme '{}' requires key on curve '{}', found "
        "key on curve '{}' {}".format(
        scheme,
        scheme_info["curve"].name,
        ec_param_obj.chosen.native,
        _for_key_on_hsm))

  ec_point_obj = asn1crypto.keys.ECPoint().load(bytes(point))
  crypto_public_key = asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
      scheme_info["curve"](), ec_point_obj.native)
  public_key_value = crypto_public_key.public_bytes(
      serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo).decode()

  # NOTE: securesysmslib.formats.ECDSAKEY_SCHEMA uses the same string for
  # "keytype" and "scheme".
  return {
      "keyid": sslib_key_id,
      "keytype": scheme,
      "scheme": scheme,
      "keyval": {
        "public": public_key_value
      }
    }



def create_signature(hsm_info, hsm_key_id, user_pin, data, scheme,
    sslib_key_id):
  """
  <Purpose>
    Sign passed data on HSM.

  <Arguments>
    hsm_info:
            A dictionary to identify the HSM conforming to HSM_INFO_SCHEMA.

    hsm_key_id:
            A tuple to identify a private key on the HSM conforming to
            HSM_KEY_ID_SCHEMA.

    user_pin:
            A string to log into the HSM.

    data:
        The bytes to sign.

    scheme:
          A signing scheme conforming to ECDSA_SCHEME_SCHEMA.

    sslib_key_id:
            The keyid to be assigned to the returned public key dictionary
            'keyid' field.

  <Exceptions>
    UnsupportedLibraryError if the PyKCS11 or cryptography libraries are not
    available or the PKCS#11 shared object could not be loaded.

    FormatError if arguments are malformed.

  <Returns>
    A signature dictionary conforming to SIGNATURE_SCHEMA.

  """
  if PKCS11 is None: # pragma: no cover
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not CRYPTO: # pragma: no cover
    raise UnsupportedLibraryError(NO_CRYPTO_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  #TODO: securesystemslib.formats.HSM_INFO_SCHEMA.check_match(hsm_info)
  #TODO: securesystemslib.formats.HSM_KEY_ID_SCHEMA.check_match(hsm_key_id)
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(user_pin)
  securesystemslib.formats.DATA_SCHEMA.check_match(data)
  securesystemslib.formats.ECDSA_SCHEME_SCHEMA.check_match(scheme)
  securesystemslib.formats.KEYID_SCHEMA.check_match(sslib_key_id)

  # Create a session and login to generate signature using keys stored in hsm
  session = _setup_session(hsm_info, user_pin)

  # TODO: DRY with export_pubkey and add proper error handling

  key_objects = session.findObjects([
      (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
      (PyKCS11.CKA_ID,  hsm_key_id)])

  key_object = key_objects.pop()
  key_type = session.getAttributeValue(key_object, [PyKCS11.CKA_KEY_TYPE])[0]

  # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
  signature = session.sign(
      key_object, data, SIGNING_SCHEMES[scheme]["mechanism"])

  _teardown_session(session)

  # The PKCS11 signature octets correspond to the concatenation of the ECDSA
  # values r and s, both represented as an octet string of equal length of at
  # most nLen with the most significant byte first (i.e. big endian)
  # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
  r_s_len = int(len(signature) / 2)
  r = int.from_bytes(signature[:r_s_len], byteorder="big")
  s = int.from_bytes(signature[r_s_len:], byteorder="big")

  # Create an ASN.1 encoded Dss-Sig-Value to be used with pyca/cryptography
  dss_sig_value = binascii.hexlify(
      asymmetric.utils.encode_dss_signature(r, s)).decode("ascii")

  return {
      "keyid": sslib_key_id,
      "sig": dss_sig_value
    }



def _setup_session(hsm_info, user_pin=None, user_type=None):
  """Create new hsm session, login if pin is passed and return session object.
  """
  # Don't add PyKCS11.CKU_USER to function signature to make this module
  # importable even if PyKCS11 is not installed
  if user_type is None:
    user_type = PyKCS11.CKU_USER

  try:
    # TODO: parametrize RW (probably only needed for tests)
    session = PKCS11.openSession(
        hsm_info["slot_id"],
        PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    if user_pin is not None:
      session.login(user_pin, user_type)

  except PyKCS11.PyKCS11Error as e:
    if PyKCS11.CKR[e.value] == "CKR_USER_ALREADY_LOGGED_IN":
      logger.debug(
          "CKU_USER already logged into HSM '{}'".format(hsm_info["slot_id"]))

    else:
      raise

  return session


def _teardown_session(session):
  """Close logout and close session no matter what. """
  for _teardown_func in [session.logout, session.closeSession]:
    try:
      _teardown_func()

    except Exception as e:
      logger.debug(e)
