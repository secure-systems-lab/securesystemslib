"""
<Program Name>
  ecdsa_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  November 22, 2016.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to support ECDSA keys and signatures.  ECDSA is an
  elliptic-curve digital signature algorithm.  It grants a similar level of
  security as RSA, but uses smaller keys.  No subexponential-time algorithm is
  known for the elliptic curve discrete logarithm problem.

  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

  'securesystemslib.ecdsa_keys.py' calls the 'cryptography' library to perform
  all of the ecdsa-related operations.

  The ecdsa-related functions included here are generate(), create_signature()
  and verify_signature().  The 'cryptography' library is used by ecdsa_keys.py
  to perform the actual ECDSA computations, and the functions listed above can
  be viewed as an easy-to-use public interface.
 """

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# 'binascii' required for hexadecimal conversions.  Signatures and
# public/private keys are hexlified.
import binascii

import logging

# Import cryptography modules to support ecdsa keys and signatures.
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends.interfaces import PEMSerializationBackend

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import cryptography.exceptions

# Perform object format-checking and add ability to handle/raise exceptions.
import securesystemslib.formats
import securesystemslib.exceptions

_SUPPORTED_ECDSA_ALGORITHMS = ['ecdsa-sha2-nistp256']

logger = logging.getLogger('securesystemslib_ecdsa_keys')


def generate_public_and_private(algorithm='ecdsa-sha2-nistp256'):
  """
  <Purpose>
    Generate a pair of ECDSA public and private keys with one of the supported,
    external cryptography libraries.  The public and private keys returned
    conform to 'securesystemslib.formats.PEMECDSA_SCHEMA' and
    'securesystemslib.formats.PEMECDSA_SCHEMA', respectively.

    The public ECDSA public key has the PEM format:
    TODO: should we encrypt the private keys returned here?  Should the
    create_signature() accept encrypted keys?

    '-----BEGIN PUBLIC KEY-----

    ...

    '-----END PUBLIC KEY-----'



    The private ECDSA private key has the PEM format:

    '-----BEGIN EC PRIVATE KEY-----

    ...

    -----END EC PRIVATE KEY-----'

    >>> public, private = generate_public_and_private()
    >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
    True
    >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
    True

  <Arguments>
    algorithm:
      A string indicating which algorithm to use for the generation of the
      public and private ECDSA keys.  'ecdsa-sha2-nistp256' is the only
      currently supported ECDSA algorithm, which is supported by OpenSSH and
      specified in RFC 5656 (https://tools.ietf.org/html/rfc5656).

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'algorithm' is improperly
    formatted.

    securesystemslib.exceptions.UnsupportedLibraryError, if a required cryptography
    library unavailable.

  <Side Effects>
    None.

  <Returns>
    A (public, private) tuple that conform to
    'securesystemslib.formats.PEMECDSA_SCHEMA' and
    'securesystemslib.formats.PEMECDSA_SCHEMA', respectively.
  """

  # Does 'algorithm' have the correct format?
  # Verify that 'algorithm' is of the correct type, and that it's one of the
  # supported ECDSA algorithms.  It must conform to
  # 'securesystemslib.formats.ECDSAALGORITHMS_SCHEMA'.  Raise
  # 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.ECDSAALGORITHMS_SCHEMA.check_match(algorithm)

  public_key = None
  private_key = None

  if algorithm == 'ecdsa-sha2-nistp256':
    private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
    public_key = private_key.public_key()

  # The formats ECDSAALGORITHMS_SCHEMA check above should have detected any
  # invalid 'algorithm'.
  else: #pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError('An unsupported'
      ' algorithm was specified: ' + repr(algorithm) + '.\n  Supported'
      ' algorithms: ' + repr(_SUPPORTED_ECDSA_ALGORITHMS))

  private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

  public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

  return public_pem.decode('utf-8'), private_pem.decode('utf-8')





def create_signature(public_key, private_key, data):
  """
  <Purpose>
    Return a (signature, method) tuple.

    >>> algorithm = 'ecdsa-sha2-nistp256'
    >>> public, private = generate_public_and_private(algorithm)
    >>> data = b'The quick brown fox jumps over the lazy dog'
    >>> signature, method = create_signature(public, private, data)
    >>> securesystemslib.formats.ECDSASIGNATURE_SCHEMA.matches(signature)
    True
    >>> method == algorithm
    True

  <Arguments>
    public:
      The ECDSA public key in PEM format.

    private:
      The ECDSA private key in PEM format.

    data:
      Byte data used by create_signature() to generate the signature returned.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if a signature cannot be created.

  <Side Effects>
    None.

  <Returns>
    A signature dictionary conformat to
    'securesystemslib.format.SIGNATURE_SCHEMA'.  ECDSA signatures are XX bytes,
    however, the hexlified signature is stored in the dictionary returned.
  """

  # Do 'public_key' and 'private_key' have the correct format?
  # This check will ensure that the arguments conform to
  # 'securesystemslib.formats.PEMECDSA_SCHEMA'.  Raise
  # 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMECDSA_SCHEMA.check_match(public_key)

  # Is 'private_key' properly formatted?
  securesystemslib.formats.PEMECDSA_SCHEMA.check_match(private_key)

  method = 'ecdsa-sha2-nistp256'

  try:
    private_key = load_pem_private_key(private_key.encode('utf-8'),
      password=None, backend=default_backend())

    signer = private_key.signer(ec.ECDSA(hashes.SHA256()))
    signer.update(data)
    signature = signer.finalize()

  except TypeError as e:
    raise securesystemslib.exceptions.CryptoError('Could not create'
      ' signature: ' + str(e))

  return signature, method





def verify_signature(public_key, method, signature, data):
  """
  <Purpose>
    ...

    >>> algorithm = 'ecdsa-sha2-nistp256'
    >>> public, private = generate_public_and_private(algorithm)
    >>> data = b'The quick brown fox jumps over the lazy dog'
    >>> signature, method = create_signature(public, private, data)
    >>> verify_signature(public, method, signature, data)
    True
    >>> verify_signature(public, method, signature, b'bad data')
    False

  <Arguments>
    public_key:
      The ECDSA public key in PEM format.  The publi key is needed to verify
      'signature'.

    method:
      The signature method used to generate 'signature'.  For example:
      'ecdsa-sha2-nistp256'.

    signature:
      The signature to be verified, which should have been generated by
      the private key associated with 'public_key'.  'data'.

    data:
      Byte data that was used by create_signature() to generate 'signature'.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if any of the arguments are improperly
    formatted.

  <Side Effects>
    None.

  <Returns>
    Boolean, indicating whether the 'signature' of data was generated by
    the private key associated with 'public_key'.
  """

  # Are the arguments properly formatted?
  # If not, raise 'securesystemslib.exceptions.FormatError'.
  securesystemslib.formats.PEMECDSA_SCHEMA.check_match(public_key)
  securesystemslib.formats.NAME_SCHEMA.check_match(method)
  securesystemslib.formats.ECDSASIGNATURE_SCHEMA.check_match(signature)

  # Is 'method' one of the supported ECDSA algorithms?
  if method in _SUPPORTED_ECDSA_ALGORITHMS:
    ecdsa_key = load_pem_public_key(public_key.encode('utf-8'), backend=default_backend())

    if not isinstance(ecdsa_key, ec.EllipticCurvePublicKey):
      raise securesystemslib.exceptions.FormatError('Invalid ECDSA public'
        ' key: ' + repr(public_key))

    else:
      logger.debug('Loaded a valid ECDSA public key.')

    try:
      verifier = ecdsa_key.verifier(signature, ec.ECDSA(hashes.SHA256()))
      verifier.update(data)

    except TypeError as e:
      raise securesystemslib.exceptions.FormatError('Invalid signature or'
        ' data: ' + str(e))

    # verify() raises an 'InvalidSignature' exception if 'signature'
    # is invalid.
    try:
      verifier.verify()
      return True

    except cryptography.exceptions.InvalidSignature:
      return False

  else:
    raise securesystemslib.exceptions.UnknownMethodError('Unsupported signing'
      ' method given: ' + repr(method) + '.  \nSupported'
      ' methods: ' + repr(_SUPPORTED_ECDSA_ALGORITHMS))





def create_ecdsa_public_and_private_from_pem(pem, password=None):
  """
  <Purpose>
    Create public and private ECDSA keys from a private 'pem'.  The public and
    private keys are strings in PEM format:

    public: '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----',
    private: '-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----'}}

    >>> junk, private = generate_public_and_private()
    >>> public, private = create_ecdsa_public_and_private_from_pem(private)
    >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
    True
    >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
    True
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_ecdsa_encrypted_pem(private, passphrase)
    >>> public, private = create_ecdsa_public_and_private_from_pem(encrypted_pem, passphrase)
    >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
    True
    >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
    True

  <Arguments>
    pem:
      A string in PEM format.  The private key is extracted and returned in
      an ecdsakey object.

    password: (optional)
      The password, or passphrase, to decrypt the private part of the ECDSA key
      if it is encrypted.  'password' is not used directly as the encryption
      key, a stronger encryption key is derived from it.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.UnsupportedLibraryError, if any of the cryptography
    libraries specified in 'settings.py' are unsupported or unavailable.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the ECDSA keys and other identifying information.
    Conforms to 'securesystemslib.formats.ECDSAKEY_SCHEMA'.
  """

  # Does 'pem' have the correct format?
  # This check will ensure 'pem' conforms to
  # 'securesystemslib.formats.ECDSARSA_SCHEMA'.
  securesystemslib.formats.PEMECDSA_SCHEMA.check_match(pem)

  if password is not None:
    securesystemslib.formats.PASSWORD_SCHEMA.check_match(password)
    password = password.encode('utf-8')

  else:
    logger.debug('The password/passphrase is unset.  The PEM is expected'
      ' to be unencrypted.')

  public = None
  private = None

  # Generate the public and private ECDSA keys.  The pyca/cryptography library
  # performs the actual import operation.
  try:
    private = load_pem_private_key(pem.encode('utf-8'), password=password,
      backend=default_backend())

  except (ValueError, cryptography.exceptions.UnsupportedAlgorithm) as e:
    raise securesystemslib.exceptions.CryptoError('Could not import private'
      ' PEM.\n' + str(e))

  public = private.public_key()

  # Serialize public and private keys to PEM format.
  private = private.private_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

  public = public.public_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

  return public.decode('utf-8'), private.decode('utf-8')





def create_ecdsa_encrypted_pem(private_pem, passphrase):
  """
  <Purpose>
    Return a string in PEM format, where the private part of the ECDSA key is
    encrypted. The private part of the ECDSA key is encrypted as done by
    pyca/cryptography: "Encrypt using the best available encryption for a given
    key's backend. This is a curated encryption choice and the algorithm may
    change over time."

    >>> junk, private = generate_public_and_private()
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_ecdsa_encrypted_pem(private, passphrase)
    >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(encrypted_pem)
    True

  <Arguments>
    private_pem:
    The private ECDSA key string in PEM format.

    passphrase:
    The passphrase, or password, to encrypt the private part of the ECDSA
    key. 'passphrase' is not used directly as the encryption key, a stronger
    encryption key is derived from it.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

      securesystemslib.exceptions.CryptoError, if an ECDSA key in encrypted PEM
      format cannot be created.

  <Side Effects>
    None.

  <Returns>
    A string in PEM format, where the private RSA portion is encrypted.
    Conforms to 'securesystemslib.formats.PEMECDSA_SCHEMA'.
  """

  # Does 'private_key' have the correct format?
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PEMRSA_SCHEMA.check_match(private_pem)

  # Does 'passphrase' have the correct format?
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(passphrase)

  encrypted_pem = None

  private = load_pem_private_key(private_pem.encode('utf-8'), password=None,
    backend=default_backend())

  encrypted_private_pem = \
    private.private_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8')))

  return encrypted_private_pem



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'ecdsa_keys.py' as a standalone module.
  # python -B ecdsa_keys.py
  import doctest
  doctest.testmod()
