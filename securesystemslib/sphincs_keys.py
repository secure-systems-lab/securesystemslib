"""
<Program Name>
  sphincs_keys.py

<Author>
  Ruben Gonzalez <mail@ruben-gonzalez.de>

<Started>
  Otober 12, 2022.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to include SPHINCS+ post-quantum signature support.
 """
# 'os' required to generate OS-specific randomness (os.urandom) suitable for
# cryptographic use.
# http://docs.python.org/2/library/os.html#miscellaneous-functions
import os

from securesystemslib import exceptions, formats

SPX_AVAIL = True
NO_SPX_MSG = "spinhcs+ key support requires the pyspx library"

try:
    from pyspx import shake_128s
except ImportError:
    SPX_AVAIL = False

_SHAKE_SEED_LEN = 48


def generate_public_and_private():
    """Generates spx public and private key.

    Returns:
        tuple: Containing the (public, private) keys.
    Raises:
        UnsupportedLibraryError: In case pyspx is not available.
    """
    if not SPX_AVAIL:
        raise exceptions.UnsupportedLibraryError(NO_SPX_MSG)
    seed = os.urandom(_SHAKE_SEED_LEN)
    public, private = shake_128s.generate_keypair(seed)
    return public, private


def create_signature(public_key, private_key, data, scheme):
    """Signs data with the private key.
    Arguments:
          public_key (bytes): The public key. Not used so far.
          private_key (bytes): The private key.
          data (bytes): The data to be signed.
          scheme (str): The name of the scheme as defined in formats.py.
    Returns:
        tuple: Containing the values (signature, scheme).
    Raises:
        UnsupportedLibraryError: In case pyspx is not available.
    """
    if not SPX_AVAIL:
        raise exceptions.UnsupportedLibraryError(NO_SPX_MSG)
    formats.SPHINCSPUBLIC_SCHEMA.check_match(public_key)
    formats.SPHINCSPRIVATE_SCHEMA.check_match(private_key)
    formats.SPHINCS_SIG_SCHEMA.check_match(scheme)

    signature = shake_128s.sign(data, private_key)

    return signature, scheme


def verify_signature(public_key, scheme, signature, data):
    """Verify a signature using the public key.
    Arguments:
          public_key (bytes): The public key used for verification.
          scheme (str): The name of the scheme as defined in formats.py.
          signature (bytes): The sphincs+ signature as generated with create_signature.
          data (bytes): The data that was signed.
    Returns:
        bool: True if the signature was valid, False otherwise.
    Raises:
        UnsupportedLibraryError: In case pyspx is not available.
    """
    if not SPX_AVAIL:
        raise exceptions.UnsupportedLibraryError(NO_SPX_MSG)
    formats.SPHINCSPUBLIC_SCHEMA.check_match(public_key)

    # Is 'scheme' properly formatted?
    formats.SPHINCS_SIG_SCHEMA.check_match(scheme)

    # Is 'signature' properly formatted?
    formats.SPHINCSSIGNATURE_SCHEMA.check_match(signature)

    return shake_128s.verify(data, signature, public_key)
