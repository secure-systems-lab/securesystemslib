# 'os' required to generate OS-specific randomness (os.urandom) suitable for
# cryptographic use.
# http://docs.python.org/2/library/os.html#miscellaneous-functions
import os

from securesystemslib import exceptions
from securesystemslib import formats

_SPX_AVAIL = True
NO_SPX_MSG = "spinhcs+ key support requires the pyspx library"

try:
    from pyspx import shake_128s
except ImportError:
    _SPX_AVAIL = False

_SHAKE_SEED_LEN = 48


def generate_public_and_private():
    if not _SPX_AVAIL:
        raise exceptions.UnsupportedLibraryError(NO_SPX_MSG)
    seed = os.urandom(_SHAKE_SEED_LEN)
    public, private = shake_128s.generate_keypair(seed)
    return public, private


def create_signature(public_key, private_key, data, scheme):
    if not _SPX_AVAIL:
        raise exceptions.UnsupportedLibraryError(NO_SPX_MSG)
    formats.SPHINCSPUBLIC_SCHEMA.check_match(public_key)
    formats.SPHINCSPRIVATE_SCHEMA.check_match(private_key)
    formats.SPHINCS_SIG_SCHEMA.check_match(scheme)

    signature = shake_128s.sign(data, private_key)

    return signature, scheme


def verify_signature(public_key, scheme, signature, data):
    if not _SPX_AVAIL:
        raise exceptions.UnsupportedLibraryError(NO_SPX_MSG)
    formats.SPHINCSPUBLIC_SCHEMA.check_match(public_key)

    # Is 'scheme' properly formatted?
    formats.SPHINCS_SIG_SCHEMA.check_match(scheme)

    # Is 'signature' properly formatted?
    formats.SPHINCSSIGNATURE_SCHEMA.check_match(signature)

    return shake_128s.verify(data, signature, public_key)


if __name__ == '__main__':
    # The interactive sessions of the documentation strings can
    # be tested by running 'ed25519_keys.py' as a standalone module.
    # python -B ed25519_keys.py
    import doctest
    doctest.testmod()
