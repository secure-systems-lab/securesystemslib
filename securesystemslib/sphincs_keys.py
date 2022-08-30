# 'os' required to generate OS-specific randomness (os.urandom) suitable for
# cryptographic use.
# http://docs.python.org/2/library/os.html#miscellaneous-functions
import os

from pyspx import shake_128s

from securesystemslib import exceptions
from securesystemslib import formats

_SHAKE_SEED_LEN = 48


def generate_public_and_private():
    seed = os.urandom(_SHAKE_SEED_LEN)
    public, private = shake_128s.generate_keypair(seed)
    return public, private


def create_signature(public_key, private_key, data, scheme):
    formats.SPHINCSPUBLIC_SCHEMA.check_match(public_key)
    formats.SPHINCSPRIVATE_SCHEMA.check_match(private_key)
    formats.SPHINCS_SIG_SCHEMA.check_match(scheme)

    signature = shake_128s.sign(data, private_key)

    return signature, scheme


def verify_signature(public_key, scheme, signature, data):
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
