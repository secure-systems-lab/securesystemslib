#!/usr/bin/env python

"""
<Program Name>
  settings.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  December 7, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Store all crypto-related settings used by securesystemslib.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals


# Set a directory that should be used for all temporary files. If this
# is None, then the system default will be used. The system default
# will also be used if a directory path set here is invalid or
# unusable.
temporary_directory = None

# The current "good enough" number of PBKDF2 passphrase iterations.
# We recommend that important keys, such as root, be kept offline.
# 'toto.settings.PBKDF2_ITERATIONS' should increase as CPU speeds increase, set here
# at 100,000 iterations by default (in 2013).  The repository maintainer may opt
# to modify the default setting according to their security needs and
# computational restrictions.  A strong user password is still important.
# Modifying the number of iterations will result in a new derived key+PBDKF2
# combination if the key is loaded and re-saved, overriding any previous
# iteration setting used in the old '<keyid>' key file.
# https://en.wikipedia.org/wiki/PBKDF2
PBKDF2_ITERATIONS = 100000

# Supported cryptography libraries that can be used to generate and verify RSA
# keys and signatures:  ['pycrypto', 'pyca-cryptography']
RSA_CRYPTO_LIBRARY = 'pyca-cryptography'

# Supported Ed25519 cryptography libraries: ['pynacl', 'ed25519']
ED25519_CRYPTO_LIBRARY = 'ed25519'

# Supported ECDSA cryptography libraries: ['pyca-cryptography']
ECDSA_CRYPTO_LIBRARY = 'pyca-cryptography'

# General purpose cryptography. Algorithms and functions that fall under
# general purpose include AES, PBKDF2, cryptographically strong random number
# generators, and cryptographic hash functions.  The majority of the general
# cryptography is needed by the repository and developer tools.
# RSA_CRYPTO_LIBRARY and ED25519_CRYPTO_LIBRARY are needed on the client side
# of the software updater.
# Supported libraries for general-purpose cryptography:  ['pycrypto',
# 'pyca-cryptography']
GENERAL_CRYPTO_LIBRARY = 'pyca-cryptography'

# The algorithm(s) in HASH_ALGORITHMS are used to generate key IDs.
HASH_ALGORITHMS = ['sha256', 'sha512']
