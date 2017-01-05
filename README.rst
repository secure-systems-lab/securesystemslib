Secure Systems Library
----------------------

.. image:: https://travis-ci.org/secure-systems-lab/securesystemslib.svg?branch=master
   :target: https://travis-ci.org/secure-systems-lab/securesystemslib

.. image:: https://coveralls.io/repos/github/secure-systems-lab/securesystemslib/badge.svg?branch=master
   :target: https://coveralls.io/github/secure-systems-lab/securesystemslib?branch=master

Cryptography and general-purpose functions for Secure Systems Lab projects
at NYU.


Overview
++++++++

The secure systems library (securesystemslib) supports multiple public-key
algorithms, such as `ECDSA
<https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>`,
`Ed25519 <http://ed25519.cr.yp.to/>`_ and `RSA
<https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29>`_, via multiple
cryptography libraries.  This library is written in Python.  Users may choose
from multiple library options for supported algorithms by modifying their
corresponding entries in [settings.py](settings.py).

The `cryptography
<https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>`_
library may be used to generate keys and signatures with the ECDSA and RSA
algorithms, and perform general-purpose cryptography such as encrypting keys.
The `PyCrypto <https://www.dlitz.net/software/pycrypto/>`_ library may be
selected to generate RSA keys and `RSA-PSS
<https://en.wikipedia.org/wiki/RSA-PSS>`_ signatures.  If generation of Ed25519
signatures is needed, the `PyNaCl <https://github.com/pyca/pynacl>`_ library
setting should be enabled.  PyNaCl is a Python binding to the Networking and
Cryptography Library.  For key storage, RSA keys may be stored in PEM or JSON
format, and Ed25519 keys in JSON format.  Private keys, for both RSA and
Ed25519, are encrypted and passphrase-protected (strengthened with
PBKDF2-HMAC-SHA256.)  Generating, importing, and loading cryptographic key
files can be done with functions available in securesystemslib.

Installation
++++++++++++
::
    $ pip install securesystemslib


Create RSA Keys
~~~~~~~~~~~~~~~

Note:  In the instructions below, lines that start with `>>>` denote commands
that should be entered by the reader, `#` begins the start of a comment, and
text without prepended symbols is the output of a command.

::
    >>> from securesystemslib import *

    # The following function creates an RSA key pair, where the private key is
    # saved to "rsa_key1" and the public key to "rsa_key1.pub" (both saved to
    # the current working directory).  A full directory path may be specified
    # instead of saving keys to the current working directory.  If specified
    # directories do not exist, they will be created.
    >>> generate_and_write_rsa_keypair("rsa_key1", bits=2048, password="password")

    # If the key length is unspecified, it defaults to 3072 bits. A length of
    # less than 2048 bits raises an exception. A password may be supplied as an
    # argument, otherwise a user prompt is presented.
    >>> generate_and_write_rsa_keypair("rsa_key2")
    Enter a password for the RSA key:
    Confirm:


The following four key files should now exist:

1.  **rsa_key1**
2.  **rsa_key1.pub**
3.  **rsa_key2**
4.  **rsa_key2.pub**

Import RSA Keys
~~~~~~~~~~~~~~~

::
    # Continuing from the previous section . . .

    # Import an existing public key.
    >>> public_rsa_key1 =
    >>> import_rsa_publickey_from_file("rsa_key1.pub")

    # Import an existing private key.  Importing a private key requires a
    # password, whereas importing a public key does not.
    >>> private_rsa_key1 = import_rsa_privatekey_from_file("rsa_key1")
    Enter a password for the encrypted RSA key:

**import_rsa_privatekey_from_file()** raises a
`securesystemslib.exceptions.CryptoError` exception if the key / password is
invalid:

::
    securesystemslib.exceptions.CryptoError: RSA (public, private) tuple cannot
    be generated from the encrypted PEM string: Bad decrypt. Incorrect password?

Note: The specific message provided by the exception might differ depending on
which cryptography library is used.

Create and Import Ed25519 Keys
++++++++++++++++++++++++++++++

::
    # Continuing from the previous section . . .

    # Generate and write an Ed25519 key pair.  The private key is saved
    # encrypted.  A 'password' argument may be supplied, otherwise a prompt is
    # presented.
    >>> generate_and_write_ed25519_keypair('ed25519_key')
    Enter a password for the Ed25519 key:
    Confirm:

    # Import the ed25519 public key just created . . .
    >>> public_ed25519_key =
    >>> import_ed25519_publickey_from_file('ed25519_key.pub')

    # and its corresponding private key.
    >>> private_ed25519_key =
    >>> import_ed25519_privatekey_from_file('ed25519_key')
    Enter a password for the encrypted Ed25519 key:


