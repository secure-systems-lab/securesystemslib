Secure Systems Library
----------------------

.. image:: https://travis-ci.org/secure-systems-lab/securesystemslib.svg?branch=master
   :target: https://travis-ci.org/secure-systems-lab/securesystemslib

.. image:: https://coveralls.io/repos/github/secure-systems-lab/securesystemslib/badge.svg?branch=master
   :target: https://coveralls.io/github/secure-systems-lab/securesystemslib?branch=master

A library that provides cryptographic and general-purpose functions for Secure
Systems Lab projects at NYU.  The routines are general enough to be usable by other
projects.

Overview
++++++++

The secure systems library (securesystemslib) supports public-key and
general-purpose cryptography, such as `ECDSA
<https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>`_,
`Ed25519 <http://ed25519.cr.yp.to/>`_, `RSA
<https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29>`_, SHA256, SHA512, etc.
Cryptography operations are performed via configurable cryptography
libraries (e.g., `cryptography <https://cryptography.io/en/latest/>`_ and
`PyNaCl <https://github.com/pyca/pynacl>`_).  Users may choose from
cryptography library options for supported algorithms by modifying the library's
corresponding entries in settings.py.

The cryptography library may be used to generate keys and signatures with the
ECDSA and RSA algorithms, and perform general-purpose cryptography such as
encrypting keys.  The `PyCrypto <https://www.dlitz.net/software/pycrypto/>`_
library may be selected to generate RSA keys and `RSA-PSS
<https://en.wikipedia.org/wiki/RSA-PSS>`_ signatures.  If generation of Ed25519
signatures is needed, the PyNaCl library setting should be enabled.  PyNaCl is
a Python binding to the Networking and Cryptography Library.  For key storage,
RSA keys may be stored in PEM or JSON format, and Ed25519 keys in JSON format.
Generating, importing, and loading cryptographic key files can be done with
functions available in securesystemslib.

Installation
++++++++++++

::

    $ pip install securesystemslib


Create RSA Keys
~~~~~~~~~~~~~~~

Note:  In the instructions below, lines that start with *>>>* denote commands
that should be entered by the reader, *#* begins the start of a comment, and
text without prepended symbols is the output of a command.

::

    >>> from securesystemslib.interface import *

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

1.  rsa_key1
2.  rsa_key1.pub
3.  rsa_key2
4.  rsa_key2.pub

Import RSA Keys
~~~~~~~~~~~~~~~

::

    # Continuing from the previous section . . .

    # Import an existing public key.
    >>> public_rsa_key1 = import_rsa_publickey_from_file("rsa_key1.pub")

    # Import an existing private key.  Importing a private key requires a
    # password, whereas importing a public key does not.
    >>> private_rsa_key1 = import_rsa_privatekey_from_file("rsa_key1")
    Enter a password for the encrypted RSA key:

**import_rsa_privatekey_from_file()** raises a
*securesystemslib.exceptions.CryptoError* exception if the key / password is
invalid:

::

    securesystemslib.exceptions.CryptoError: RSA (public, private) tuple cannot
    be generated from the encrypted PEM string: Bad decrypt. Incorrect password?

Note: The specific message provided by the exception might differ depending on
which cryptography library is used.

Create and Import Ed25519 Keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    # Continuing from the previous section . . .

    # Generate and write an Ed25519 key pair.  The private key is saved
    # encrypted.  A 'password' argument may be supplied, otherwise a prompt is
    # presented.
    >>> generate_and_write_ed25519_keypair('ed25519_key')
    Enter a password for the Ed25519 key:
    Confirm:

    # Import the Ed25519 public key just created . . .
    >>> public_ed25519_key = import_ed25519_publickey_from_file('ed25519_key.pub')

    # and its corresponding private key.
    >>> private_ed25519_key = import_ed25519_privatekey_from_file('ed25519_key')
    Enter a password for the encrypted Ed25519 key:


Create and Import ECDSA Keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    # continuing from the previous sections . . .

    >>> generate_and_write_ecdsa_keypair('ecdsa_key')
    Enter a password for the ECDSA key:
    Confirm:

    >>> public_ecdsa_key = import_ecdsa_publickey_from_file('ecdsa_key.pub')
    >>> private_ecdsa_key = import_ecdsa_privatekey_from_file('ecdsa_key')
    Enter a password for the encrypted ECDSA key:


Generate ECDSA, Ed25519, and RSA Signatures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note: Users may also access the crypto functions directly to perform
cryptographic operations.

::

    >>> from securesystemslib.keys import *

    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> ed25519_key = generate_ed25519_key()
    >>> signature = create_signature(ed25519_key, data)
    >>> rsa_key = generate_rsa_key(2048)
    >>> signature = create_signature(rsa_key, data)
    >>> ecdsa_key = generate_ecdsa_key()
    >>> signature = create_signature(ecdsa_key, data)


Verify ECDSA, Ed25519, and RSA Signatures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    # Continuing from the previous sections . . .

    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> ed25519_key = generate_ed25519_key()
    >>> signature = create_signature(ed25519_key, data)
    >>> verify_signature(ed25519_key, signature, data)
    True
    >>> verify_signature(ed25519_key, signature, 'bad_data')
    False
    >>> rsa_key = generate_rsa_key()
    >>> signature = create_signature(rsa_key, data)
    >>> verify_signature(rsa_key, signature, data)
    True
    >>> ecdsa_key = generate_ecdsa_key()
    >>> signature = create_signature(ecdsa_key, data)
    >>> verify_signature(ecdsa_key, signature, data)
    True


Miscellaneous functions
~~~~~~~~~~~~~~~~~~~~~~~

**create_rsa_encrypted_pem()**

::

    # Continuing from the previous sections . . .

    >>> rsa_key = generate_rsa_key()
    >>> private = rsa_key['keyval']['private']
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)

**import_rsakey_from_public_pem()**

::

    >>> rsa_key = generate_rsa_key()
    >>> public = rsa_key['keyval']['public']
    >>> rsa_key2 = import_rsakey_from_public_pem(public)


**import_rsakey_from_pem()**

::

    >>> rsa_key = generate_rsa_key()
    >>> public = rsa_key['keyval']['public']
    >>> private = rsa_key['keyval']['private']
    >>> rsa_key2 = import_rsakey_from_pem(public)
    >>> rsa_key3 = import_rsakey_from_pem(private)


**extract_pem()**

::

    >>> rsa_key = generate_rsa_key()
    >>> private_pem = extract_pem(rsakey['keyval']['private'], private_pem=True)
    >>> public_pem = extract_pem(rsakey['keyval']['public'], private_pem=False)


**encrypt_key()**

::

    >>> ed25519_key = generate_ed25519_key()
    >>> password = 'secret'
    >>> encrypted_key = encrypt_key(ed25519_key, password)


**decrypt_key()**

::

    >>> ed25519_key = generate_ed25519_key()
    >>> password = 'secret'
    >>> encrypted_key = encrypt_key(ed25519_key, password)
    >>> decrypted_key = decrypt_key(encrypted_key.encode('utf-8'), password)
    >>> decrypted_key == ed25519_key
    True


**create_rsa_encrypted_pem()**

::

  >>> rsa_key = generate_rsa_key()
  >>> private = rsa_key['keyval']['private']
  >>> passphrase = 'secret'
  >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)


**is_pem_public()**

::

    >>> rsa_key = generate_rsa_key()
    >>> public = rsa_key['keyval']['public']
    >>> private = rsa_key['keyval']['private']
    >>> is_pem_public(public)
    True
    >>> is_pem_public(private)
    False


**is_pem_private()**

::

    >>> rsa_key = generate_rsa_key()
    >>> private = rsa_key['keyval']['private']
    >>> public = rsa_key['keyval']['public']
    >>> is_pem_private(private)
    True
    >>> is_pem_private(public)
    False


**import_ecdsakey_from_private_pem()**

::

    >>> ecdsa_key = generate_ecdsa_key()
    >>> private_pem = ecdsa_key['keyval']['private']
    >>> ecdsa_key2 = import_ecdsakey_from_private_pem(private_pem)


**import_ecdsakey_from_public_pem()**

::

    >>> ecdsa_key = generate_ecdsa_key()
    >>> public = ecdsa_key['keyval']['public']
    >>> ecdsa_key2 = import_ecdsakey_from_public_pem(public)


**import_ecdsakey_from_pem()**

::

    >>> ecdsa_key = generate_ecdsa_key()
    >>> private_pem = ecdsa_key['keyval']['private']
    >>> ecdsa_key2 = import_ecdsakey_from_pem(private_pem)
    >>> public_pem = ecdsa_key['keyval']['public']
    >>> ecdsa_key2 = import_ecdsakey_from_pem(public_pem)

