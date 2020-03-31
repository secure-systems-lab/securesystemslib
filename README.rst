Secure Systems Library
----------------------

.. image:: https://travis-ci.org/secure-systems-lab/securesystemslib.svg?branch=master
   :target: https://travis-ci.org/secure-systems-lab/securesystemslib

.. image:: https://coveralls.io/repos/github/secure-systems-lab/securesystemslib/badge.svg?branch=master
   :target: https://coveralls.io/github/secure-systems-lab/securesystemslib?branch=master

.. image:: https://api.dependabot.com/badges/status?host=github&repo=secure-systems-lab/securesystemslib
   :target: https://api.dependabot.com/badges/status?host=github&repo=secure-systems-lab/securesystemslib


A library that provides cryptographic and general-purpose functions for Secure
Systems Lab projects at NYU.  The routines are general enough to be usable by
other projects.

Overview
++++++++

securesystemslib supports public-key and general-purpose cryptography, such as
`ECDSA
<https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>`_,
`Ed25519 <http://ed25519.cr.yp.to/>`_, `RSA
<https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29>`_, SHA256, SHA512, etc.
Most of the cryptographic operations are performed by the `cryptography
<https://cryptography.io/en/latest/>`_ and `PyNaCl
<https://github.com/pyca/pynacl>`_ libraries, but verification of Ed25519
signatures can be done in pure Python.

The `cryptography` library is used to generate keys and signatures with the
ECDSA and RSA algorithms, and perform general-purpose cryptography such as
encrypting keys.  The PyNaCl library is used to generate Ed25519 keys and
signatures.  PyNaCl is a Python binding to the Networking and Cryptography
Library.  For key storage, RSA keys may be stored in PEM or JSON format, and
Ed25519 keys in JSON format.  Generating, importing, and loading cryptographic
key files can be done with functions available in securesystemslib.

securesystemslib also provides an interface to the `GNU Privacy Guard (GPG)
<https://gnupg.org/>`_ command line tool, with functions to create RSA and DSA
signatures using private keys in a local gpg keychain; to export the
corresponding public keys in a *pythonic* format; and to verify the created
signatures using the exported keys. The latter does not require the gpg command
line tool to be installed, instead the `cryptography` library is used.

Installation
++++++++++++

::

    $ pip install securesystemslib


The default installation only supports Ed25519 keys and signatures (in pure
Python).  Support for RSA, ECDSA, and E25519 via the `cryptography` and
`PyNaCl` libraries is available by installing the `crypto` and `pynacl` extras:

::

    $ pip install securesystemslib[crypto]
    $ pip install securesystemslib[pynacl]

Usage
++++++++++++

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
    # argument, otherwise a user prompt is presented.  If the password is an
    # empty string, the private key is saved unencrypted.
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

    # Import an existing private key.  If your private key is encrypted,
    # which it should be, you either have to pass a 'password' or enter one
    # on the prompt.
    >>> private_rsa_key1 = import_rsa_privatekey_from_file("rsa_key1", password='some passphrase")
    OR:
    >>> private_rsa_key1 = import_rsa_privatekey_from_file("rsa_key1", prompt=True)
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

    >>> data = b'The quick brown fox jumps over the lazy dog'
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

    >>> data = b'The quick brown fox jumps over the lazy dog'
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




GnuPG interface
~~~~~~~~~~~~~~~

Signature creation and public key export requires installation of the `gpg` or
`gpg2` command line tool, which may be downloaded from
`https://gnupg.org/download <https://gnupg.org/>`_. It is
is also needed to generate the supported RSA or DSA signing keys (see `gpg` man
pages for detailed instructions). Sample keys are available in a test keyring
at `tests/gpg_keyrings/rsa`, which may be passed to the signing and export
functions using the `homedir` argument (if not passed the default keyring is
used).

::

    >>> import securesystemslib.gpg.functions as gpg

    >>> data = b"The quick brown fox jumps over the lazy dog"

    >>> signing_key_id = "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
    >>> keyring = "tests/gpg_keyrings/rsa"

    >>> signature = gpg.create_signature(data, signing_key_id, homedir=keyring)
    >>> public_key = gpg.export_pubkey(non_default_signing_key, homedir=keyring)

    >>> gpg.verify_signature(signature, public_key, data)
    True
    
Testing
++++++++++++

Testing is done with `tox <https://testrun.org/tox/>`_, which can be installed with pip:
::

    $ pip install tox


Secure Systems Library supports multiple versions of Python.
For that reason, the project is tested against multiple virtual environments with different Python versions.
If you run
::

$ tox

this will run all tests creating virtual environments for all python versions described in the *tox.ini* file.

If you want to run the tests against specific python version, for example Python 3.7, you will use:
::

$ tox -e py37
