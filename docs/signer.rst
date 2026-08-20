Signer API
==========

.. currentmodule:: securesystemslib.signer

The signer module provides a simple and unified cryptographic signing and signature verification API designed to work consistently regardless of the underlying signing technology. This is achieved with abstract interfaces backed by multiple implementations:

* ``Signer.sign``
* ``Key.verify_signature``

The interfaces can be implemented using arbitrary asymmetric signing technology.
The ``Key`` class is also a container class for public key data. The ``Signer``
class, on the other hand, treats the private key as implementation detail. This
means that one specific signer may indeed contain the private key, but another
calls a remote cloud KMS, or a local hardware token for signing.

In addition to sign and verify interface methods, the signer API provides
generic *load* methods:

* ``Signer.from_priv_key_uri`` -  Loads any specific signer from a URI. The
  specific signer implementation itself is responsible for the URI format and
  resolution. To become discoverable, signers and their URI schemes are
  registered in the ``SIGNER_FOR_URI_SCHEME`` lookup table.

* ``Key.from_dict`` - Loads any specific key from a serialized format. The
  specific key implementation is responsible for the public key format and
  deserialization. To become discoverable, key type and signing scheme --
  required fields in any public key -- are registered in the
  ``KEY_FOR_TYPE_AND_SCHEME`` lookup table.

An application can use these same methods to uniformly load any signer or public
key, regardless of the specific implementation. Many signers and keys are
already included in the signer API. And an application can also create and
register its own.


Usage
-----
The signer API is designed around a 4-step lifecycle.

Crucially, **steps 1 and 2 are one-time setup operations** specific to the
chosen signing technology (e.g. a hardware token or a Cloud KMS).

In contrast, **steps 3 and 4 are completely technology-agnostic**: the exact
same signing and verification code works for all signers and public keys.

1. **Generate key pair** *(technology-specific, one-time)*

   Typically done out-of-band using tooling specific to the signing technology
   (for example, generating a key on a Yubikey with Yubico Authenticator,
   or creating a signing key via a Cloud KMS console / CLI).

2. **Configure public key and signer details** *(signer-specific, one-time)*

   Signer implementations provide an ``import_()`` class method to read the
   public key and construct the corresponding private key URI required to access
   the signer. Both the private key URI and the public key should be stored for
   later use.

3. **Sign** *(generic, repeatable)*

   Load any signer uniformly using :meth:`Signer.from_priv_key_uri` with the
   stored private key URI and the public key. Signers that require user secrets
   (such as an HSM PIN or passphrase) accept an optional
   :data:`SecretsHandler` callback.

4. **Verify** *(generic, repeatable)*

   Deserialize the public key with :meth:`Key.from_dict` and call
   :meth:`Key.verify_signature`. The verifying application does not need to
   know where or how the signature was created.


Example
~~~~~~~

The following example illustrates the full lifecycle using :class:`HSMSigner`
(a PKCS#11 hardware token such as a YubiKey):

.. code-block:: python

    # --- Steps 1 & 2: Technology-specific one-time setup ---

    # Step 1 (out-of-band): Generate key pair on the hardware token (e.g.
    # using Yubico Authenticator)

    # Step 2: Import public key and private key URI from the hardware token
    from securesystemslib.signer import HSMSigner

    uri, public_key = HSMSigner.import_()
    # Save the URI string and serialized public key for later use
    # uri -> "hsm:2?label=YubiKey+PIV+%2315835999"
    public_key_dict = public_key.to_dict()


    # --- Steps 3 & 4: technology-agnostic signing and verification ---
    # The code below works identically for ANY signer
    from getpass import getpass
    from securesystemslib.signer import Key, Signer

    # Step 3: Sign using generic Signer interface
    # In the Yubikey case, user may be asked for a PIN
    def pin_handler(secret_name: str) -> str:
        return getpass(f"Enter {secret_name}: ")

    # Load the stored public key and signer
    signer = Signer.from_priv_key_uri(uri, public_key, secrets_handler=pin_handler)
    signature = signer.sign(b"data to sign")

    # Step 4: Verify using generic Key interface
    public_key.verify_signature(signature, b"data to sign")


.. note::

   See `'New Signer API' <https://theupdateframework.github.io/python-tuf/2023/01/24/securesystemslib-signer-api.html>`_ blog post
   for background information.

API documentation
-----------------

.. Autodoc cannot resolve docs for imported globals (sphinx-doc/sphinx#6495)
.. As workaround we reference their original internal definition.
.. autodata:: securesystemslib.signer._signer.SIGNER_FOR_URI_SCHEME
   :no-value:
.. autodata:: securesystemslib.signer._key.KEY_FOR_TYPE_AND_SCHEME
   :no-value:
.. autoclass:: securesystemslib.signer.Signer
.. autoclass:: securesystemslib.signer.Key
.. autoclass:: securesystemslib.signer.Signature

Key type constants
~~~~~~~~~~~~~~~~~~

.. autodata:: securesystemslib.signer._constants.KEY_TYPE_RSA
   :noindex:
.. autodata:: securesystemslib.signer._constants.KEY_TYPE_ECDSA
   :noindex:
.. autodata:: securesystemslib.signer._constants.KEY_TYPE_ED25519
   :noindex:
.. autodata:: securesystemslib.signer._constants.KEY_TYPE_MLDSA
   :noindex:

Signing scheme constants
~~~~~~~~~~~~~~~~~~~~~~~~

.. autodata:: securesystemslib.signer._constants.ECDSA_SHA2_NISTP256
   :noindex:
.. autodata:: securesystemslib.signer._constants.ECDSA_SHA2_NISTP384
   :noindex:
.. autodata:: securesystemslib.signer._constants.ECDSA_SHA2_NISTP521
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSASSA_PSS_SHA224
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSASSA_PSS_SHA256
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSASSA_PSS_SHA384
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSASSA_PSS_SHA512
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSA_PKCS1V15_SHA224
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSA_PKCS1V15_SHA256
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSA_PKCS1V15_SHA384
   :noindex:
.. autodata:: securesystemslib.signer._constants.RSA_PKCS1V15_SHA512
   :noindex:
.. autodata:: securesystemslib.signer._constants.ED25519
   :noindex:
.. autodata:: securesystemslib.signer._constants.MLDSA_44_1
   :noindex:
.. autodata:: securesystemslib.signer._constants.MLDSA_65_1
   :noindex:
.. autodata:: securesystemslib.signer._constants.MLDSA_87_1
   :noindex:



Signer implementations
~~~~~~~~~~~~~~~~~~~~~~

All signers implement the `Signer` interface: only the unique API specific to
each signer is documented below.

.. autoclass:: securesystemslib.signer.CryptoSigner
   :exclude-members: sign, public_key, from_priv_key_uri

.. autoclass:: securesystemslib.signer.AWSSigner
   :members: import_
   :exclude-members: sign, public_key, from_priv_key_uri

.. autoclass:: securesystemslib.signer.AzureSigner
   :members: import_
   :exclude-members: sign, public_key, from_priv_key_uri

.. autoclass:: securesystemslib.signer.GCPSigner
   :members: import_
   :exclude-members: sign, public_key, from_priv_key_uri

.. autoclass:: securesystemslib.signer.HSMSigner
   :members: import_
   :exclude-members: sign, public_key, from_priv_key_uri

.. autoclass:: securesystemslib.signer.TKeySigner
   :members: import_
   :exclude-members: sign, public_key, from_priv_key_uri

.. autoclass:: securesystemslib.signer.VaultSigner
   :members: import_
   :exclude-members: sign, public_key, from_priv_key_uri

.. autoclass:: securesystemslib.signer.SigstoreSigner
   :members: import_, import_via_auth, import_github_actions
   :exclude-members: sign, public_key, from_priv_key_uri

