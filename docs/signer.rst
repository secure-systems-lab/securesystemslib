Signer API
==========

.. currentmodule:: securesystemslib.signer

At its core the signer API defines abstract interfaces to create and verify
cryptographic signatures:

* ``Signer.sign``
* ``Key.verify_signature``

These interfaces can be implemented using arbitrary PKI technology. Many
default implementations are included.

In addition, the API provides generic *load* methods for signers and public
keys:

* ``Signer.from_priv_key_uri`` - to load a signer from a URI
* ``Key.from_dict`` - to load a public key from a serialized format

These methods allow an application to use the exact same code, in order to load
any signer or public key, which implements above interface, independently of
the specific implementation.

For a signer or public key implementation to become discoverable, it needs
to be *registered* in the corresponding lookup table:

* ``SIGNER_FOR_URI_SCHEME``
* ``KEY_FOR_TYPE_AND_SCHEME``

Usage
-----
The signer API is streamlined for the following series of user events,
which may happen on different systems and at different points in time:

1. **Generate** key pair (signature provider -specific)

   Typically, this is done outside of the signer API, e.g. by using a Cloud KMS
   web UI or an HSM console.

2. **Configure** public key and signer access URI

   The public key for a signer must be available in the signing context,
   in order to express its eligibility.

   Some of the existing signer implementations have methods to import a public
   key from a signature provider and to build the related signer access URI.

   The public key can then be serialized with interface methods for use
   in the signing context and in the verification context.

3. **Sign**, given a configured public key and signer access URI

4. **Verify**, given a configured public key

.. warning::
   The API is experimental and may change without warning in versions ``<1.0.0``.

   See `'New Signer API' <https://theupdateframework.github.io/python-tuf/2023/01/24/securesystemslib-signer-api.html>`_ blog post
   for background infos.

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
