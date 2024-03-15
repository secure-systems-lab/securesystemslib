Signer API
==========

.. currentmodule:: securesystemslib.signer

At its core the signer API defines abstract interfaces to create and verify
cryptographic signatures:

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
  specific key implementation is responsible public key format and
  deserialization. To become discoverable, key type and signing scheme --
  required fields in any public key -- are registered in the
  ``KEY_FOR_TYPE_AND_SCHEME`` lookup table.

An application can use these same methods to uniformly load any signer or public
key, regardless of the specific implementation. Many signers and keys are
already included in the signer API. And an application can also create and
register its own.


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
