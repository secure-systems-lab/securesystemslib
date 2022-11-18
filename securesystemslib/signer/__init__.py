"""
The Signer API

This module provides extensible interfaces for public keys and signers:
Some implementations are provided by default but more can be added by users.
"""
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME, Key, SSlibKey
from securesystemslib.signer._signature import GPGSignature, Signature
from securesystemslib.signer._signer import (
    SIGNER_FOR_URI_SCHEME,
    GPGSigner,
    SecretsHandler,
    Signer,
    SSlibSigner,
)
