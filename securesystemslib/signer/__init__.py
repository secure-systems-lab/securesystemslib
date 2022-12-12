"""
The Signer API

This module provides extensible interfaces for public keys and signers:
Some implementations are provided by default but more can be added by users.
"""
from securesystemslib.signer._gcp_signer import GCPSigner
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME, Key, SSlibKey
from securesystemslib.signer._signature import GPGSignature, Signature
from securesystemslib.signer._signer import (
    SIGNER_FOR_URI_SCHEME,
    GPGSigner,
    SecretsHandler,
    Signer,
    SSlibSigner,
)

# Register supported private key uri schemes and the Signers implementing them
SIGNER_FOR_URI_SCHEME.update(
    {
        SSlibSigner.ENVVAR_URI_SCHEME: SSlibSigner,
        SSlibSigner.FILE_URI_SCHEME: SSlibSigner,
        GCPSigner.SCHEME: GCPSigner,
    }
)

# Register supported key types and schemes, and the Keys implementing them
KEY_FOR_TYPE_AND_SCHEME.update(
    {
        ("ecdsa", "ecdsa-sha2-nistp256"): SSlibKey,
        ("ecdsa", "ecdsa-sha2-nistp384"): SSlibKey,
        ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"): SSlibKey,
        ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"): SSlibKey,
        ("ed25519", "ed25519"): SSlibKey,
        ("rsa", "rsassa-pss-md5"): SSlibKey,
        ("rsa", "rsassa-pss-sha1"): SSlibKey,
        ("rsa", "rsassa-pss-sha224"): SSlibKey,
        ("rsa", "rsassa-pss-sha256"): SSlibKey,
        ("rsa", "rsassa-pss-sha384"): SSlibKey,
        ("rsa", "rsassa-pss-sha512"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-md5"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha1"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha224"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha256"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha384"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha512"): SSlibKey,
        ("sphincs", "sphincs-shake-128s"): SSlibKey,
    }
)
