"""
The Signer API

This module provides extensible interfaces for public keys and signers:
Some implementations are provided by default but more can be added by users.
"""

# ruff: noqa: F401
from securesystemslib.signer._aws_signer import AWSSigner
from securesystemslib.signer._azure_signer import AzureSigner
from securesystemslib.signer._crypto_signer import CryptoSigner
from securesystemslib.signer._gcp_signer import GCPSigner
from securesystemslib.signer._gpg_signer import GPGKey, GPGSigner
from securesystemslib.signer._hsm_signer import HSMSigner
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME, Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import (
    SIGNER_FOR_URI_SCHEME,
    SecretsHandler,
    Signer,
)
from securesystemslib.signer._sigstore_signer import SigstoreKey, SigstoreSigner
from securesystemslib.signer._spx_signer import (
    SpxKey,
    SpxSigner,
    generate_spx_key_pair,
)
from securesystemslib.signer._vault_signer import VaultSigner

# Register supported private key uri schemes and the Signers implementing them
SIGNER_FOR_URI_SCHEME.update(
    {
        CryptoSigner.SCHEME: CryptoSigner,
        GCPSigner.SCHEME: GCPSigner,
        HSMSigner.SCHEME: HSMSigner,
        GPGSigner.SCHEME: GPGSigner,
        AzureSigner.SCHEME: AzureSigner,
        AWSSigner.SCHEME: AWSSigner,
        VaultSigner.SCHEME: VaultSigner,
    }
)

# Signers with currently unstable metadata formats, not supported by default:
#   SigstoreSigner,
#   SpxSigner (also does not yet support private key uri scheme)

# Register supported key types and schemes, and the Keys implementing them
KEY_FOR_TYPE_AND_SCHEME.update(
    {
        ("ecdsa", "ecdsa-sha2-nistp256"): SSlibKey,
        ("ecdsa", "ecdsa-sha2-nistp384"): SSlibKey,
        ("ecdsa", "ecdsa-sha2-nistp521"): SSlibKey,
        ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"): SSlibKey,
        ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"): SSlibKey,
        ("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"): SSlibKey,
        ("ed25519", "ed25519"): SSlibKey,
        ("rsa", "rsassa-pss-sha224"): SSlibKey,
        ("rsa", "rsassa-pss-sha256"): SSlibKey,
        ("rsa", "rsassa-pss-sha384"): SSlibKey,
        ("rsa", "rsassa-pss-sha512"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha224"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha256"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha384"): SSlibKey,
        ("rsa", "rsa-pkcs1v15-sha512"): SSlibKey,
        ("rsa", "pgp+rsa-pkcsv1.5"): GPGKey,
        ("dsa", "pgp+dsa-fips-180-2"): GPGKey,
        ("eddsa", "pgp+eddsa-ed25519"): GPGKey,
    }
)

# Keys with currently unstable metadata formats, not supported by default:
#       ("sphincs", "sphincs-shake-128s"): SpxKey,
#       ("sigstore-oidc", "Fulcio"): SigstoreKey,
