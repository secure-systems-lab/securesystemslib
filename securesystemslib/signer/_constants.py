"""Constants for supported key types and signing schemes.

These are used throughout the ``securesystemslib.signer`` package instead of
hardcoded strings. The publicly registered key type and scheme pairs are listed
in ``securesystemslib.signer.KEY_FOR_TYPE_AND_SCHEME``.
"""

# Key types
KEY_TYPE_RSA = "rsa"
KEY_TYPE_ECDSA = "ecdsa"
KEY_TYPE_ED25519 = "ed25519"

# ECDSA schemes
ECDSA_SHA2_NISTP256 = "ecdsa-sha2-nistp256"
ECDSA_SHA2_NISTP384 = "ecdsa-sha2-nistp384"
ECDSA_SHA2_NISTP521 = "ecdsa-sha2-nistp521"

# RSA-PSS schemes
RSASSA_PSS_SHA224 = "rsassa-pss-sha224"
RSASSA_PSS_SHA256 = "rsassa-pss-sha256"
RSASSA_PSS_SHA384 = "rsassa-pss-sha384"
RSASSA_PSS_SHA512 = "rsassa-pss-sha512"

# RSA-PKCS1v15 schemes
RSA_PKCS1V15_SHA224 = "rsa-pkcs1v15-sha224"
RSA_PKCS1V15_SHA256 = "rsa-pkcs1v15-sha256"
RSA_PKCS1V15_SHA384 = "rsa-pkcs1v15-sha384"
RSA_PKCS1V15_SHA512 = "rsa-pkcs1v15-sha512"

# Ed25519
ED25519 = "ed25519"
