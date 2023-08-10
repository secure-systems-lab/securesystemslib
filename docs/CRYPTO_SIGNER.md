
# CryptoSigner

`CryptoSigner` is a modern replacement for the legacy `securesystemslib.keys`
module. It can be used via the `Signer.from_priv_key_uri` API to load private
*rsa*, *ecdsa* and *ed25519* keys from file. It also provides API to generate
in-memory signers for ad-hoc signing.

## Code examples

### Example 1: Ad-hoc signing

`CryptoSigner` provides `generate_{rsa, ed25519, ecdsa}` methods for ad-hoc
signing and signature verification, e.g. in tests or demos.

```python
from securesystemslib.signer import CryptoSigner

signer = CryptoSigner.generate_ed25519()
signature = signer.sign(b"data")
signer.public_key.verify_signature(signature, b"data")
```

### Example 2: Asynchronous key management and signing

The typical Signer API usage is described in
[this blog post](https://theupdateframework.github.io/python-tuf/2023/01/24/securesystemslib-signer-api.html)
and outlined below for a file-based signer.

#### 1. Generate key files
*`CryptoSigner` does not provide API to generate key files. Compatible
keys can be generated with standard tools like `openssl genpkey` (CLI) or
`pyca/cryptography` (Python).*

```python
from cryptography.hazmat.primitives import asymmetric, serialization

# Generate key pair
private_key = asymmetric.ed25519.Ed25519PrivateKey.generate()

# Serialize private key as encrypted PEM/PKCS8
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"hunter2"),
)

# Serialize public key as encrypted PEM/subjectPublicKeyInfo
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Write key files
with open("private.pem", "wb") as f:
    f.write(private_pem)
with open("public.pem", "wb") as f:
    f.write(public_pem)
```

#### 2. Prepare signing environment

```python
import os
from securesystemslib.signer import SSlibKey

with open("public.pem", "rb") as f:
    public_bytes = f.read()

# Make public key, signer URI, and key decryption password available to the
# signer, e.g. via environment variables. The private key file must also be
# available to the signer at the specified path.
os.environ.update({
    "SIGNER_URI":  "file:private.pem?encrypted=true",
    "SIGNER_PUBLIC": public_bytes.decode(),
    "SIGNER_SECRET": "hunter2"
})
```

#### 3. Load and use signer

```python
import os
from securesystemslib.signer import SSlibKey, Signer, CryptoSigner, SIGNER_FOR_URI_SCHEME

# NOTE: Registration becomes obsolete once CryptoSigner is the default file signer
SIGNER_FOR_URI_SCHEME.update({CryptoSigner.FILE_URI_SCHEME: CryptoSigner})

# Read signer details
uri = os.environ["SIGNER_URI"]
public_key = SSlibKey.from_pem(os.environ["SIGNER_PUBLIC"].encode())
secrets_handler = lambda sec: os.environ["SIGNER_SECRET"]

# Load and sign
signer = Signer.from_priv_key_uri(uri, public_key, secrets_handler)
signer.sign(b"data")
```
