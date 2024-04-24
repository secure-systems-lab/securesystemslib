
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

#### 1. Generate key content
*`CryptoSigner` does not provide a comprehensive API for key content generation.
Compatible keys can be generated with standard tools like `openssl genpkey` (CLI) or
`pyca/cryptography` (Python).*

```python
from cryptography.hazmat.primitives import asymmetric, serialization

from securesystemslib.signer import SSlibKey

# Generate key pair
private_key = asymmetric.ed25519.Ed25519PrivateKey.generate()

# Deploy private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("private.pem", "wb") as f:
    f.write(private_pem)

# TODO: The public details (public key and the private key URI) must be stored
# somewhere. In a TUF system the public key goes into TUF metadata, and the
# URI can can be stored either in the metadata as well (as a custom field) or in
# signing application configuration
public_key = SSlibKey.from_crypto(private_key.public_key())
uri = "file2:private.pem"
```

#### 2. Load and use signer

Signer usage is not specific to CryptoSigner:

```python
from securesystemslib.signer import Signer

# TODO: load the URI and public key (see earlier comment)
signer = Signer.from_priv_key_uri(uri, public_key)
signer.sign(b"data")
```
