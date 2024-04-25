
# CryptoSigner

`CryptoSigner` implements signing with file-based *rsa*, *ecdsa* and *ed25519*
keys. New private key material can be created with the provided simple API
or with [cryptography](https://cryptography.io/).

Loading the signer at signing time works through the generic
`Signer.from_priv_key_uri()` method using the "file2:" URI.

## Code examples

### 1. Generate key content

`CryptoSigner` provides `generate_{rsa, ed25519, ecdsa}` methods to create new
private key material.

```python
from securesystemslib.signer import CryptoSigner

signer = CryptoSigner.generate_ed25519()

# store private key securely
with open ("privkey.pem", "wb") as f:
    f.write(signer.private_bytes)

# Publish the public key
pubkey = signer.public_key
print(pubkey.to_dict())
```

For more control over the key material, the cryptography API can be used

<details><summary>Generating a new private key with cryptography</summary>

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from securesystemslib.signer import CryptoSigner

# Generate key pair with non-default arguments
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)

signer = CryptoSigner(private_key)

# store private key securely
with open ("privkey.pem", "wb") as f:
    f.write(signer.private_bytes)

# Publish the public key
pubkey = signer.public_key
print(pubkey.to_dict())
```
</details>

<details><summary>Using an existing private key</summary>

```python
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from securesystemslib.signer import CryptoSigner

# Load a PEM encoded key from disk
with open("privkey.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), None)

signer = CryptoSigner(private_key)

# Publish the public key
pubkey = signer.public_key
print(pubkey.to_dict())
```
</details>

### 2. Load and use signer

Signer usage is not specific to CryptoSigner:

```python
from securesystemslib.signer import Signer

# Load signer using URI that points to private key bytes
signer = Signer.from_priv_key_uri("file2:privkey.pem", pubkey)
signature = signer.sign(b"data")
print(signature.to_dict())
```
