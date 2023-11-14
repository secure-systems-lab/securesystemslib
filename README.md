# securesystemslib

[![CI](https://github.com/secure-systems-lab/securesystemslib/workflows/Run%20Securesystemslib%20tests/badge.svg)](https://github.com/secure-systems-lab/securesystemslib/actions?query=workflow%3A%22Run+Securesystemslib+tests%22+branch%3Amain)
[![Documentation Status](https://readthedocs.org/projects/python-securesystemslib/badge/?version=latest)](https://python-securesystemslib.readthedocs.io/en/latest/?badge=latest)

Securesystemslib is a cryptography interface for signing and verifying digital
signatures. It is developed for the [TUF](https://theupdateframework.io) and
[in-toto](https://in-toto.io) projects: the key and signature containers are
compatible with metadata formats from those projects.

Under the hood, Securesystemslib can use various digital signing systems
(e.g. [cryptography](https://pypi.org/project/cryptography/), PIV hardware keys
and multiple cloud-based key management systems).

## Installation

The default installation supports [pure-Python `ed25519` signature
verification](https://github.com/pyca/ed25519) only. To enable other schemes and
signature creation, `securesystemslib` can be installed with *extras*. See
[pyproject.toml](pyproject.toml) for available *optional dependencies*.

```bash
# Install with ed25519, RSA, ECDSA sign and verify support
pip install securesystemslib[crypto]
```

```bash
# ...or with HSM (e.g. Yubikey) support
pip install securesystemslib[hsm]
```

## Usage
[python-securesystemslib.readthedocs.io](https://python-securesystemslib.readthedocs.io)

## Contact
- Questions and discussions:
  [`#securesystemslib-python`](https://cloud-native.slack.com/archives/C05PF3GA7AL)
  on [CNCF Slack](https://communityinviter.com/apps/cloud-native/cncf)
- Security issues: [*Report a vulnerability*](https://github.com/secure-systems-lab/securesystemslib/security/advisories/new)
- Other issues and requests: [*Open a new
  issue*](https://github.com/secure-systems-lab/securesystemslib/issues/new)

## Testing
`tox` is used for testing. It can be installed via
[pip](https://tox.wiki/en/4.9.0/installation.html#via-pip) and executed from the
command line in the root of the repository.

```bash
tox
```

## Legacy key migration

Use [`migrate_keys`](docs/migrate_key.py) script to convert key pairs generated
with legacy `keys` or `interface` modules to a consistent standard format, which
is compatible with [`CryptoSigner`](docs/CRYPTO_SIGNER.md).
