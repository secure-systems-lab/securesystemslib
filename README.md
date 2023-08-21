# securesystemslib

[![CI](https://github.com/secure-systems-lab/securesystemslib/workflows/Run%20Securesystemslib%20tests/badge.svg)](https://github.com/secure-systems-lab/securesystemslib/actions?query=workflow%3A%22Run+Securesystemslib+tests%22+branch%3Amain)

A cryptography interface to sign and verify
[TUF](https://theupdateframework.io) and [in-toto](https://in-toto.io)
metadata.

## Installation

The default installation supports [pure-Python `ed25519` signature
verification](https://github.com/pyca/ed25519) only. To enable other schemes and
signature creation, `securesystemslib` can be installed with *extras*. See
[pyproject.toml](pyproject.toml) for available *optional dependencies*.

```bash
# Install with ed25519, RSA, ECDSA sign and verify support
pip install securesystemslib[crypto]
```

## Usage
[python-securesystemslib.readthedocs.io](https://python-securesystemslib.readthedocs.io)

## Contact
- Questions and discussions:
  [`#securesystemslib-python`](https://cloud-native.slack.com/archives/C05PF3GA7AL)
  on [CNCF Slack](https://communityinviter.com/apps/cloud-native/cncf)
- Security issues: [*Draft a new security
  advisory*](https://github.com/secure-systems-lab/securesystemslib/security/advisories/new)
- Other issues and requests: [*Open a new
  issue*](https://github.com/secure-systems-lab/securesystemslib/issues/new)

## Testing
`tox` is used for testing. It can be installed via
[pip](https://tox.wiki/en/4.9.0/installation.html#via-pip) and executed from the
command line in the root of the repository.

```bash
tox
```
