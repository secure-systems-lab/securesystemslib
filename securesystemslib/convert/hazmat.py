"""
This module contains functions to convert `cryptography.hazmat` keys into `securesystemlib` key dicts.
"""


import typing

from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey,
    _EllipticCurvePublicKey,
)
from cryptography.hazmat.backends.openssl.ed25519 import (
    _Ed25519PrivateKey,
    _Ed25519PublicKey,
)
from cryptography.hazmat.backends.openssl.rsa import (
    _RSAPrivateKey,
    _RSAPublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from ..keys import (
    format_ed25519_dict,
    import_ecdsakey_from_pem,
    import_rsakey_from_pem,
)


def _hazmat_key_to_pem(
    key: typing.Union[
        _RSAPrivateKey,
        _EllipticCurvePrivateKey,
    ]
) -> str:
    """The approach already used in this lib is to convert keys into PEM and then to parse from it."""

    if key.__class__.__name__.endswith("PrivateKey"):
        serialized = key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,
            NoEncryption(),
        )
    elif key.__class__.__name__.endswith("PublicKey"):
        serialized = key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        raise TypeError(key)

    return serialized.decode("utf-8")


def _import_hazmat_ed25519_private_key(
    key: _Ed25519PrivateKey,
) -> dict:
    """Imports hazmat ed25519 private key"""

    pub = key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    sec = key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    )
    return format_ed25519_dict(
        pub,
        sec,
    )


def _import_hazmat_ed25519_public_key(
    key: _Ed25519PublicKey,
) -> dict:
    """Imports hazmat ed25519 public key"""

    pub = key.public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    return format_ed25519_dict(
        pub,
        None,
    )


def _import_rsa_key(
    key: _RSAPrivateKey,
) -> dict:
    """Imports hazmat RSA key"""

    return import_rsakey_from_pem(_hazmat_key_to_pem(key))


def _import_ecdsa_key(
    key: _EllipticCurvePrivateKey,
) -> dict:
    """Imports hazmat ECDSA key"""

    return import_ecdsakey_from_pem(_hazmat_key_to_pem(key))


_typeMapping = {
    _Ed25519PrivateKey: _import_hazmat_ed25519_private_key,
    _Ed25519PublicKey: _import_hazmat_ed25519_public_key,
    _RSAPrivateKey: _import_rsa_key,
    _RSAPublicKey: _import_rsa_key,
    _EllipticCurvePrivateKey: _import_ecdsa_key,
    _EllipticCurvePublicKey: _import_ecdsa_key,
}


def import_hazmat_key(
    key: typing.Union[
        _RSAPrivateKey, _EllipticCurvePrivateKey, _Ed25519PrivateKey
    ]
) -> dict:
    """
    <Purpose>
        Converts a `cryptography.hazmat` key into a dictionary conformant to 'securesystemslib.formats.KEY_SCHEMA'.

    <Arguments>
        key:
            A key of the classes from `cryptography.hazmat` module. Currently only keys of `openssl` backend are implemented.

    <Exceptions>
        securesystemslib.exceptions.FormatError, if 'key_value' does not conform to
        'securesystemslib.formats.KEYVAL_SCHEMA', or if the private key is not
        present in 'key_value' if requested by the caller via 'private'.
        NotImplementedError, if we cannot convert a key of this type.

    <Side Effects>
        None.

    <Returns>
        A 'securesystemslib.formats.KEY_SCHEMA' dictionary."""

    key_type = type(key)
    try:
        mapper = _typeMapping[key_type]
    except KeyError as ex:
        raise NotImplementedError(key_type) from ex
    else:
        return mapper(key)
