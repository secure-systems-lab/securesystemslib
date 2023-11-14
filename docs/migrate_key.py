#!/usr/bin/env python
"""CLI script to migrate legacy keys to standard format

Convert legacy key files created via `securesystemslib.interface` or
`securesystemslib.keys` to a standard format, e.g. for use with `CryptoSigner`
of the Signer API (see CRYPTO_SIGNER.md).

Standard format for all algorithms
----------------------------------
* private: PEM/PKCS8
* public: PEM/subjectPublicKeyInfo

NOTE: Auto-generated keyids are likely to change after migration. Make sure to
set keyids of new signers explicitly, by passing a public key with the desired
keyid, or adopt changes in any delegations in TUF or in-toto.

"""
import argparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_public_key,
)

from securesystemslib import interface as legacy
from securesystemslib.signer import CryptoSigner


def migrate_private(path_in, algo, password):
    """Migrate private key"""
    legacy_key = legacy.import_privatekey_from_file(path_in, algo, password)
    crypto_signer = CryptoSigner.from_securesystemslib_key(legacy_key)

    if password:
        encryption_algorithm = BestAvailableEncryption(password.encode())
    else:
        encryption_algorithm = NoEncryption()

    private_key = crypto_signer._private_key  # pylint: disable=protected-access

    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )


def migrate_public(path_in, algo):
    """Migrate public key"""
    legacy_keys = legacy.import_publickeys_from_file([path_in], [algo])
    legacy_key = list(legacy_keys.values())[0]

    if algo in ["rsa", "ecdsa"]:
        public_key = load_pem_public_key(
            legacy_key["keyval"]["public"].encode()
        )
    else:  # ed25519
        public_bytes = bytes.fromhex(legacy_key["keyval"]["public"])
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Migrate legacy keys to standard format "
            "(PEM/PKCS8/subjectPublicKeyInfo)."
        )
    )

    parser.add_argument(
        "--type",
        choices=["private", "public"],
        required=True,
        help="key type",
    )
    parser.add_argument(
        "--password",
        help="password to decrypt legacy and encrypt new private key",
    )
    parser.add_argument(
        "--algo",
        choices=["rsa", "ecdsa", "ed25519"],
        required=True,
        help="key algorithm",
    )
    parser.add_argument(
        "--in",
        dest="path_in",
        metavar="PATH",
        required=True,
        help="file path to legacy key",
    )
    parser.add_argument(
        "--out",
        dest="path_out",
        metavar="PATH",
        required=True,
        help="file path to new key",
    )

    args = parser.parse_args()

    if args.type == "private":
        new_key_bytes = migrate_private(args.path_in, args.algo, args.password)

    else:  # public
        if args.password:
            parser.print_usage()
            parser.error("use password with --type private only")
        new_key_bytes = migrate_public(args.path_in, args.algo)

    with open(args.path_out, "wb+") as output_file:
        output_file.write(new_key_bytes)


if __name__ == "__main__":
    main()
