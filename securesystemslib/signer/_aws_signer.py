"""Signer implementation for AWS Key Management Service"""

import logging
from typing import Optional, Tuple
from urllib import parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
import securesystemslib.hash as sslib_hash
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib import exceptions
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import (
    SecretsHandler,
    Signature,
    Signer,
    SSlibKey,
)

logger = logging.getLogger(__name__)

AWS_IMPORT_ERROR = None
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    AWS_IMPORT_ERROR = ("Signing with AWS KMS requires aws-kms and cryptography.")

class AWSSigner(Signer):
    """
    AWS Key Management Service Signer

    This Signer uses AWS KMS to sign. This signer supports signing with RSA and EC keys.

    Arguments:
        key_id: AWS KMS key id
        public_key: The related public key instance

    Raises:
        UnsupportedAlgorithmError: The payload hash algorithm is unsupported.
        UnsupportedLibraryError: google.cloud.kms was not found
        Various errors from botocore.exceptions
    """

    SCHEME = "awskms"

    def __init__(self, key_id: str, public_key: Key):
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        self.hash_algorithm = self._get_hash_algorithm(public_key)
        self.key_id = key_id
        self.public_key = public_key
        self.client = boto3.client("kms")

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "AWSSigner":
        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"AWSSigner does not support {priv_key_uri}")

        return cls(uri.path, public_key)

    @classmethod
    def import_(cls, aws_key_id: str) -> Tuple[str, Key]:
        """
        Load key and signer details from AWS KMS

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.
        """
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)
        
        client = boto3.client("kms")
        request = client.get_public_key(KeyId=aws_key_id)
        kms_pubkey = serialization.load_der_public_key(request["PublicKey"])

        key_spec = request["KeySpec"]
        public_key_pem = kms_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        try:
            keytype, scheme = cls._get_keytype_and_scheme(key_spec)
        except KeyError as e:
            raise exceptions.UnsupportedAlgorithmError(
                f"{key_spec} is not a supported signing algorithm"
            ) from e

        keyval = {"public": public_key_pem}
        keyid = cls._get_keyid(keytype, scheme, keyval)
        public_key = SSlibKey(keyid, keytype, scheme, keyval)
        return f"{cls.SCHEME}:{aws_key_id}", public_key

    @staticmethod
    def _get_keytype_and_scheme(key_spec: str) -> Tuple[str, str]:
        """
        Return keytype and scheme for the AWS KMS key type and signing algorithm

        Arguments:
        key_spec (str): AWS KMS key type

        Returns:
        Tuple[str, str]: Tuple containing key type and signing scheme
        """
        default_rsa_keytype_and_scheme = [
                ("rsa", "rsassa-pss-sha256")
            ]
        keytype_and_scheme = {
            "ECC_NIST_P256": [
                ("ecdsa", "ECDSA_SHA_256"),
            ],
            "ECC_NIST_P384": [
                ("ecdsa", "ECDSA_SHA_384"),
            ],
            "RSA_2048": default_rsa_keytype_and_scheme,
            "RSA_3072": default_rsa_keytype_and_scheme,
            "RSA_4096": default_rsa_keytype_and_scheme,
        }
        keytype_and_scheme_list = keytype_and_scheme.get(key_spec)

        if keytype_and_scheme_list is None or len(keytype_and_scheme_list) == 0:
            raise KeyError(f"Unsupported key type: {key_spec}")
        return keytype_and_scheme_list[0]

    @staticmethod
    def _get_hash_algorithm(public_key: Key) -> str:
        """
        Helper function to return payload hash algorithm used for this key

        Arguments:
        public_key (Key): Public key object

        Returns:
        str: Hash algorithm
        """
        if public_key.keytype == "rsa":
            # hash algorithm is encoded as last scheme portion
            algo = public_key.scheme.split("-")[-1]
        if public_key.keytype in [
            "ecdsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
        ]:
            # nistp256 uses sha-256, nistp384 uses sha-384
            bits = public_key.scheme.split("-nistp")[-1]
            algo = f"sha{bits}"

        # trigger UnsupportedAlgorithm if appropriate
        _ = sslib_hash.digest(algo)
        return algo

    def sign(self, payload: bytes) -> Signature:
        """
        Sign the payload with the AWS KMS key

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from botocore.exceptions.

        Returns:
            Signature.
        """
        sslib_signing_algos = ["ecdsa-sha2-nistp256",
                               "ecdsa-sha2-nistp384",
                               "ecdsa-sha2-nistp512",
                               "rsassa-pss-sha256",
                               "rsassa-pss-sha384",
                               "rsassa-pss-sha512",
                               "rsa-pkcs1v15-sha256",
                               "rsa-pkcs1v15-sha384",
                               "rsa-pkcs1v15-sha512"]
        aws_signing_algos = ["ECDSA_SHA_256",
                             "ECDSA_SHA_384",
                             "ECDSA_SHA_512",
                             "RSASSA_PSS_SHA_256",
                             "RSASSA_PSS_SHA_384",
                             "RSASSA_PSS_SHA_512",
                             "RSASSA_PKCS1_V1_5_SHA_256",
                             "RSASSA_PKCS1_V1_5_SHA_384","RSASSA_PKCS1_V1_5_SHA_512"]
        try:
            for ssl, aws in zip(sslib_signing_algos, aws_signing_algos):
                if ssl == self.public_key.scheme:
                    signing_scheme = aws
                    self.public_key.scheme = ssl
            request = self.client.sign(
                KeyId=self.key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm=signing_scheme
            )
            hasher = sslib_hash.digest(self.hash_algorithm)
            hasher.update(payload)
            logger.debug("signing response %s", request)
            response = request["Signature"]
            logger.debug("signing response %s", response)

            return Signature(self.public_key.keyid, response.hex())
        except (BotoCoreError, ClientError) as e:
            logger.error("Failed to sign with AWS KMS: %s", str(e))
            raise e
