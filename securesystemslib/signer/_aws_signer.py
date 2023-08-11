"""Signer implementation for AWS Key Management Service"""

import logging
from typing import Optional, Tuple
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib import exceptions
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer
from securesystemslib.signer._utils import compute_default_keyid

logger = logging.getLogger(__name__)

AWS_IMPORT_ERROR = None
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    from cryptography.hazmat.primitives import serialization
except ImportError:
    AWS_IMPORT_ERROR = "Signing with AWS KMS requires aws-kms and cryptography."


class AWSSigner(Signer):
    """AWS Key Management Service Signer

    This Signer uses AWS KMS to sign and supports signing with RSA/EC keys and
    uses "ambient" credentials typically environment variables such as
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN. These will
    be recognized by the boto3 SDK, which underlies the aws_kms Python module.

    For more details on AWS authentication, refer to the AWS Command Line
    Interface User Guide:
        https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html

    Some practical authentication options include:
        AWS CLI: https://aws.amazon.com/cli/
        AWS SDKs: https://aws.amazon.com/tools/

    The specific permissions that AWS KMS signer needs are:
        kms:Sign for sign()
        kms:GetPublicKey for import()

    Arguments:
        aws_key_id (str): AWS KMS key ID or alias.
        public_key (Key): The related public key instance.

    Returns:
        AWSSigner: An instance of the AWSSigner class.

    Raises:
        UnsupportedAlgorithmError: If the payload hash algorithm is unsupported.
        BotoCoreError: Errors from the botocore.exceptions library.
        ClientError: Errors related to AWS KMS client.
        UnsupportedLibraryError: If necessary libraries for AWS KMS are not available.
    """

    SCHEME = "awskms"

    def __init__(self, aws_key_id: str, public_key: Key):
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        self.hash_algorithm = self._get_hash_algorithm(public_key)
        self.aws_key_id = aws_key_id
        self.public_key = public_key
        self.client = boto3.client("kms")
        self.aws_algo = self._get_aws_signing_algo(self.public_key.scheme)

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
    def import_(cls, aws_key_id: str, local_scheme: str) -> Tuple[str, Key]:
        """Loads a key and signer details from AWS KMS.

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.

        Arguments:
            aws_key_id (str): AWS KMS key ID.
            local_scheme (str): Local scheme to use.

        Returns:
            Tuple[str, Key]: A tuple where the first element is a string
            representing the private key URI, and the second element is an
            instance of the public key.

        Raises:
            UnsupportedAlgorithmError: If the AWS KMS signing algorithm is
            unsupported.
            BotoCoreError: Errors from the botocore.exceptions library.
            ClientError: Errors related to AWS KMS client.
        """
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        client = boto3.client("kms")
        request = client.get_public_key(KeyId=aws_key_id)
        kms_pubkey = serialization.load_der_public_key(request["PublicKey"])

        public_key_pem = kms_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        try:
            keytype = cls._get_keytype_for_scheme(local_scheme)
        except KeyError as e:
            raise exceptions.UnsupportedAlgorithmError(
                f"{local_scheme} is not a supported signing algorithm"
            ) from e

        keyval = {"public": public_key_pem}
        keyid = compute_default_keyid(keytype, local_scheme, keyval)
        public_key = SSlibKey(keyid, keytype, local_scheme, keyval)
        return f"{cls.SCHEME}:{aws_key_id}", public_key

    @staticmethod
    def _get_keytype_for_scheme(
        scheme: str,
    ) -> str:
        """Returns the Secure Systems Library key type.

        Arguments:
            (str): The Secure Systems Library scheme.

        Returns:
            str: The Secure Systems Library key type.
        """
        keytype_for_scheme = {
            "ecdsa-sha2-nistp256": "ecdsa",
            "ecdsa-sha2-nistp384": "ecdsa",
            "ecdsa-sha2-nistp512": "ecdsa",
            "rsassa-pss-sha256": "rsa",
            "rsassa-pss-sha384": "rsa",
            "rsassa-pss-sha512": "rsa",
            "rsa-pkcs1v15-sha256": "rsa",
            "rsa-pkcs1v15-sha384": "rsa",
            "rsa-pkcs1v15-sha512": "rsa",
        }
        return keytype_for_scheme[scheme]

    @staticmethod
    def _get_aws_signing_algo(
        scheme: str,
    ) -> str:
        """Returns AWS signing algorithm

        Arguments:
            scheme (str): The Secure Systems Library signing scheme.

        Returns:
            str: AWS signing scheme.
        """
        aws_signing_algorithms = {
            "ecdsa-sha2-nistp256": "ECDSA_SHA_256",
            "ecdsa-sha2-nistp384": "ECDSA_SHA_384",
            "ecdsa-sha2-nistp512": "ECDSA_SHA_512",
            "rsassa-pss-sha256": "RSASSA_PSS_SHA_256",
            "rsassa-pss-sha384": "RSASSA_PSS_SHA_384",
            "rsassa-pss-sha512": "RSASSA_PSS_SHA_512",
            "rsa-pkcs1v15-sha256": "RSASSA_PKCS1_V1_5_SHA_256",
            "rsa-pkcs1v15-sha384": "RSASSA_PKCS1_V1_5_SHA_384",
            "rsa-pkcs1v15-sha512": "RSASSA_PKCS1_V1_5_SHA_512",
        }
        return aws_signing_algorithms[scheme]

    @staticmethod
    def _get_hash_algorithm(public_key: Key) -> str:
        """Helper function to return payload hash algorithm used for this key

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
        """Sign the payload with the AWS KMS key

        Arguments:
            payload: bytes to be signed.

        Raises:
            BotoCoreError: Errors from the botocore.exceptions library.
            ClientError: Errors related to AWS KMS client.

        Returns:
            Signature.
        """
        try:
            request = self.client.sign(
                KeyId=self.aws_key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm=self.aws_algo,
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
