"""Signer implementation for AWS Key Management Service"""

import logging
from typing import Optional, Tuple
from urllib import parse

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

    def __init__(self, aws_key_id: str, public_key: Key):
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        self.aws_key_id = aws_key_id
        self.public_key = public_key
        self.client = boto3.client("kms")
        self.aws_algo = AWSSigner.aws_signing_algorithms.get(
            self.public_key.scheme
        )

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
    def import_(
        cls, aws_key_id: str, local_scheme: Optional[str] = None
    ) -> Tuple[str, Key]:
        """Loads a key and signer details from AWS KMS.

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.

        Arguments:
            aws_key_id (str): AWS KMS key ID.
            local_scheme (Optional[str]): The Secure Systems Library RSA or ECDSA scheme.
            Defaults to 'rsassa-pss-sha256' if not provided and RSA.

        Returns:
            Tuple[str, Key]: A tuple where the first element is a string
            representing the private key URI, and the second element is an
            instance of the public key.

        Raises:
            UnsupportedAlgorithmError: If the AWS KMS signing algorithm is
            unsupported.
            BotoCoreError: Errors from the botocore library.
            ClientError: Errors related to AWS KMS client.
        """
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        if local_scheme:
            if local_scheme not in cls.aws_signing_algorithms:
                raise ValueError(f"Unsupported scheme: {local_scheme}")

        try:
            client = boto3.client("kms")
            request = client.get_public_key(KeyId=aws_key_id)
        except (BotoCoreError, ClientError) as e:
            logger.error(
                "Failed to import key using AWS KMS key ID %s: %s",
                aws_key_id,
                str(e),
            )
            raise e

        kms_pubkey = serialization.load_der_public_key(request["PublicKey"])
        keytype = cls._get_keytype_from_aws_response(request)

        if not local_scheme:
            if keytype == "ecdsa":
                aws_scheme = request["SigningAlgorithms"][0]
                scheme = cls._get_ecdsa_scheme(aws_scheme)
            elif keytype == "rsa":
                scheme = "rsassa-pss-sha256"
            else:
                raise ValueError(f"Unsupported key type: {keytype}")

        public_key_pem = kms_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        keyval = {"public": public_key_pem}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        public_key = SSlibKey(keyid, keytype, scheme, keyval)
        return f"{cls.SCHEME}:{aws_key_id}", public_key

    @staticmethod
    def _get_keytype_from_aws_response(reponse: dict) -> str:
        """Determines the key type from the AWS KMS get_public_key response.

        Arguments:
            response (dict): The response from AWS KMS get_public_key request.

        Returns:
            str: The key type, either 'ecdsa' or 'rsa'.
        """
        algo = reponse["SigningAlgorithms"][0]
        if "ECDSA" in algo:
            return "ecdsa"
        if "RSASSA" in algo:
            return "rsa"
        raise exceptions.UnsupportedAlgorithmError(
            f"Unsupported algorithm in AWS response: {algo}"
        )

    @staticmethod
    def _get_ecdsa_scheme(aws_algo: str) -> str:
        """Returns ECDSA signing scheme based on AWS signing algorithm.

        Arguments:
            aws_algo (str): The AWS ECDSA signing algorithm.

        Returns:
            str: The Secure Systems Library ECDSA scheme.
        """
        ecdsa_signing_algorithms = {
            "ECDSA_SHA_256": "ecdsa-sha2-nistp256",
            "ECDSA_SHA_384": "ecdsa-sha2-nistp384",
            "ECDSA_SHA_512": "ecdsa-sha2-nistp512",
        }
        return ecdsa_signing_algorithms[aws_algo]

    def sign(self, payload: bytes) -> Signature:
        """Sign the payload with the AWS KMS key

        This method sends the payload to AWS KMS, where it is signed using the specified
        key and algorithm using the raw message type.

        Arguments:
            payload (bytes): The payload to be signed.

        Raises:
            BotoCoreError, ClientError: If an error occurs during the signing process.

        Returns:
            Signature: A signature object containing the key ID and the signature.
        """
        try:
            sign_request = self.client.sign(
                KeyId=self.aws_key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm=self.aws_algo,
            )

            logger.debug("Signing response: %s", sign_request)
            response = sign_request["Signature"]
            logger.debug("Signature response: %s", response)

            return Signature(self.public_key.keyid, response.hex())
        except (BotoCoreError, ClientError) as e:
            logger.error(
                "Failed to sign using AWS KMS key ID %s: %s",
                self.aws_key_id,
                str(e),
            )
            raise e
