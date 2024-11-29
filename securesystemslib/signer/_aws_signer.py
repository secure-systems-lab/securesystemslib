"""Signer implementation for AWS Key Management Service"""

from __future__ import annotations

import logging
from urllib import parse

from securesystemslib.exceptions import (
    UnsupportedAlgorithmError,
    UnsupportedLibraryError,
)
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

    # Ordered dict of securesystemslib schemes to aws signing algorithms
    # NOTE: the order matters when choosing a default (see _get_default_scheme)
    aws_algos = {
        "ecdsa-sha2-nistp256": "ECDSA_SHA_256",
        "ecdsa-sha2-nistp384": "ECDSA_SHA_384",
        # "ecdsa-sha2-nistp521": "ECDSA_SHA_512", # FIXME: needs SSlibKey support
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
        self._public_key = public_key
        self.client = boto3.client("kms")
        self.aws_algo = self.aws_algos[self.public_key.scheme]

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> AWSSigner:
        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"AWSSigner does not support {priv_key_uri}")

        return cls(uri.path, public_key)

    @classmethod
    def _get_default_scheme(cls, supported_by_key: list[str]) -> str | None:
        # Iterate over supported AWS algorithms, pick the **first** that is also
        # supported by the key, and return the related securesystemslib scheme.
        for scheme, algo in cls.aws_algos.items():
            if algo in supported_by_key:
                return scheme
        return None

    @staticmethod
    def _get_keytype_for_scheme(scheme: str) -> str:
        if scheme.startswith("ecdsa"):
            return "ecdsa"
        if scheme.startswith("rsa"):
            return "rsa"
        raise RuntimeError

    @classmethod
    def import_(
        cls, aws_key_id: str, local_scheme: str | None = None
    ) -> tuple[str, Key]:
        """Loads a key and signer details from AWS KMS.

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.

        Arguments:
            aws_key_id (str): AWS KMS key ID.
            local_scheme (Optional[str]): The Secure Systems Library RSA/ECDSA scheme.
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
            if local_scheme not in cls.aws_algos:
                raise ValueError(f"Unsupported scheme '{local_scheme}'")

        client = boto3.client("kms")
        request = client.get_public_key(KeyId=aws_key_id)
        key_algos = request["SigningAlgorithms"]

        if local_scheme:
            if cls.aws_algos[local_scheme] not in key_algos:
                raise UnsupportedAlgorithmError(
                    f"Unsupported scheme '{local_scheme}' for AWS key"
                )

        else:
            local_scheme = cls._get_default_scheme(key_algos)
            if not local_scheme:
                raise UnsupportedAlgorithmError(
                    f"Unsupported AWS key algorithms: {key_algos}"
                )

        keytype = cls._get_keytype_for_scheme(local_scheme)

        kms_pubkey = serialization.load_der_public_key(request["PublicKey"])

        public_key_pem = kms_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        keyval = {"public": public_key_pem}
        keyid = compute_default_keyid(keytype, local_scheme, keyval)
        public_key = SSlibKey(keyid, keytype, local_scheme, keyval)
        return f"{cls.SCHEME}:{aws_key_id}", public_key

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
