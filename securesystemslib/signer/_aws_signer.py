"""Signer implementation for AWS Key Management Service"""

import logging
from typing import Optional, Tuple
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib import exceptions
from securesystemslib.exceptions import UnsupportedLibraryError
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
    from cryptography.hazmat.primitives import serialization
except ImportError:
    AWS_IMPORT_ERROR = "Signing with AWS KMS requires aws-kms and cryptography."


class AWSSigner(Signer):
    """
    AWS Key Management Service Signer

    This Signer uses AWS KMS to sign. This signer supports signing with RSA and EC keys uses "ambient" credentials: typically environment variables such as AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN (if necessary). These will be recognized by the boto3 SDK, which underlies the aws_kms Python module.

    Note: For more details on AWS authentication, refer to the AWS Command Line Interface User Guide:
    https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html.

    Some practical authentication options include:
    AWS CLI: https://aws.amazon.com/cli/
    AWS SDKs: https://aws.amazon.com/tools/
    The specific permissions that AWS KMS signer needs are:

    kms:Sign for the sign()
    kms:GetPublicKey for the import()

    Arguments:
        key_id (str): AWS KMS key ID.
        public_key (Key): Related public key instance.

    Returns:
        AWSSigner: An instance of the AWSSigner class.

    Raises:
        UnsupportedAlgorithmError: If the payload hash algorithm is unsupported.
        BotoCoreError: Errors from the botocore.exceptions library.
        ClientError: Errors related to AWS KMS client.

    Note:
        If necessary libraries for AWS KMS are not available, the UnsupportedLibraryError will be raised.
    """

    SCHEME = "awskms"

    def __init__(self, key_id: str, public_key: Key):
        """
        Initializer for the AWSSigner class.

        This initializer also establishes a connection with AWS KMS and retrieves
        necessary information about the key to be used for signing.

        Arguments:
            key_id (str): AWS KMS key ID.
            public_key (Key): Related public key instance.

        Raises:
            UnsupportedLibraryError: If necessary libraries for AWS KMS are not available.
        """
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        self.hash_algorithm = self._get_hash_algorithm(public_key)
        self.key_id = key_id
        self.public_key = public_key
        self.client = boto3.client("kms")
        self.get_aws_algo = self._get_keytype_and_scheme(
            self.client.get_public_key(KeyId=self.key_id)["SigningAlgorithms"],
            self.public_key.scheme,
            get_aws_signing_scheme=True,
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
    def import_(cls, aws_key_id: str, local_scheme: str) -> Tuple[str, Key]:
        """
        Loads a key and signer details from AWS KMS.

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.

        Arguments:
            aws_key_id (str): AWS KMS key ID.
            local_scheme (str): Local scheme to use.

        Returns:
            Tuple[str, Key]: A tuple where the first element is a string representing the private key URI, and the second element is an instance of the public key.

        Raises:
            UnsupportedAlgorithmError: If the AWS KMS signing algorithm is unsupported.
            BotoCoreError: Errors from the botocore.exceptions library.
            ClientError: Errors related to AWS KMS client.
        """
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        client = boto3.client("kms")
        request = client.get_public_key(KeyId=aws_key_id)
        kms_pubkey = serialization.load_der_public_key(request["PublicKey"])

        aws_algorithms_list = request["SigningAlgorithms"]
        public_key_pem = kms_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        try:
            keytype, scheme = cls._get_keytype_and_scheme(
                aws_algorithms_list, local_scheme
            )
        except KeyError as e:
            raise exceptions.UnsupportedAlgorithmError(
                f"{aws_algorithms_list} is not a supported signing algorithm"
            ) from e

        keyval = {"public": public_key_pem}
        keyid = cls._get_keyid(keytype, scheme, keyval)
        public_key = SSlibKey(keyid, keytype, scheme, keyval)
        return f"{cls.SCHEME}:{aws_key_id}", public_key

    @staticmethod
    def _get_keytype_and_scheme(
        aws_algorithms_list: list,
        local_scheme: str,
        get_aws_signing_scheme=False,
    ) -> Tuple[str, str]:
        """
        Returns key type and scheme for the AWS KMS key type and signing algorithm

        Arguments:
            aws_algorithms_list (list): AWS KMS signing algorithms
            local_scheme (str): The Secure Systems Library scheme
            get_aws_signing_scheme (bool, optional): Enables the return of an AWS signing algorithm for signing. Defaults to False.

        Returns:
            Tuple[str, str]: Tuple containing key type and signing scheme if get_aws_signing_scheme is False.
            Tuple[str, str]: AWS signing scheme in the first value and an empty string in the last to keep returns consistent if get_aws_signing_scheme is True.
        """
        keytypes_and_schemes = {
            "ECDSA_SHA_256": ("ecdsa", "ecdsa-sha2-nistp256"),
            "ECDSA_SHA_384": ("ecdsa", "ecdsa-sha2-nistp384"),
            "ECDSA_SHA_512": ("ecdsa", "ecdsa-sha2-nistp512"),
            "RSASSA_PSS_SHA_256": ("rsa", "rsassa-pss-sha256"),
            "RSASSA_PSS_SHA_384": ("rsa", "rsassa-pss-sha384"),
            "RSASSA_PSS_SHA_512": ("rsa", "rsassa-pss-sha512"),
            "RSASSA_PKCS1_V1_5_SHA_256": ("rsa", "rsa-pkcs1v15-sha256"),
            "RSASSA_PKCS1_V1_5_SHA_384": ("rsa", "rsa-pkcs1v15-sha384"),
            "RSASSA_PKCS1_V1_5_SHA_512": ("rsa", "rsa-pkcs1v15-sha512"),
        }
        keytype_and_scheme = keytypes_and_schemes[aws_algorithms_list[0]]
        keytype = keytype_and_scheme[0]

        if get_aws_signing_scheme:
            AWSSigner._get_aws_signing_algo(
                keytype, local_scheme, keytypes_and_schemes, keytype_and_scheme
            )
        if keytype == "ecdsa":
            return keytype_and_scheme
        sslib_rsa_and_scheme = AWSSigner._parse_rsa(
            keytypes_and_schemes, local_scheme
        )
        return sslib_rsa_and_scheme

    @staticmethod
    def _get_aws_signing_algo(
        keytype: str,
        local_scheme: str,
        keytypes_and_schemes: dict,
        keytype_and_scheme: tuple,
    ) -> Tuple[str, str]:
        """
        Returns AWS signing algorithm

        Arguments:
            keytype (str): The Secure Systems Library key type.
            local_scheme (str): The Secure Systems Library signing scheme.
            keytypes_and_schemes (dict): The Secure Systems Library key types and signing schemes with the appropriate AWS signing algorithm as the dictionary key.
            keytype_and_scheme (tuple): The Secure Systems Library key type and signing scheme.

        Returns:
            Tuple[str, str]: AWS signing scheme in the first value and an empty string in the last to keep returns consistent.
        """
        if keytype == "ecdsa":
            aws_ecdsa_signing_algo = next(
                (
                    aws_ecdsa_signing_algo
                    for aws_ecdsa_signing_algo, local_scheme in keytypes_and_schemes.items()
                    if local_scheme == keytype_and_scheme
                ),
                None,
            )
            if aws_ecdsa_signing_algo is not None:
                return (aws_ecdsa_signing_algo, "")
        aws_rsa_signing_algo = AWSSigner._parse_rsa(
            keytypes_and_schemes,
            local_scheme,
            get_aws_signing_scheme=True,
        )
        return aws_rsa_signing_algo

    @staticmethod
    def _parse_rsa(
        keytypes_and_schemes: dict,
        local_scheme: str,
        get_aws_signing_scheme: bool = False,
    ) -> Tuple[str, str]:
        """
        Returns the correct key type and scheme or AWS signing algorithm for RSA keys.

        Arguments:
            keytypes_and_schemes (dict): A mapping of AWS KMS signing algorithms to key types and schemes.
            local_scheme (str): The Secure Systems Library signing scheme.
            get_aws_signing_scheme (bool, optional): Enables the return of an AWS signing algorithm for signing. Defaults to False.

        Returns:
            Tuple[str, str]: Tuple containing key type and signing scheme if get_aws_signing_scheme is False.
            Tuple[str, str]: Tuple containing the AWS signing scheme for the first value and an empty string in the last to keep returns consistent if get_aws_signing_scheme is True.
        """
        for algo in keytypes_and_schemes:
            algo_parts = algo.split("_")
            algo_prefix = algo_parts[0].lower()
            if algo_parts[1] == "PSS":
                padding = algo_parts[1].lower()
                sha = algo_parts[3].lower()
                sslib_pss_algo = f"{algo_prefix}-{padding}-sha{sha}"
                if (
                    sslib_pss_algo == local_scheme
                    and not get_aws_signing_scheme
                ):
                    return "rsa", sslib_pss_algo
                if sslib_pss_algo == local_scheme and get_aws_signing_scheme:
                    return (algo, "")
            elif algo_parts[1] == "PKCS1":
                padding = f"{algo_parts[1].lower()}{algo_parts[2].lower()}{algo_parts[3].lower()}"
                sha = algo_parts[5].lower()
                sslib_pkcs_algo = f"rsa-{padding}-sha{sha}"
                if (
                    sslib_pkcs_algo == local_scheme
                    and not get_aws_signing_scheme
                ):
                    return "rsa", sslib_pkcs_algo
                if sslib_pkcs_algo == local_scheme and get_aws_signing_scheme:
                    return (algo, "")
        # If no matching signing algorithm is found, raise an exception
        raise exceptions.UnsupportedAlgorithmError(
            f"Unsupported signing algorithm: {local_scheme[1]}"
        )

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
            BotoCoreError: Errors from the botocore.exceptions library.
            ClientError: Errors related to AWS KMS client.

        Returns:
            Signature.
        """
        try:
            signing_algorithm = self.get_aws_algo[0]
            request = self.client.sign(
                KeyId=self.key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm=signing_algorithm,
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
