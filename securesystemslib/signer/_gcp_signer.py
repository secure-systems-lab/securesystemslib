"""Signer implementation for Google Cloud KMS"""

import logging
from typing import Optional
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib import exceptions
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer

logger = logging.getLogger(__name__)

GCP_IMPORT_ERROR = None
try:
    from google.cloud import kms
except ImportError:
    GCP_IMPORT_ERROR = (
        "google-cloud-kms library required to sign with Google Cloud keys."
    )


class GCPSigner(Signer):
    """Google Cloud KMS Signer

    This Signer uses Google Cloud KMS to sign: the payload is hashed locally,
    but the signature is created on the KMS.

    The signer uses "ambient" credentials: typically environment var
    GOOGLE_APPLICATION_CREDENTIALS that points to a file with valid
    credentials. These will be found by google.cloud.kms, see
    https://cloud.google.com/docs/authentication/getting-started
    (and https://github.com/google-github-actions/auth for the relevant
    GitHub action).

    Arguments:
        gcp_keyid: Fully qualified GCP KMS key name, like
            projects/python-tuf-kms/locations/global/keyRings/securesystemslib-tests/cryptoKeys/ecdsa-sha2-nistp256/cryptoKeyVersions/1
        public_key: The related public key instance

    Raises:
        UnsupportedAlgorithmError: The payload hash algorithm is unsupported.
        UnsupportedLibraryError: google.cloud.kms was not found
        Various errors from google.cloud modules: e.g.
            google.auth.exceptions.DefaultCredentialsError if ambient
            credentials are not found
    """

    SCHEME = "gcpkms"

    def __init__(self, gcp_keyid: str, public_key: Key):
        if GCP_IMPORT_ERROR:
            raise exceptions.UnsupportedLibraryError(GCP_IMPORT_ERROR)

        self.hash_algorithm = self._get_hash_algorithm(public_key)
        self.gcp_keyid = gcp_keyid
        self.public_key = public_key
        self.client = kms.KeyManagementServiceClient()

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "GCPSigner":
        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"GCPSigner does not support {priv_key_uri}")

        return cls(uri.path, public_key)

    @staticmethod
    def _get_hash_algorithm(public_key: Key) -> str:
        """Helper function to return payload hash algorithm used for this key"""

        # TODO: This could be a public abstract method on Key so that GCPSigner
        # would not be tied to a specific Key implementation -- not all keys
        # have a pre hash algorithm though.
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
        """Signs payload with Google Cloud KMS.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from google.cloud modules.

        Returns:
            Signature.
        """
        # NOTE: request and response can contain CRC32C of the digest/sig:
        # Verifying could be useful but would require another dependency...

        hasher = sslib_hash.digest(self.hash_algorithm)
        hasher.update(payload)
        digest = {self.hash_algorithm: hasher.digest()}
        request = {"name": self.gcp_keyid, "digest": digest}

        logger.debug("signing request %s", request)
        response = self.client.asymmetric_sign(request)
        logger.debug("signing response %s", response)

        return Signature(self.public_key.keyid, response.signature.hex())
