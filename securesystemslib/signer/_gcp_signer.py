"""Signer implementation for Google Cloud KMS"""

from __future__ import annotations

import logging
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib import exceptions
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer
from securesystemslib.signer._utils import compute_default_keyid

logger = logging.getLogger(__name__)

GCP_IMPORT_ERROR = None
try:
    from google.cloud import kms
    from google.cloud.kms_v1.types import CryptoKeyVersion
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
    https://cloud.google.com/docs/authentication/getting-started.
    Some practical authentication options include:
    * GitHub Action: https://github.com/google-github-actions/auth
    * gcloud CLI: https://cloud.google.com/sdk/gcloud

    The specific permissions that GCPSigner needs are:
    * roles/cloudkms.signer for sign()
    * roles/cloudkms.publicKeyViewer for import()

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
        self._public_key = public_key
        self.client = kms.KeyManagementServiceClient()

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> GCPSigner:
        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"GCPSigner does not support {priv_key_uri}")

        return cls(uri.path, public_key)

    @classmethod
    def import_(cls, gcp_keyid: str) -> tuple[str, Key]:
        """Load key and signer details from KMS

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.
        """
        if GCP_IMPORT_ERROR:
            raise exceptions.UnsupportedLibraryError(GCP_IMPORT_ERROR)

        client = kms.KeyManagementServiceClient()
        request = {"name": gcp_keyid}
        kms_pubkey = client.get_public_key(request)
        try:
            keytype, scheme = cls._get_keytype_and_scheme(kms_pubkey.algorithm)
        except KeyError as e:
            raise exceptions.UnsupportedAlgorithmError(
                f"{kms_pubkey.algorithm} is not a supported signing algorithm"
            ) from e

        keyval = {"public": kms_pubkey.pem}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        public_key = SSlibKey(keyid, keytype, scheme, keyval)

        return f"{cls.SCHEME}:{gcp_keyid}", public_key

    @staticmethod
    def _get_keytype_and_scheme(algorithm: int) -> tuple[str, str]:
        """Return keytype and scheme for the KMS algorithm enum"""
        keytypes_and_schemes = {
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256: (
                "ecdsa",
                "ecdsa-sha2-nistp256",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384: (
                "ecdsa",
                "ecdsa-sha2-nistp384",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256: (
                "rsa",
                "rsassa-pss-sha256",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256: (
                "rsa",
                "rsassa-pss-sha256",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256: (
                "rsa",
                "rsassa-pss-sha256",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA512: (
                "rsa",
                "rsassa-pss-sha512",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256: (
                "rsa",
                "rsa-pkcs1v15-sha256",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256: (
                "rsa",
                "rsa-pkcs1v15-sha256",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256: (
                "rsa",
                "rsa-pkcs1v15-sha256",
            ),
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512: (
                "rsa",
                "rsa-pkcs1v15-sha512",
            ),
        }
        return keytypes_and_schemes[algorithm]

    @staticmethod
    def _get_hash_algorithm(public_key: Key) -> str:
        """Helper function to return payload hash algorithm used for this key"""

        # TODO: This could be a public abstract method on Key so that GCPSigner
        # would not be tied to a specific Key implementation -- not all keys
        # have a pre hash algorithm though.
        if public_key.keytype == "rsa":
            # hash algorithm is encoded as last scheme portion
            algo = public_key.scheme.split("-")[-1]
        elif public_key.keytype in [
            "ecdsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
        ]:
            # nistp256 uses sha-256, nistp384 uses sha-384
            bits = public_key.scheme.split("-nistp")[-1]
            algo = f"sha{bits}"
        else:
            raise exceptions.UnsupportedAlgorithmError(
                f"Unsupported key type {public_key.keytype} in key {public_key.keyid}"
            )

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
