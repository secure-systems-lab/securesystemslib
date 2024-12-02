"""Signer implementation for Azure Key Vault"""

from __future__ import annotations

import logging
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer
from securesystemslib.signer._utils import compute_default_keyid

AZURE_IMPORT_ERROR = None
try:
    from azure.core.exceptions import HttpResponseError
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.keys import KeyClient, KeyCurveName, KeyVaultKey
    from azure.keyvault.keys.crypto import (
        CryptographyClient,
        SignatureAlgorithm,
    )
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
except ImportError:
    AZURE_IMPORT_ERROR = (
        "Signing with Azure Key Vault requires azure-identity, "
        "azure-keyvault-keys and cryptography."
    )

logger = logging.getLogger(__name__)


class UnsupportedKeyType(Exception):  # noqa: N818
    pass


class AzureSigner(Signer):
    """Azure Key Vault Signer

    This Signer uses Azure Key Vault to sign.
    Currently this signer only supports signing with EC keys.
    RSA support will be added in a separate pull request.

    The specific permissions that AzureSigner needs are:
    * "Key Vault Crypto User" for import() and sign()

    See https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli
    for a list of all built-in Azure Key Vault roles

    Arguments:
        az_key_uri: Fully qualified Azure Key Vault name, like
            https://<vault-name>.vault.azure.net/keys/<key-name>/<version>
        public_key: public key object

    Raises:
        Various errors from azure.identity
        Various errors from azure.keyvault.keys
    """

    SCHEME = "azurekms"

    def __init__(self, az_key_uri: str, public_key: Key):
        if AZURE_IMPORT_ERROR:
            raise UnsupportedLibraryError(AZURE_IMPORT_ERROR)

        try:
            cred = DefaultAzureCredential()
            self.crypto_client = CryptographyClient(
                az_key_uri,
                credential=cred,
            )
            self.signature_algorithm = self._get_signature_algorithm(
                public_key,
            )
            self.hash_algorithm = self._get_hash_algorithm(public_key)
        except UnsupportedKeyType as e:
            logger.info("Key %s has unsupported key type or unsupported elliptic curve")
            raise e
        self._public_key = public_key

    @property
    def public_key(self) -> Key:
        return self._public_key

    @staticmethod
    def _get_key_vault_key(
        cred: DefaultAzureCredential,
        vault_name: str,
        key_name: str,
    ) -> KeyVaultKey:
        """Return KeyVaultKey created from the Vault name and key name"""
        vault_url = f"https://{vault_name}.vault.azure.net/"

        try:
            key_client = KeyClient(vault_url=vault_url, credential=cred)
            return key_client.get_key(key_name)
        except (HttpResponseError,) as e:
            logger.info(
                "Key %s/%s failed to create key client from credentials, "
                "key ID, and Vault URL: %s",
                vault_name,
                key_name,
                str(e),
            )
            raise e

    @staticmethod
    def _create_crypto_client(
        cred: DefaultAzureCredential,
        kv_key: KeyVaultKey,
    ) -> CryptographyClient:
        """Return CryptographyClient created Azure credentials and a KeyVaultKey"""
        try:
            return CryptographyClient(kv_key, credential=cred)
        except (HttpResponseError,) as e:
            logger.info(
                "Key %s failed to create crypto client from "
                "credentials and KeyVaultKey: %s",
                kv_key,
                str(e),
            )
            raise e

    @staticmethod
    def _get_signature_algorithm(public_key: Key) -> SignatureAlgorithm:
        """Return SignatureAlgorithm after parsing the public key"""
        if public_key.keytype != "ecdsa":
            logger.info("only EC keys are supported for now")
            raise UnsupportedKeyType("Supplied key must be an EC key")
        # Format is "ecdsa-sha2-nistp256"
        comps = public_key.scheme.split("-")
        if len(comps) != 3:  # noqa: PLR2004
            raise UnsupportedKeyType("Invalid scheme found")

        if comps[2] == "nistp256":
            return SignatureAlgorithm.es256
        if comps[2] == "nistp384":
            return SignatureAlgorithm.es384
        if comps[2] == "nistp521":
            return SignatureAlgorithm.es512

        raise UnsupportedKeyType("Unsupported curve supplied by key")

    @staticmethod
    def _get_hash_algorithm(public_key: Key) -> str:
        """Return the hash algorithm used by the public key"""
        # Format is "ecdsa-sha2-nistp256"
        comps = public_key.scheme.split("-")
        if len(comps) != 3:  # noqa: PLR2004
            raise UnsupportedKeyType("Invalid scheme found")

        if comps[2] == "nistp256":
            return "sha256"
        if comps[2] == "nistp384":
            return "sha384"
        if comps[2] == "nistp521":
            return "sha512"

        raise UnsupportedKeyType("Unsupported curve supplied by key")

    @staticmethod
    def _get_keytype_and_scheme(crv: str) -> tuple[str, str]:
        if crv == KeyCurveName.p_256:
            return "ecdsa", "ecdsa-sha2-nistp256"
        if crv == KeyCurveName.p_384:
            return "ecdsa", "ecdsa-sha2-nistp384"
        if crv == KeyCurveName.p_521:
            return "ecdsa", "ecdsa-sha2-nistp521"

        raise UnsupportedKeyType("Unsupported curve supplied by key")

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> AzureSigner:
        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"AzureSigner does not support {priv_key_uri}")

        az_key_uri = priv_key_uri.replace("azurekms:", "https:")
        return cls(az_key_uri, public_key)

    @classmethod
    def import_(cls, az_vault_name: str, az_key_name: str) -> tuple[str, Key]:
        """Load key and signer details from KMS

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.
        """
        if AZURE_IMPORT_ERROR:
            raise UnsupportedLibraryError(AZURE_IMPORT_ERROR)

        credential = DefaultAzureCredential()
        key_vault_key = cls._get_key_vault_key(credential, az_vault_name, az_key_name)

        if not key_vault_key.key.kty.startswith("EC"):
            raise UnsupportedKeyType(f"Unsupported key type {key_vault_key.key.kty}")

        if key_vault_key.key.crv == KeyCurveName.p_256:
            crv: ec.EllipticCurve = ec.SECP256R1()
        elif key_vault_key.key.crv == KeyCurveName.p_384:
            crv = ec.SECP384R1()
        elif key_vault_key.key.crv == KeyCurveName.p_521:
            crv = ec.SECP521R1()
        else:
            raise UnsupportedKeyType(f"Unsupported curve type {key_vault_key.key.crv}")

        # Key is in JWK format, create a curve from it with the parameters
        x = int.from_bytes(key_vault_key.key.x, byteorder="big")
        y = int.from_bytes(key_vault_key.key.y, byteorder="big")

        cpub = ec.EllipticCurvePublicNumbers(x, y, crv)
        pub_key = cpub.public_key()
        pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        keytype, scheme = cls._get_keytype_and_scheme(key_vault_key.key.crv)
        keyval = {"public": pem.decode("utf-8")}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        public_key = SSlibKey(keyid, keytype, scheme, keyval)
        priv_key_uri = key_vault_key.key.kid.replace("https:", "azurekms:")

        return priv_key_uri, public_key

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Azure Key Vault.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from azure.keyvault.keys.

        Returns:
            Signature.
        """

        hasher = sslib_hash.digest(self.hash_algorithm)
        hasher.update(payload)
        digest = hasher.digest()
        response = self.crypto_client.sign(self.signature_algorithm, digest)

        # This code is copied from:
        # https://github.com/secure-systems-lab/securesystemslib/blob/135567fa04f10d0c6a4cd32eb45ce736e1f50a93/securesystemslib/signer/_hsm_signer.py#L379
        #
        # The PKCS11 signature octets correspond to the concatenation of the
        # ECDSA values r and s, both represented as an octet string of equal
        # length of at most nLen with the most significant byte first (i.e.
        # big endian)
        # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
        r_s_len = int(len(response.signature) / 2)
        r = int.from_bytes(response.signature[:r_s_len], byteorder="big")
        s = int.from_bytes(response.signature[r_s_len:], byteorder="big")

        # Create an ASN.1 encoded Dss-Sig-Value to be used with
        # pyca/cryptography
        dss_sig_value = encode_dss_signature(r, s).hex()

        return Signature(self.public_key.keyid, dss_sig_value)
