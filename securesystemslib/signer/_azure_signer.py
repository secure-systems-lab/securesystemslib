"""Signer implementation for Azure Key Vault"""

import binascii

from typing import Optional
from urllib import parse

import logging
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import (
    KeyClient,
    KeyVaultKey,
    KeyCurveName,
    KeyType,
)
from azure.keyvault.keys.crypto import (
    CryptographyClient,
    SignatureAlgorithm
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)
import securesystemslib.hash as sslib_hash
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import (
    SecretsHandler,
    Signature,
    Signer,
)

logger = logging.getLogger(__name__)

class UnsupportedKeyType(Exception):
    pass

class AzureSigner(Signer):
    """Azure Key Vault Signer

    This Signer uses Azure Key Vault to sign.
    Currently this signer only supports signing with EC keys.
    RSA support will be added in a separate pull request.

    Arguments:
        az_keyvaultid: Fully qualified Azure Key Vault name, like
            azurekms://<vault-name>.vault.azure.net
        az_keyid: Azure Key Vault key name

    Raises:
        Various errors from azure.identity
        Various errors from azure.keyvault.keys
    """

    SCHEME = "azurekms"

    def __init__(self, az_keyvaultid: str, az_keyid: str):
        try:
            credential = DefaultAzureCredential()
            # az vault is on form: azurekms:// but key client expects https://
            vault_url = az_keyvaultid.replace("azurekms:", "https:")

            key_vault_key = self._create_key_vault_key(credential, az_keyid, vault_url)
            self.signature_algorithm = self._get_signature_algorithm(key_vault_key)
            self.hash_algorithm = self._get_hash_algorithm(key_vault_key)
            self.crypto_client = self._create_crypto_client(credential, key_vault_key)
        except UnsupportedKeyType as e:
            logger.info("Key %s has unsupported key type or unsupported elliptic curve")

    @staticmethod
    def _create_key_vault_key(cred: DefaultAzureCredential, az_keyid: str, vault_url: str) -> KeyVaultKey:
        try:
            key_client = KeyClient(vault_url=vault_url, credential=cred)
            return key_client.get_key(az_keyid)
        except (
            HttpResponseError,
        ) as e:
            logger.info("Key %s failed to create key client from credentials, key ID, and Vault URL: %s", az_keyid, str(e))

    @staticmethod
    def _create_crypto_client(cred: DefaultAzureCredential, kv_key: KeyVaultKey) -> CryptographyClient:
        try:
            return CryptographyClient(kv_key, credential=cred)
        except (
            HttpResponseError,
        ) as e:
            logger.info("Key %s failed to create crypto client from credentials and KeyVaultKey: %s", az_keyid, str(e))

    @staticmethod
    def _get_signature_algorithm(kvk: KeyVaultKey) -> SignatureAlgorithm:
        key_type = kvk.key.kty
        if key_type != KeyType.ec and key_type != KeyType.ec_hsm:
            logger.info("only EC keys are supported for now")
            raise UnsupportedKeyType("Supplied key must be an EC key")
        key_curve_name = kvk.key.crv
        if key_curve_name == KeyCurveName.p_256:
            return SignatureAlgorithm.es256
        elif KeyCurveName.p_384:
            return SignatureAlgorithm.es384
        elif KeyCurveName.p_521:
            return SignatureAlgorithm.es512
        else:
            raise UnsupportedKeyType("Unsupported curve supplied by key")

    @staticmethod
    def _get_hash_algorithm(kvk: KeyVaultKey) -> str:
        key_curve_name = kvk.key.crv
        if key_curve_name == KeyCurveName.p_256:
            return "sha256"
        elif KeyCurveName.p_384:
            return "sha384"
        elif KeyCurveName.p_521:
            return "sha512"
        else:
            logger.info("unsupported curve supplied")
            # trigger UnsupportedAlgorithm if appropriate
            _ = sslib_hash.digest("")

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "AzureSigner":
        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"AzureSigner does not support {priv_key_uri}")

        return cls(priv_key_uri, public_key)

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
        dss_sig_value = binascii.hexlify(encode_dss_signature(r, s)).decode(
            "ascii"
        )

        return Signature(response.key_id, dss_sig_value)
