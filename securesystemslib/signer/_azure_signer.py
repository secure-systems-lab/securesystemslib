"""Signer implementation for Azure Key Vault"""

from typing import Optional
from urllib import parse

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import (
    KeyClient,
    KeyVaultKey
)
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import (
    SecretsHandler,
    Signature,
    Signer,
)
from azure.keyvault.keys.crypto import SignatureAlgorithm

class AzureSigner(Signer):
    """Azure Key Vault Signer

    This Signer uses Azure Key Vault to sign.

    The specific permissions that AzureSigner needs are:
    * todo:add roles

    Arguments:
        az_keyvaultid: Fully qualified Azure Key Vault name, like
            azurekms://<vault-name>.vault.azure.net
        az_keyid: Fully qualified Azure Key Vault key name, like
            azurekms://<vault-name>.vault.azure.net/<key-name>

    Raises:
        Various errors from azure.identity
        Various errors from azure.keyvault.keys
    """

    SCHEME = "azurekms"

    def __init__(self, az_keyvaultid: str, az_keyid: str):
        self.az_keyid = az_keyid
        credential = DefaultAzureCredential()

        # az vault is on form: azurekms:// but key client expects https://
        vault_url = az_keyvaultid.replace("azurekms:", "https:")

        key_client = KeyClient(vault_url=vault_url, credential=credential)
        self.key_client = key_client

        key_vault_key = key_client.get_key(az_keyid)
        crypto_client = CryptographyClient(key_vault_key, credential=credential)

        self.crypto_client = crypto_client
        self.signature_algorithm = self._get_signature_algorithm(key_vault_key)

    @staticmethod
    def _get_signature_algorithm(kvk: KeyVaultKey) -> SignatureAlgorithm:
        key_curve_name = kvk.key.crv
        if key_curve_name == KeyCurveName.p_256:
            return SignatureAlgorithm.es256
        elif KeyCurveName.p_384:
            return SignatureAlgorithm.es384
        elif KeyCurveName.p_521:
            return SignatureAlgorithm.es512
        else:
            print("unsupported curve supplied")

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

        result = self.crypto_client.sign(SignatureAlgorithm.es256, payload)

        return Signature(result.keyid, result.signature.hex())
