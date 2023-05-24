"""Signer implementation for Azure Key Vault"""

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import (
    KeyClient,
    KeyVaultKey
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
        self.public_key = public_key

        credential = DefaultAzureCredential()
        key_client = KeyClient(vault_url=az_keyvaultid, credential=credential)
        self.key_client = key_client

        key_vault_key = key_client.get_key(az_keyid)
        crypto_client = CryptographyClient(key_vault_key, credential=credential)
        
        self.crypto_client = crypto_client
        self.signature_algorithm = self._get_signature_algorithm(key_vault_key)

    @staticmethod
    def _get_signature_algorithm(key: KeyVaultKey) -> SignatureAlgorithm:
        key_curve_name = keyVaultKey.key.crv
        match key_curve_name:
            case KeyCurveName.p_256:
                return SignatureAlgorithm.es256
            case KeyCurveName.p_384:
                return SignatureAlgorithm.es384
            case KeyCurveName.p_521:
                return SignatureAlgorithm.es512
            case _:
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

        return cls(uri.path, public_key)

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Azure Key Vault.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from azure.keyvault.keys.

        Returns:
            Signature.
        """

        result = crypto_client.sign(SignatureAlgorithm.es256, payload)

        return Signature(result.keyid, result.signature.hex())
