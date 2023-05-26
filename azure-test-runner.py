from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import AzureSigner, Key, Signer


def main():
    azure_key_vault = "azurekms://tsa-staging.vault.azure.net"
    azure_key_id = "tsa-leaf"

    data = ("data" * 8).encode("utf-8")
    signer = AzureSigner.from_priv_key_uri(
        azure_key_vault,
        azure_key_id
    )
    sig = signer.sign(data)

    print(sig)

if __name__ == "__main__":
    main()
