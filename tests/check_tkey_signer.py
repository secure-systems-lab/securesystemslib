import unittest

from securesystemslib.signer import Signer, TKeySigner


class TestTKeySigner(unittest.TestCase):
    def test_tkey_signer_import_and_sign(self) -> None:
        """This test requires
        * a physical Tillitis TKey to be connected
        * a touch on the key when it blinks green
        """

        def passphrase(_: str) -> str:
            return "hunter2"

        uri, pub_key = TKeySigner.import_(passphrase="hunter2")

        self.assertEqual(pub_key.keytype, "ml-dsa")
        self.assertEqual(pub_key.scheme, "ml-dsa-44/1")
        self.assertTrue(uri.startswith("tkey:"))
        self.assertTrue("digest=" in uri)
        self.assertTrue("passphrase=true" in uri)

        # Get a signer from standard Signer factory, sign
        signer = Signer.from_priv_key_uri(uri, pub_key, passphrase)
        signature = signer.sign(b"PQC!")

        pub_key.verify_signature(signature, b"PQC!")


if __name__ == "__main__":
    unittest.main()
