"""
This module confirms that signing using KMS keys works.

The purpose is to do a smoke test, not to exhaustively test every possible
key and environment combination.

For Google Cloud (GCP), the requirements to successfully test are:
* Google Cloud authentication details have to be available in the environment
* The key defined in the test has to be available to the authenticated user

NOTE: the filename is purposefully check_ rather than test_ so that tests are
only run when explicitly invoked: The tests can only pass on Securesystemslib
GitHub Action environment because of the above requirements.
"""

import unittest

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import GCPSigner, Key, Signer
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME, SSlibKey

# Temporarily enable ml-dsa keys so they can be parsed for this test.
# TODO: Remove this once ml-dsa is supported by default.
KEY_FOR_TYPE_AND_SCHEME[("ml-dsa", "ml-dsa-65/1")] = SSlibKey


class TestKMSKeys(unittest.TestCase):
    """Test that KMS keys can be used to sign."""

    keys_to_test = [
        # ECDSA key
        (
            "projects/python-tuf-kms/locations/global/keyRings/securesystemslib-tests/cryptoKeys/ecdsa-sha2-nistp256/cryptoKeyVersions/1",
            Key.from_dict(
                "ab45d8d98992a4128efaea284c7ef0459557db199aeadf237ae41b915b9b5a1c",
                {
                    "keytype": "ecdsa",
                    "scheme": "ecdsa-sha2-nistp256",
                    "keyval": {
                        "public": (
                            "-----BEGIN PUBLIC KEY-----\n"
                            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/ptvrXYuUc2ZaKssHhtg/IKNbO1X\n"
                            "cDWlbKqLNpaK62MKdOwDz1qlp5AGHZkTY9tO09iq1F16SvVot1BQ9FJ2dw==\n"
                            "-----END PUBLIC KEY-----\n"
                        )
                    },
                },
            ),
        ),
        # ML-DSA-65 key
        (
            "projects/python-tuf-kms/locations/global/keyRings/securesystemslib-tests/cryptoKeys/ml-dsa-65/cryptoKeyVersions/1",
            Key.from_dict(
                "64b2c1923d4f6cf74910b560e1f14c21d057446e86f16d8c3588e10c4b7f01ce",
                {
                    "keytype": "ml-dsa",
                    "scheme": "ml-dsa-65/1",
                    "keyval": {
                        "public": (
                            "-----BEGIN PUBLIC KEY-----\n"
                            "MIIHsjALBglghkgBZQMEAxIDggehADELwmjdUsZ9Y6I9pbMfhYBDpDrEDlBr9g0X\n"
                            "JL5H547U2migKioZLCgLaYREqcLH7B/K5YUci40TadejM+8TOQ0wVs0zjymewEfD\n"
                            "53DOgaiTSWyUlAvjNPvFQn/HPQTXenbty4Jh98TDkrJXB5Y/UOuklvW05FhpoDzE\n"
                            "EXzillKm7RuUjkD3Hqg5RRGPcbshsVvqpdICCu+gCAw0pVxDVHc5v2d0xuB7QD68\n"
                            "nlaeteHN0moRp+W0swjRMCy/UYX9QcMwUoS3Vct2hes3b+QhnSbWSrRD7qxlH9m/\n"
                            "bzzD/CC48mnOpV04CCKZ5Kp5z+PgUWwAO7/eCELNS4DgiYt6su9Fli0Ugpd0fd9K\n"
                            "eRhghB7A/lPQ4OXDfuo/Q+lMhAUseLKOcDancNEiUCjfkVMAfU9O5pbu0ZQcYR5Z\n"
                            "icVzlkVaW2Acwn/G+ZQ151PL2NwMT12TLzX7jEOVlOsTKRBrQtkv5Y9hYl53RQB1\n"
                            "fulv0jlfhL5tWoe1anLTqB4pEJecof0MIua/6sOumv3CFt2vQniMl9nKibR6WiqO\n"
                            "GDaz7fz2Y3XTxAoxeNT36ScRSB8Fea7xp/mifj3XdYIQ5zRSvfFEYA0tC9W+KMdQ\n"
                            "do0HJhV5tQwg9UJuqN5btsrdmRRCv7M5L8m88Mw/qxx8zrliz2mqYA1MRZiigQjW\n"
                            "EDY21pfYwGv9Fx7uUyzpK/Vev4qxtnyHPCw2jWdyplKnPbwlmadPHhje012RcK9U\n"
                            "OJVJC53Q7aiX5ASYK8BtbKJGBveeeJZmiWivxSm1F6Y3OygNWVTXWfy3wDtpCse6\n"
                            "rFn8O3MtzltKJJ28g3Tl3ywivS52ic9bUA5ksvgExtrJK036X6LsXnHsRSZTSauT\n"
                            "X64ygioMCLqycN3c/lLc4zVptLnzAF2sRaefjywObiZ3JPBTPNF9zHDeuaZCcIIk\n"
                            "tOh2NR86t2SY9MWUSV2lT/KKmpk+1ZQpJaMAuCqpyjCbdo66U9dtmWsSpMzppzsX\n"
                            "9tXwh0Agv5a+TPMgeexgKWzZcjxIQw7o2xRPcUYK6Cq1rE8PxKWEAKQYHuvt3nPK\n"
                            "pA/b2nJpsk+dMyfjTkYqtCyb9t00YBpY7zi0nw8hYOp/x1MWUo+F276gkP3zqQ9H\n"
                            "kKzWRGj34Zqez0mUqyDzH/BqKBTFYzp8++TxMOFcEgCGfQp1Jul/dVkju4n27Xn4\n"
                            "JY78xW9ojz9WjEaAUjL8Fkpnc96AV1jkXd/PWOCqDjdmvxMGi9oYE2icvFrpNI62\n"
                            "mzOBz0nBVV3IHdmIgD3BKxJJz4ZJfDvCsqsbTnArSsjmxtolqi1mz1yXkDbgfnCx\n"
                            "hOhsW5E6ATONsosNQY1QGfGNQEdL/bqyKZSQFOww6WhL/EfWBBjbpiUHscebaHFg\n"
                            "PsxjS/d8Z9frqUACxJhQ8JHGGQz8a5LOJRvYvQVZFOYMjwMiV9pDrOUWsXlmW58f\n"
                            "1XayxSmqaoYQZnaco008EEiQ9M3mdV0aW+xwrSk33cW4hfs//GvOz0/Fil3ouNOx\n"
                            "rWP9r0N9QjxR0p+IbFCGaZ9bObN6IC4/tmEwDEha2Iunozd+N++tbQwfvuPNfAYw\n"
                            "CkZeHQYqm+cW5FbOx6DW3CuUYUJ8XZEwtI4rPMpg6gVsg8KgCRQI0JjLkiGgRGEj\n"
                            "cNWCMu2D+HbTtKIefktFPhinAR1U8NVLk0fmzlM0wAG0qVWSLtlh9sWMhAn3ai4K\n"
                            "XTgutM9vICwR1PTk6VNmcusPuvnQGJCxyySlXu/1FaAGe3Na+LN5KClV2L59xzND\n"
                            "/ImqX/zMfFyPjahYKKoy5B2XDH1/NZtus/BRknek6Hq/zBEuOzvvNmhbpvJxRekP\n"
                            "6C+5ent/hZWWwUP/aD6hnyDUPpZ+008UcTToe6G3LGbrdv7Qd5w56xwK98SFqqG7\n"
                            "YT2o7WYtkdt4MRekFHhhtHtc3NvrIsK5wJu6H5IRHiheQnxvNiCvcGH1z5fTUNjj\n"
                            "Dz2uvSsRj5aLdWWI29Yk7/0HF8s6eIm8UQeGU+fzS+dXXlFjlec6+V5VXZEULcVh\n"
                            "D7oXVolwuts+NZdztozhrRpKdgt8h8D8CUgK9SRJjhEBYJ87903d92sYsb+orw70\n"
                            "3+rGV+UNsdvN694slq4oBwmv6aYrRVpoT6BHn/Jpwd9rKzCrfmBx0hSF14XCH3eq\n"
                            "Vnc7uEfVLeVJlseh80wY/618SRlLciZwvXKUEM+Jq22xn+CqBY8WPA/vgBxV2QoG\n"
                            "qcpZq59EkdJYub4lCGxRgWtzdsoyjD3NBfTJaqSxRQysw0xWZ9PStFrjX+SPyNeF\n"
                            "YUD/NFzPXhflZJZoZ5RX7Ow82TuDXPUCqZOL7kedAxy57laRAR7ZDMm/2dNnysRb\n"
                            "NP+MjapE7k4q2+A3l7FxZved4Ng7YttXCwBxcoR0Dj8Vi5kdJ7cMlECYoG1rtbAx\n"
                            "iqzj6jTO6X23/u210iH5tMX+NxM9ioZPZb9w9bkEGjNgNQws74QSROPUfSikLW2g\n"
                            "vZCvs4Ix14Ku3fiWdLjp2sm3A3prvh9pOHNta8xZzqcS6qZ8Uql+CQgLDVGMiSm9\n"
                            "phzIVQGDfHi+Lle1e2CiYsQ9p9axenXg+rRndMrTnX1pVtKJxoFkktyjaoXaaJeg\n"
                            "BQ2MpA4q\n"
                            "-----END PUBLIC KEY-----\n"
                        )
                    },
                },
            ),
        ),
    ]

    def test_gcp_sign(self):
        """Test that GCP KMS key works for signing"""
        data = b"data"
        for gcp_id, pubkey in self.keys_to_test:
            with self.subTest(scheme=pubkey.scheme):
                signer = Signer.from_priv_key_uri(f"gcpkms:{gcp_id}", pubkey)
                sig = signer.sign(data)

                pubkey.verify_signature(sig, data)
                with self.assertRaises(UnverifiedSignatureError):
                    pubkey.verify_signature(sig, b"NOT DATA")

    def test_gcp_import(self):
        """Test that GCP KMS key can be imported"""
        for gcp_id, pubkey in self.keys_to_test:
            with self.subTest(scheme=pubkey.scheme):
                uri, key = GCPSigner.import_(gcp_id)
                self.assertEqual(key, pubkey)
                self.assertEqual(uri, f"gcpkms:{gcp_id}")


if __name__ == "__main__":
    unittest.main(verbosity=1, buffer=True)
