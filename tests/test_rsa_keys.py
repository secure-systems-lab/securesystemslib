"""
<Program Name>
  test_rsa_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 3, 2015.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for 'rsa_keys.py'.
"""

import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.hash
import securesystemslib.keys
import securesystemslib.rsa_keys

(
    public_rsa,
    private_rsa,
) = securesystemslib.rsa_keys.generate_rsa_public_and_private()
FORMAT_ERROR_MSG = (
    "securesystemslib.exceptions.FormatError raised.  Check object's format."
)


class TestRSA_keys(
    unittest.TestCase
):  # pylint: disable=missing-class-docstring,invalid-name
    def setUp(self):
        pass

    def test_generate_rsa_public_and_private(self):
        pub, priv = securesystemslib.rsa_keys.generate_rsa_public_and_private()

        # Check format of 'pub' and 'priv'.
        self.assertEqual(
            None,
            securesystemslib.formats.PEMRSA_SCHEMA.check_match(pub),
            FORMAT_ERROR_MSG,
        )
        self.assertEqual(
            None,
            securesystemslib.formats.PEMRSA_SCHEMA.check_match(priv),
            FORMAT_ERROR_MSG,
        )

        # Check for an invalid "bits" argument.  bits >= 2048.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.rsa_keys.generate_rsa_public_and_private,
            1024,
        )

        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.rsa_keys.generate_rsa_public_and_private,
            "2048",
        )

    def test_create_rsa_signature(self):
        global private_rsa  # pylint: disable=global-variable-not-assigned
        global public_rsa  # pylint: disable=global-variable-not-assigned
        data = "The quick brown fox jumps over the lazy dog".encode("utf-8")

        for rsa_scheme in securesystemslib.keys.RSA_SIGNATURE_SCHEMES:
            signature, scheme = securesystemslib.rsa_keys.create_rsa_signature(
                private_rsa, data, rsa_scheme
            )

            # Verify format of returned values.
            self.assertNotEqual(None, signature)
            self.assertEqual(
                None,
                securesystemslib.formats.RSA_SCHEME_SCHEMA.check_match(scheme),
                FORMAT_ERROR_MSG,
            )
            self.assertEqual(rsa_scheme, scheme)

            # Check for improperly formatted arguments.
            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.create_rsa_signature,
                123,
                data,
            )

            # Check for an unset private key.
            self.assertRaises(
                ValueError,
                securesystemslib.rsa_keys.create_rsa_signature,
                "",
                data,
            )

            # Check for an invalid PEM.
            self.assertRaises(
                securesystemslib.exceptions.CryptoError,
                securesystemslib.rsa_keys.create_rsa_signature,
                "123",
                data,
            )

            # Check for invalid 'data'.
            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.create_rsa_signature,
                private_rsa,
                "",
            )

            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.create_rsa_signature,
                private_rsa,
                123,
            )

            # Check for a missing private key.
            self.assertRaises(
                securesystemslib.exceptions.CryptoError,
                securesystemslib.rsa_keys.create_rsa_signature,
                public_rsa,
                data,
            )

            # Check for a TypeError by attempting to create a signature with an
            # encrypted key.
            encrypted_pem = securesystemslib.rsa_keys.create_rsa_encrypted_pem(
                private_rsa, "pw"
            )
            self.assertRaises(
                securesystemslib.exceptions.CryptoError,
                securesystemslib.rsa_keys.create_rsa_signature,
                encrypted_pem,
                data,
            )

    def test_verify_rsa_signature(self):
        global public_rsa  # pylint: disable=global-variable-not-assigned
        global private_rsa  # pylint: disable=global-variable-not-assigned
        data = "The quick brown fox jumps over the lazy dog".encode("utf-8")

        for rsa_scheme in securesystemslib.keys.RSA_SIGNATURE_SCHEMES:
            signature, scheme = securesystemslib.rsa_keys.create_rsa_signature(
                private_rsa, data, rsa_scheme
            )

            valid_signature = securesystemslib.rsa_keys.verify_rsa_signature(
                signature, scheme, public_rsa, data
            )
            self.assertEqual(True, valid_signature)

            # Check for an invalid public key.
            self.assertRaises(
                securesystemslib.exceptions.CryptoError,
                securesystemslib.rsa_keys.verify_rsa_signature,
                signature,
                scheme,
                private_rsa,
                data,
            )

            # Check for improperly formatted arguments.
            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.verify_rsa_signature,
                signature,
                123,
                public_rsa,
                data,
            )

            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.verify_rsa_signature,
                signature,
                scheme,
                123,
                data,
            )

            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.verify_rsa_signature,
                123,
                scheme,
                public_rsa,
                data,
            )

            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.verify_rsa_signature,
                signature,
                "invalid_scheme",
                public_rsa,
                data,
            )

            # Check for invalid 'signature' and 'data' arguments.
            self.assertRaises(
                securesystemslib.exceptions.FormatError,
                securesystemslib.rsa_keys.verify_rsa_signature,
                signature,
                scheme,
                public_rsa,
                123,
            )

            self.assertEqual(
                False,
                securesystemslib.rsa_keys.verify_rsa_signature(
                    signature, scheme, public_rsa, b"mismatched data"
                ),
            )

            (
                mismatched_signature,
                scheme,
            ) = securesystemslib.rsa_keys.create_rsa_signature(
                private_rsa, b"mismatched data"
            )

            self.assertEqual(
                False,
                securesystemslib.rsa_keys.verify_rsa_signature(
                    mismatched_signature, scheme, public_rsa, data
                ),
            )

    def test_verify_rsa_pss_different_salt_lengths(self):
        rsa_scheme = "rsassa-pss-sha256"
        data = "The ancients say, salt length does not matter that much".encode(
            "utf-8"
        )

        private_key = load_pem_private_key(
            private_rsa.encode("utf-8"),
            password=None,
            backend=default_backend(),
        )
        digest = securesystemslib.hash.digest_from_rsa_scheme(
            rsa_scheme, "pyca_crypto"
        )

        # Make sure digest size and max salt length are not accidentally the same
        self.assertNotEqual(
            digest.algorithm.digest_size,
            padding.calculate_max_pss_salt_length(
                private_key, digest.algorithm
            ),
        )

        # Sign with max salt length (briefly available in sslib v0.24.0):
        max_salt_sig = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(digest.algorithm),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            digest.algorithm,
        )

        # Sign with salt length == digest length
        fix_salt_sig, _ = securesystemslib.rsa_keys.create_rsa_signature(
            private_rsa, data
        )

        # Verification infers salt length automatically and so works for both
        for signature in (max_salt_sig, fix_salt_sig):
            verified = securesystemslib.rsa_keys.verify_rsa_signature(
                signature, rsa_scheme, public_rsa, data
            )
            self.assertTrue(verified)

    def test_create_rsa_encrypted_pem(self):
        global public_rsa  # pylint: disable=global-variable-not-assigned
        global private_rsa  # pylint: disable=global-variable-not-assigned

        encrypted_pem = securesystemslib.rsa_keys.create_rsa_encrypted_pem(
            private_rsa, "password"
        )
        self.assertTrue(
            securesystemslib.formats.PEMRSA_SCHEMA.matches(encrypted_pem)
        )

        # Test for invalid private key (via PEM).
        self.assertRaises(
            securesystemslib.exceptions.CryptoError,
            securesystemslib.rsa_keys.create_rsa_encrypted_pem,
            public_rsa,
            "password",
        )

        # Test for invalid arguments.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.rsa_keys.create_rsa_encrypted_pem,
            public_rsa,
            123,
        )

        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.rsa_keys.create_rsa_encrypted_pem,
            123,
            "password",
        )

        self.assertRaises(
            ValueError,
            securesystemslib.rsa_keys.create_rsa_encrypted_pem,
            "",
            "password",
        )

    def test_create_rsa_public_and_private_from_pem(self):
        global public_rsa  # pylint: disable=global-variable-not-assigned
        global private_rsa  # pylint: disable=global-variable-not-assigned

        (
            public,
            private,
        ) = securesystemslib.rsa_keys.create_rsa_public_and_private_from_pem(
            private_rsa
        )

        self.assertTrue(securesystemslib.formats.PEMRSA_SCHEMA.matches(public))
        self.assertTrue(securesystemslib.formats.PEMRSA_SCHEMA.matches(private))

        self.assertRaises(
            securesystemslib.exceptions.CryptoError,
            securesystemslib.rsa_keys.create_rsa_public_and_private_from_pem,
            public_rsa,
        )

    def test_encrypt_key(self):
        global public_rsa  # pylint: disable=global-variable-not-assigned
        global private_rsa  # pylint: disable=global-variable-not-assigned

        key_object = {
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyid": "1223",
            "keyval": {"public": public_rsa, "private": private_rsa},
        }

        encrypted_key = securesystemslib.rsa_keys.encrypt_key(
            key_object, "password"
        )
        self.assertTrue(
            securesystemslib.formats.ENCRYPTEDKEY_SCHEMA.matches(encrypted_key)
        )

        key_object["keyval"]["private"] = ""
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.rsa_keys.encrypt_key,
            key_object,
            "password",
        )

    def test_decrypt_key(self):
        # Test for valid arguments.
        global public_rsa  # pylint: disable=global-variable-not-assigned
        global private_rsa  # pylint: disable=global-variable-not-assigned
        passphrase = "pw"

        rsa_key = {
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyid": "d62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d",
            "keyval": {"public": public_rsa, "private": private_rsa},
        }

        encrypted_rsa_key = securesystemslib.rsa_keys.encrypt_key(
            rsa_key, passphrase
        )

        _ = securesystemslib.rsa_keys.decrypt_key(encrypted_rsa_key, passphrase)

        # Test for invalid arguments.
        self.assertRaises(
            securesystemslib.exceptions.CryptoError,
            securesystemslib.rsa_keys.decrypt_key,
            "bad",
            passphrase,
        )

        # Test for invalid encrypted content (i.e., invalid hmac and ciphertext.)
        encryption_delimiter = (
            securesystemslib.rsa_keys._ENCRYPTION_DELIMITER  # pylint: disable=protected-access
        )
        salt, iterations, hmac, iv, ciphertext = encrypted_rsa_key.split(
            encryption_delimiter
        )

        # Set an invalid hmac.  The decryption routine sould raise a
        # securesystemslib.exceptions.CryptoError exception because 'hmac' does not
        # match the hmac calculated by the decryption routine.
        bad_hmac = "12345abcd"
        invalid_encrypted_rsa_key = (
            salt
            + encryption_delimiter
            + iterations
            + encryption_delimiter
            + bad_hmac
            + encryption_delimiter
            + iv
            + encryption_delimiter
            + ciphertext
        )

        self.assertRaises(
            securesystemslib.exceptions.CryptoError,
            securesystemslib.rsa_keys.decrypt_key,
            invalid_encrypted_rsa_key,
            passphrase,
        )

        # Test for invalid 'ciphertext'
        bad_ciphertext = "12345abcde"
        invalid_encrypted_rsa_key = (
            salt
            + encryption_delimiter
            + iterations
            + encryption_delimiter
            + hmac
            + encryption_delimiter
            + iv
            + encryption_delimiter
            + bad_ciphertext
        )

        self.assertRaises(
            securesystemslib.exceptions.CryptoError,
            securesystemslib.rsa_keys.decrypt_key,
            invalid_encrypted_rsa_key,
            passphrase,
        )


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
