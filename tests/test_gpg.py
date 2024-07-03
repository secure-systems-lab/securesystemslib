"""
<Program Name>
  test_gpg.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test gpg/pgp-related functions.

"""

import os
import shutil
import tempfile
import unittest

from collections import OrderedDict
from copy import deepcopy
from unittest.mock import patch

# ruff: noqa: I001
import cryptography.hazmat.primitives.hashes as hashing
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization

from securesystemslib._gpg.common import (
    _assign_certified_key_info,
    _get_verified_subkeys,
    get_pubkey_bundle,
    parse_pubkey_bundle,
    parse_pubkey_payload,
    parse_signature_packet,
)
from securesystemslib._gpg.constants import (
    PACKET_TYPE_PRIMARY_KEY,
    PACKET_TYPE_SUB_KEY,
    PACKET_TYPE_USER_ATTR,
    PACKET_TYPE_USER_ID,
    SHA1,
    SHA256,
    SHA512,
    have_gpg,
)
from securesystemslib._gpg.dsa import create_pubkey as dsa_create_pubkey
from securesystemslib._gpg.eddsa import ED25519_SIG_LENGTH
from securesystemslib._gpg.exceptions import (
    KeyExpirationError,
    KeyNotFoundError,
    PacketParsingError,
    PacketVersionNotSupportedError,
    SignatureAlgorithmNotSupportedError,
)
from securesystemslib._gpg.functions import (
    create_signature,
    export_pubkey,
    export_pubkeys,
    verify_signature,
)
from securesystemslib._gpg.rsa import create_pubkey as rsa_create_pubkey
from securesystemslib._gpg.util import (
    get_hashing_class,
    parse_packet_header,
    parse_subpacket_header,
)


class GPGTestUtils:
    """GPG Test utility class"""

    @staticmethod
    def ignore_not_found_error(function, path, exc_info):
        """Callback that ignores FileNotFoundError"""
        _, error, _ = exc_info
        if not isinstance(error, FileNotFoundError):
            raise error


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestUtil(unittest.TestCase):
    """Test util functions."""

    def test_get_hashing_class(self):
        # Assert return expected hashing class
        expected_hashing_class = [hashing.SHA1, hashing.SHA256, hashing.SHA512]
        for idx, hashing_id in enumerate([SHA1, SHA256, SHA512]):
            result = get_hashing_class(hashing_id)
            self.assertEqual(result, expected_hashing_class[idx])

        # Assert raises ValueError with non-supported hashing id
        with self.assertRaises(ValueError):
            get_hashing_class("bogus_hashing_id")

    def test_parse_packet_header(self):
        """Test parse_packet_header with manually crafted data."""
        data_list = [
            ## New format packet length with mock packet type 100001
            # one-octet length, header len: 2, body len: 0 to 191
            [0b01100001, 0],
            [0b01100001, 191],
            # two-octet length, header len: 3, body len: 192 to 8383
            [0b01100001, 192, 0],
            [0b01100001, 223, 255],
            # five-octet length, header len: 6, body len: 0 to 4,294,967,295
            [0b01100001, 255, 0, 0, 0, 0],
            [0b01100001, 255, 255, 255, 255, 255],
            ## Old format packet lengths with mock packet type 1001
            # one-octet length, header len: 2, body len: 0 to 255
            [0b00100100, 0],
            [0b00100100, 255],
            # two-octet length, header len: 3, body len: 0 to 65,535
            [0b00100101, 0, 0],
            [0b00100101, 255, 255],
            # four-octet length, header len: 5, body len: 0 to 4,294,967,295
            [0b00100110, 0, 0, 0, 0, 0],
            [0b00100110, 255, 255, 255, 255, 255],
        ]

        # packet_type | header_len | body_len | packet_len
        expected = [
            (33, 2, 0, 2),
            (33, 2, 191, 193),
            (33, 3, 192, 195),
            (33, 3, 8383, 8386),
            (33, 6, 0, 6),
            (33, 6, 4294967295, 4294967301),
            (9, 2, 0, 2),
            (9, 2, 255, 257),
            (9, 3, 0, 3),
            (9, 3, 65535, 65538),
            (9, 5, 0, 5),
            (9, 5, 4294967295, 4294967300),
        ]

        for idx, data in enumerate(data_list):
            result = parse_packet_header(bytearray(data))
            self.assertEqual(result, expected[idx])

        # New Format Packet Lengths with Partial Body Lengths range
        for second_octet in [224, 254]:
            with self.assertRaises(PacketParsingError):
                parse_packet_header(bytearray([0b01100001, second_octet]))

        # Old Format Packet Lengths with indeterminate length (length type 3)
        with self.assertRaises(PacketParsingError):
            parse_packet_header(bytearray([0b00100111]))

        # Get expected type
        parse_packet_header(bytearray([0b01100001, 0]), expected_type=33)

        # Raise with unexpected type
        with self.assertRaises(PacketParsingError):
            parse_packet_header(bytearray([0b01100001, 0]), expected_type=34)

    def test_parse_subpacket_header(self):
        """Test parse_subpacket_header with manually crafted data."""
        # All items until last item encode the length of the subpacket,
        # the last item encodes the mock subpacket type.
        data_list = [
            # length of length 1, subpacket length 0 to 191
            [0, 33],  # NOTE: Nonsense 0-length
            [191, 33],
            # # length of length 2, subpacket length 192 to 16,319
            [192, 0, 33],
            [254, 255, 33],
            # # length of length 5, subpacket length 0 to 4,294,967,295
            [255, 0, 0, 0, 0, 33],  # NOTE: Nonsense 0-length
            [255, 255, 255, 255, 255, 33],
        ]
        # packet_type | header_len | body_len | packet_len
        expected = [
            (33, 2, -1, 1),  # NOTE: Nonsense negative payload
            (33, 2, 190, 192),
            (33, 3, 191, 194),
            (33, 3, 16318, 16321),
            (33, 6, -1, 5),  # NOTE: Nonsense negative payload
            (33, 6, 4294967294, 4294967300),
        ]

        for idx, data in enumerate(data_list):
            result = parse_subpacket_header(bytearray(data))
            self.assertEqual(result, expected[idx])


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestCommon(unittest.TestCase):
    """Test common functions of the securesystemslib._gpg module."""

    @classmethod
    def setUpClass(self):
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa"
        )

        # Load raw public key bundle data from fixtures
        key = "F557D0FF451DEF45372591429EA70BD13D883381"
        key_expired = "E8AC80C924116DABB51D4B987CB07D6D2C199C7C"
        data = {}
        for keyid in [key, key_expired]:
            path = os.path.join(gpg_keyring_path, f"{keyid}.raw")
            with open(path, "rb") as f:
                data[keyid] = f.read()

        self.raw_key_data = data[key]
        self.raw_key_bundle = parse_pubkey_bundle(data[key])
        self.raw_expired_key_bundle = parse_pubkey_bundle(data[key_expired])

    def test_parse_pubkey_payload_errors(self):
        """Test parse_pubkey_payload errors with manually crafted data."""
        # passed data | expected error | expected error message
        test_data = [
            (None, ValueError, "empty pubkey"),
            (
                bytearray([0x03]),
                PacketVersionNotSupportedError,
                "packet version '3' not supported",
            ),
            (
                bytearray([0x04, 0, 0, 0, 0, 255]),
                SignatureAlgorithmNotSupportedError,
                "Signature algorithm '255' not supported",
            ),
        ]

        for data, error, error_str in test_data:
            with self.assertRaises(error) as ctx:
                parse_pubkey_payload(data)
            self.assertTrue(error_str in str(ctx.exception))

    def test_parse_pubkey_bundle_errors(self):
        """Test parse_pubkey_bundle errors with manually crafted data partially
        based on real gpg key data (see self.raw_key_bundle)."""
        # Extract sample (legitimate) user ID packet and pass as first packet to
        # raise first packet must be primary key error
        user_id_packet = list(self.raw_key_bundle[PACKET_TYPE_USER_ID].keys())[0]
        # Extract sample (legitimate) primary key packet and pass as first two
        # packets to raise unexpected second primary key error
        primary_key_packet = self.raw_key_bundle[PACKET_TYPE_PRIMARY_KEY]["packet"]
        # Create incomplete packet to re-raise header parsing IndexError as
        # PacketParsingError
        incomplete_packet = bytearray([0b01111111])

        # passed data | expected error message
        test_data = [
            (None, "empty gpg data"),
            (user_id_packet, "must be a primary key"),
            (primary_key_packet + primary_key_packet, "Unexpected primary key"),
            (incomplete_packet, "index out of range"),
        ]
        for data, error_str in test_data:
            with self.assertRaises(PacketParsingError) as ctx:
                parse_pubkey_bundle(data)
            self.assertTrue(error_str in str(ctx.exception))

        # Create empty packet of unsupported type 66 (bit 0-5) and length 0 and
        # pass as second packet to provoke skipping of unsupported packet
        unsupported_packet = bytearray([0b01111111, 0])
        with patch("securesystemslib._gpg.common.log") as mock_log:
            parse_pubkey_bundle(primary_key_packet + unsupported_packet)
            self.assertTrue(
                "Ignoring gpg key packet '63'" in mock_log.info.call_args[0][0]
            )

    def test_parse_pubkey_bundle(self):
        """Assert presence of packets expected returned from `parse_pubkey_bundle`
    for specific test key). See
    ```
    gpg --homedir tests/gpg_keyrings/rsa/ --export 9EA70BD13D883381 | \
        gpg --list-packets
    ```
    """
        # Expect parsed primary key
        self.assertEqual(
            self.raw_key_bundle[PACKET_TYPE_PRIMARY_KEY]["key"]["method"],
            "pgp+rsa-pkcsv1.5",
        )

        # Parse corresponding raw packet for comparison
        _, header_len, _, _ = parse_packet_header(
            self.raw_key_bundle[PACKET_TYPE_PRIMARY_KEY]["packet"]
        )

        parsed_raw_packet = parse_pubkey_payload(
            bytearray(
                self.raw_key_bundle[PACKET_TYPE_PRIMARY_KEY]["packet"][header_len:]
            )
        )

        # And compare
        self.assertDictEqual(
            self.raw_key_bundle[PACKET_TYPE_PRIMARY_KEY]["key"],
            parsed_raw_packet,
        )

        # Expect one primary key signature (revocation signature)
        self.assertEqual(
            len(self.raw_key_bundle[PACKET_TYPE_PRIMARY_KEY]["signatures"]), 1
        )

        # Expect one User ID packet, one User Attribute packet and one Subkey,
        # each with correct data
        for _type in [
            PACKET_TYPE_USER_ID,
            PACKET_TYPE_USER_ATTR,
            PACKET_TYPE_SUB_KEY,
        ]:
            # Of each type there is only one packet
            self.assertTrue(len(self.raw_key_bundle[_type]) == 1)
            # The raw packet is stored as key in the per-packet type collection
            raw_packet = next(iter(self.raw_key_bundle[_type]))
            # Its values are the raw packets header and body length
            self.assertEqual(
                len(raw_packet),
                self.raw_key_bundle[_type][raw_packet]["header_len"]
                + self.raw_key_bundle[_type][raw_packet]["body_len"],
            )
            # and one self-signature
            self.assertEqual(
                len(self.raw_key_bundle[_type][raw_packet]["signatures"]), 1
            )

    def test_assign_certified_key_info_errors(self):
        """Test _assign_certified_key_info errors with manually crafted data
        based on real gpg key data (see self.raw_key_bundle)."""

        # Replace legitimate user certifacte with a bogus packet
        wrong_cert_bundle = deepcopy(self.raw_key_bundle)
        packet, packet_data = wrong_cert_bundle[PACKET_TYPE_USER_ID].popitem()
        packet_data["signatures"] = [bytearray([0b01111111, 0])]
        wrong_cert_bundle[PACKET_TYPE_USER_ID][packet] = packet_data

        # Replace primary key id with a non-associated keyid
        wrong_keyid_bundle = deepcopy(self.raw_key_bundle)
        wrong_keyid_bundle[PACKET_TYPE_PRIMARY_KEY]["key"]["keyid"] = (
            "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
        )

        # Remove a byte in user id packet to make signature verification fail
        invalid_cert_bundle = deepcopy(self.raw_key_bundle)
        packet, packet_data = invalid_cert_bundle[PACKET_TYPE_USER_ID].popitem()
        packet = packet[:-1]
        invalid_cert_bundle[PACKET_TYPE_USER_ID][packet] = packet_data

        test_data = [
            # Skip and log parse_signature_packet error
            (wrong_cert_bundle, "Expected packet 2, but got 63 instead"),
            # Skip and log signature packet that doesn't match primary key id
            (wrong_keyid_bundle, "Ignoring User ID certificate issued by"),
            # Skip and log invalid signature
            (invalid_cert_bundle, "Ignoring invalid User ID self-certificate"),
        ]

        for bundle, expected_msg in test_data:
            with patch("securesystemslib._gpg.common.log") as mock_log:
                _assign_certified_key_info(bundle)
                msg = str(mock_log.info.call_args[0][0])
                self.assertTrue(expected_msg in msg, f"'{expected_msg}' not in '{msg}'")

    def test_assign_certified_key_info_expiration(self):
        """Test assignment of key expiration date in
        gpg.common._assign_certified_key_info using real gpg data (with ambiguity
        resolution / prioritization).

        # FIXME: Below tests are missing proper assertions for which User ID
        self-certificate is considered for the expiration date. Reasons are:
        - gpg does not let you (easily) modify individual expiration dates of User
          IDs (changing one changes all), hence we cannot assert the chosen packet
          by the particular date
        -  _assign_certified_key_info first verifies all self-certificates and then
           only considers successfully verified ones, hence we cannot modify the
           certificate data, before passing it to _assign_certified_key_info

        IMO the best solution is a better separation of concerns, e.g. separate
        self-certificate verification and packet prioritization.

        """
        # Test ambiguity resolution scheme with 3 User IDs
        #   :user ID packet: "Test Expiration I <test@expir.one>"
        #   :user ID packet: "Test Expiration II <test@expir.two>"
        #   :user ID packet: "Test Expiration III <test@expir.three>"
        # User ID packets are ordered by their creation time in ascending order.
        # "Test Expiration II" has the primary user ID flag set and therefor has
        # the highest priority.
        key = _assign_certified_key_info(self.raw_expired_key_bundle)
        self.assertTrue(
            key["validity_period"] == 87901  # noqa: PLR2004
        )  # ~ 1 day

        # Test ambiguity resolution scheme with 2 User IDs
        #   :user ID packet: "Test Expiration III <test@expir.three>"
        #   :user ID packet: "Test Expiration I <test@expir.one>"
        # User ID packets are ordered by their creation time in descending order.
        # Neither packet has the primary user ID flag set.
        # "Test Expiration III" has the highest priority.
        raw_key_bundle = deepcopy(self.raw_expired_key_bundle)
        user_id_items = list(reversed(raw_key_bundle[PACKET_TYPE_USER_ID].items()))
        del user_id_items[1]
        raw_key_bundle[PACKET_TYPE_USER_ID] = OrderedDict(user_id_items)
        key = _assign_certified_key_info(raw_key_bundle)
        self.assertTrue(
            key["validity_period"] == 87901  # noqa: PLR2004
        )  # ~ 1 day

    def test_get_verified_subkeys_errors(self):
        """Test _get_verified_subkeys errors with manually crafted data based on
        real gpg key data (see self.raw_key_bundle)."""

        # Tamper with subkey (change version number) to trigger key parsing error
        bad_subkey_bundle = deepcopy(self.raw_key_bundle)
        packet, packet_data = bad_subkey_bundle[PACKET_TYPE_SUB_KEY].popitem()
        packet = bytes(
            packet[: packet_data["header_len"]]
            + bytearray([0x03])
            + packet[packet_data["header_len"] + 1 :]
        )
        bad_subkey_bundle[PACKET_TYPE_SUB_KEY][packet] = packet_data

        # Add bogus sig to trigger sig parsing error
        wrong_sig_bundle = deepcopy(self.raw_key_bundle)
        packet, packet_data = wrong_sig_bundle[PACKET_TYPE_SUB_KEY].popitem()
        # NOTE: We can't only pass the bogus sig, because that would also trigger
        # the not enough sigs error (see not_enough_sigs_bundle) and mock only
        # lets us assert for the most recent log statement
        packet_data["signatures"].append(bytearray([0b01111111, 0]))
        wrong_sig_bundle[PACKET_TYPE_SUB_KEY][packet] = packet_data

        # Remove sigs to trigger not enough sigs error
        not_enough_sigs_bundle = deepcopy(self.raw_key_bundle)
        packet, packet_data = not_enough_sigs_bundle[PACKET_TYPE_SUB_KEY].popitem()
        packet_data["signatures"] = []
        not_enough_sigs_bundle[PACKET_TYPE_SUB_KEY][packet] = packet_data

        # Duplicate sig to trigger wrong amount signatures
        too_many_sigs_bundle = deepcopy(self.raw_key_bundle)
        packet, packet_data = too_many_sigs_bundle[PACKET_TYPE_SUB_KEY].popitem()
        packet_data["signatures"] = packet_data["signatures"] * 2
        too_many_sigs_bundle[PACKET_TYPE_SUB_KEY][packet] = packet_data

        # Tamper with primary key to trigger signature verification error
        invalid_sig_bundle = deepcopy(self.raw_key_bundle)
        invalid_sig_bundle[PACKET_TYPE_PRIMARY_KEY]["packet"] = invalid_sig_bundle[
            PACKET_TYPE_PRIMARY_KEY
        ]["packet"][:-1]

        test_data = [
            (bad_subkey_bundle, "Pubkey packet version '3' not supported"),
            (wrong_sig_bundle, "Expected packet 2, but got 63 instead"),
            (
                not_enough_sigs_bundle,
                "wrong amount of key binding signatures (0)",
            ),
            (
                too_many_sigs_bundle,
                "wrong amount of key binding signatures (2)",
            ),
            (invalid_sig_bundle, "invalid key binding signature"),
        ]

        for bundle, expected_msg in test_data:
            with patch("securesystemslib._gpg.common.log") as mock_log:
                _get_verified_subkeys(bundle)
                msg = str(mock_log.info.call_args[0][0])
                self.assertTrue(expected_msg in msg, f"'{expected_msg}' not in '{msg}'")

    def test_get_verified_subkeys(self):
        """Test correct assignment of subkey expiration date in
        gpg.common._get_verified_subkeys using real gpg data."""
        subkeys = _get_verified_subkeys(self.raw_expired_key_bundle)
        # Test subkey with validity period 175451, i.e. ~ 2 days
        self.assertTrue(
            subkeys["0ce427fa3f0f50bc83a4a760ed95e1581691db4d"].get("validity_period")
            == 175451  # noqa: PLR2004
        )

        # Test subkey  without validity period, i.e. it does not expire
        self.assertTrue(
            subkeys["70cfabf1e2f1dc60ac5c7bca10cd20d3d5bcb6ef"].get("validity_period")
            is None
        )

    def test_get_pubkey_bundle_errors(self):
        """Test correct error raising in get_pubkey_bundle."""
        # Call without key data
        with self.assertRaises(KeyNotFoundError):
            get_pubkey_bundle(None, "deadbeef")

        # Pass wrong keyid with valid gpg data to trigger KeyNotFoundError.
        not_associated_keyid = "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
        with self.assertRaises(KeyNotFoundError):
            get_pubkey_bundle(self.raw_key_data, not_associated_keyid)

    def test_parse_signature_packet_errors(self):
        """Test parse_signature_packet errors with manually crafted data."""

        # passed data | expected error message
        test_data = [
            (
                bytearray([0b01000010, 1, 255]),
                "Signature version '255' not supported",
            ),
            (
                bytearray([0b01000010, 2, 4, 255]),
                "Signature type '255' not supported",
            ),
            (
                bytearray([0b01000010, 3, 4, 0, 255]),
                "Signature algorithm '255' not supported",
            ),
            (
                bytearray([0b01000010, 4, 4, 0, 1, 255]),
                "Hash algorithm '255' not supported",
            ),
        ]
        for data, expected_error_str in test_data:
            with self.assertRaises(ValueError) as ctx:
                parse_signature_packet(data)
            self.assertTrue(
                expected_error_str in str(ctx.exception),
                f"'{expected_error_str}' not in '{str(ctx.exception)}'",
            )


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestGPGRSA(unittest.TestCase):
    """Test signature creation, verification and key export from the gpg
    module"""

    default_keyid = "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
    signing_subkey_keyid = "C5A0ABE6EC19D0D65F85E2C39BE9DF5131D924E9"
    encryption_subkey_keyid = "6A112FD3390B2E53AFC2E57F8FC8E12099AECEEA"
    unsupported_subkey_keyid = "611A9B648E16F54E8A7FAD5DA51E8CDF3B06524F"
    expired_key_keyid = "E8AC80C924116DABB51D4B987CB07D6D2C199C7C"

    keyid_768C43 = "7B3ABB26B97B655AB9296BD15B0BD02E1C768C43"  # noqa: N815

    @classmethod
    def setUpClass(self):
        # Create directory to run the tests without having everything blow up
        self.working_dir = os.getcwd()

        # Find demo files
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa"
        )

        self.test_dir = os.path.realpath(tempfile.mkdtemp())
        self.gnupg_home = "rsa"
        shutil.copytree(gpg_keyring_path, os.path.join(self.test_dir, self.gnupg_home))
        os.chdir(self.test_dir)

    @classmethod
    def tearDownClass(self):
        """Change back to initial working dir and remove temp test directory."""
        os.chdir(self.working_dir)
        shutil.rmtree(self.test_dir, onerror=GPGTestUtils.ignore_not_found_error)

    def test_export_pubkey_error(self):
        """Test correct error is raised if function called incorrectly."""
        with self.assertRaises(KeyNotFoundError):
            export_pubkey("not-a-key-id")

    def test_export_pubkey(self):
        """export a public key and make sure the parameters are the right ones:

        since there's very little we can do to check rsa key parameters are right
        we pre-exported the public key to an ssh key, which we can load with
        cryptography for the sake of comparison"""

        # export our gpg key, using our functions
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)
        our_exported_key = rsa_create_pubkey(key_data)

        # load the equivalent ssh key, and make sure that we get the same RSA key
        # parameters
        ssh_key_basename = f"{self.default_keyid}.ssh"
        ssh_key_path = os.path.join(self.gnupg_home, ssh_key_basename)
        with open(ssh_key_path, "rb") as fp:
            keydata = fp.read()

        ssh_key = serialization.load_ssh_public_key(keydata, backends.default_backend())

        self.assertEqual(
            ssh_key.public_numbers().n, our_exported_key.public_numbers().n
        )
        self.assertEqual(
            ssh_key.public_numbers().e, our_exported_key.public_numbers().e
        )

        subkey_keyids = list(key_data["subkeys"].keys())
        # We export the whole master key bundle which must contain the subkeys
        self.assertTrue(self.signing_subkey_keyid.lower() in subkey_keyids)
        # Currently we do not exclude encryption subkeys
        self.assertTrue(self.encryption_subkey_keyid.lower() in subkey_keyids)
        # However we do exclude subkeys, whose algorithm we do not support
        self.assertFalse(self.unsupported_subkey_keyid.lower() in subkey_keyids)

        # When passing the subkey keyid we also export the whole keybundle
        key_data2 = export_pubkey(self.signing_subkey_keyid, homedir=self.gnupg_home)
        self.assertDictEqual(key_data, key_data2)

    def test_export_pubkeys(self):
        """Test export multiple pubkeys at once."""
        key_dict = export_pubkeys(
            [self.default_keyid, self.keyid_768C43], homedir=self.gnupg_home
        )

        self.assertListEqual(
            sorted([self.default_keyid.lower(), self.keyid_768C43.lower()]),
            sorted(key_dict.keys()),
        )

    def test_gpg_sign_and_verify_object_with_default_key(self):
        """Create a signature using the default key on the keyring"""

        test_data = b"test_data"
        wrong_data = b"something malicious"

        signature = create_signature(test_data, homedir=self.gnupg_home)
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)

        self.assertTrue(verify_signature(signature, key_data, test_data))
        self.assertFalse(verify_signature(signature, key_data, wrong_data))

    def test_gpg_sign_and_verify_object(self):
        """Create a signature using a specific key on the keyring"""

        test_data = b"test_data"
        wrong_data = b"something malicious"

        signature = create_signature(
            test_data, keyid=self.default_keyid, homedir=self.gnupg_home
        )
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)
        self.assertTrue(verify_signature(signature, key_data, test_data))
        self.assertFalse(verify_signature(signature, key_data, wrong_data))

    def test_gpg_sign_and_verify_object_default_keyring(self):
        """Sign/verify using keyring from envvar."""

        test_data = b"test_data"

        gnupg_home_backup = os.environ.get("GNUPGHOME")
        os.environ["GNUPGHOME"] = self.gnupg_home

        signature = create_signature(test_data, keyid=self.default_keyid)
        key_data = export_pubkey(self.default_keyid)
        self.assertTrue(verify_signature(signature, key_data, test_data))

        # Reset GNUPGHOME
        if gnupg_home_backup:
            os.environ["GNUPGHOME"] = gnupg_home_backup
        else:
            del os.environ["GNUPGHOME"]

    def test_create_signature_with_expired_key(self):
        """Test signing with expired key raises OSError."""
        with self.assertRaises(OSError) as ctx:
            create_signature(
                b"livestock",
                keyid=self.expired_key_keyid,
                homedir=self.gnupg_home,
            )

        expected = "returned non-zero exit status '2'"
        self.assertTrue(
            expected in str(ctx.exception), f"{expected} not in {ctx.exception}"
        )

    def test_verify_signature_with_expired_key(self):
        """Test sig verification with expired key raises KeyExpirationError."""
        signature = {
            "keyid": self.expired_key_keyid,
            "other_headers": "deadbeef",
            "signature": "deadbeef",
        }
        content = b"livestock"
        key = export_pubkey(self.expired_key_keyid, homedir=self.gnupg_home)

        with self.assertRaises(KeyExpirationError) as ctx:
            verify_signature(signature, key, content)

        expected = (
            "GPG key 'e8ac80c924116dabb51d4b987cb07d6d2c199c7c' "
            "created on '2019-03-25 12:46 UTC' with validity period '1 day, "
            "0:25:01' expired on '2019-03-26 13:11 UTC'."
        )
        self.assertTrue(
            expected == str(ctx.exception),
            f"\nexpected: {expected}" "\ngot:      {ctx.exception}",
        )


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestGPGDSA(unittest.TestCase):
    """Test signature creation, verification and key export from the gpg
    module"""

    default_keyid = "C242A830DAAF1C2BEF604A9EF033A3A3E267B3B1"

    @classmethod
    def setUpClass(self):
        # Create directory to run the tests without having everything blow up
        self.working_dir = os.getcwd()
        self.test_dir = os.path.realpath(tempfile.mkdtemp())
        self.gnupg_home = "dsa"

        # Find keyrings
        keyrings = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "dsa"
        )

        shutil.copytree(keyrings, os.path.join(self.test_dir, self.gnupg_home))
        os.chdir(self.test_dir)

    @classmethod
    def tearDownClass(self):
        """Change back to initial working dir and remove temp test directory."""
        os.chdir(self.working_dir)
        shutil.rmtree(self.test_dir, onerror=GPGTestUtils.ignore_not_found_error)

    def test_export_pubkey(self):
        """export a public key and make sure the parameters are the right ones:

        since there's very little we can do to check key parameters are right
        we pre-exported the public key to an x.509 SubjectPublicKeyInfo key,
        which we can load with cryptography for the sake of comparison"""

        # export our gpg key, using our functions
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)
        our_exported_key = dsa_create_pubkey(key_data)

        # load same key, pre-exported with 3rd-party tooling
        pem_key_basename = f"{self.default_keyid}.pem"
        pem_key_path = os.path.join(self.gnupg_home, pem_key_basename)
        with open(pem_key_path, "rb") as fp:
            keydata = fp.read()

        pem_key = serialization.load_pem_public_key(keydata, backends.default_backend())

        # make sure keys match
        self.assertEqual(
            pem_key.public_numbers().y, our_exported_key.public_numbers().y
        )
        self.assertEqual(
            pem_key.public_numbers().parameter_numbers.g,
            our_exported_key.public_numbers().parameter_numbers.g,
        )
        self.assertEqual(
            pem_key.public_numbers().parameter_numbers.q,
            our_exported_key.public_numbers().parameter_numbers.q,
        )
        self.assertEqual(
            pem_key.public_numbers().parameter_numbers.p,
            our_exported_key.public_numbers().parameter_numbers.p,
        )

    def test_gpg_sign_and_verify_object_with_default_key(self):
        """Create a signature using the default key on the keyring"""

        test_data = b"test_data"
        wrong_data = b"something malicious"

        signature = create_signature(test_data, homedir=self.gnupg_home)
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)

        self.assertTrue(verify_signature(signature, key_data, test_data))
        self.assertFalse(verify_signature(signature, key_data, wrong_data))

    def test_gpg_sign_and_verify_object(self):
        """Create a signature using a specific key on the keyring"""

        test_data = b"test_data"
        wrong_data = b"something malicious"

        signature = create_signature(
            test_data, keyid=self.default_keyid, homedir=self.gnupg_home
        )
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)

        self.assertTrue(verify_signature(signature, key_data, test_data))
        self.assertFalse(verify_signature(signature, key_data, wrong_data))


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestGPGEdDSA(unittest.TestCase):
    """Test signature creation, verification and key export from the gpg
    module"""

    default_keyid = "4E630F84838BF6F7447B830B22692F5FEA9E2DD2"

    @classmethod
    def setUpClass(self):
        # Create directory to run the tests without having everything blow up
        self.working_dir = os.getcwd()
        self.test_dir = os.path.realpath(tempfile.mkdtemp())
        self.gnupg_home = "dsa"

        # Find keyrings
        keyrings = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "eddsa"
        )

        shutil.copytree(keyrings, os.path.join(self.test_dir, self.gnupg_home))
        os.chdir(self.test_dir)

    @classmethod
    def tearDownClass(self):
        """Change back to initial working dir and remove temp test directory."""
        os.chdir(self.working_dir)
        shutil.rmtree(self.test_dir, onerror=GPGTestUtils.ignore_not_found_error)

    def test_gpg_sign_and_verify_object_with_default_key(self):
        """Create a signature using the default key on the keyring"""

        test_data = b"test_data"
        wrong_data = b"something malicious"

        signature = create_signature(test_data, homedir=self.gnupg_home)
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)

        self.assertTrue(verify_signature(signature, key_data, test_data))
        self.assertFalse(verify_signature(signature, key_data, wrong_data))

    def test_gpg_sign_and_verify_object_with_specific_key(self):
        """Create a signature using a specific key on the keyring"""

        test_data = b"test_data"
        wrong_data = b"something malicious"

        signature = create_signature(
            test_data, keyid=self.default_keyid, homedir=self.gnupg_home
        )
        key_data = export_pubkey(self.default_keyid, homedir=self.gnupg_home)

        self.assertTrue(verify_signature(signature, key_data, test_data))
        self.assertFalse(verify_signature(signature, key_data, wrong_data))

    def test_verify_short_signature(self):
        """Correctly verify a special-crafted short signature."""

        test_data = b"hello"
        signature_path = os.path.join(self.gnupg_home, "short.sig")

        # Read special-crafted raw gpg signature that is one byte too short
        with open(signature_path, "rb") as f:
            signature_data = f.read()

        # Check that the signature is padded upon parsing
        # NOTE: The returned signature is a hex string and thus twice as long
        signature = parse_signature_packet(signature_data)
        self.assertTrue(len(signature["signature"]) == (ED25519_SIG_LENGTH * 2))

        # Check that the signature can be successfully verified
        key = export_pubkey(self.default_keyid, homedir=self.gnupg_home)
        self.assertTrue(verify_signature(signature, key, test_data))


if __name__ == "__main__":
    unittest.main()
