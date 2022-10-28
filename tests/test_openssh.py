#!/usr/bin/env python

"""
<Program Name>
  test_openssh.py

<Author>
  KOLANICH

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test OpenSSH-related functions.

"""

import unittest
from pathlib import Path

this_dir = Path(__file__).resolve().absolute().parent
keys_dir = this_dir / "data" / "ssh"

# pylint: disable=wrong-import-position
from securesystemslib.convert.ssh import import_ssh_key
from securesystemslib.keys import create_signature, verify_signature

TEST_DATA = b"test"


class TestOpenSSH(unittest.TestCase):
    def test_openssh_import_and_sign_and_verify(self):
        files = sorted(set(keys_dir.glob("*.pub")))
        for pub_f in files:
            sec_f = pub_f.parent / pub_f.stem
            with self.subTest(pub_f=pub_f, sec_f=sec_f):
                pub = import_ssh_key(pub_f.read_text(), None)
                sec = import_ssh_key(sec_f.read_text(), None)
                signature = create_signature(sec, TEST_DATA)
                self.assertTrue(verify_signature(pub, signature, TEST_DATA))


if __name__ == "__main__":
    unittest.main()
