#!/usr/bin/env python

"""
<Program Name>
  test_interface.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 5, 2017.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'interface.py'.
"""

import os
import time
import datetime
import tempfile
import json
import shutil
import stat
import sys
import unittest

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

# Use external backport 'mock' on versions under 3.3
if sys.version_info >= (3, 3):
  import unittest.mock as mock

else:
  import mock

from securesystemslib import (
    KEY_TYPE_RSA,
    KEY_TYPE_ED25519,
    KEY_TYPE_ECDSA)

from securesystemslib.formats import (
    RSAKEY_SCHEMA,
    PUBLIC_KEY_SCHEMA,
    ANY_PUBKEY_DICT_SCHEMA,
    ED25519KEY_SCHEMA,
    ECDSAKEY_SCHEMA)

from securesystemslib.exceptions import Error, FormatError, CryptoError

from securesystemslib.interface import (
    _generate_and_write_rsa_keypair,
    generate_and_write_rsa_keypair,
    generate_and_write_rsa_keypair_with_prompt,
    generate_and_write_unencrypted_rsa_keypair,
    import_rsa_privatekey_from_file,
    import_rsa_publickey_from_file,
    _generate_and_write_ed25519_keypair,
    generate_and_write_ed25519_keypair,
    generate_and_write_ed25519_keypair_with_prompt,
    generate_and_write_unencrypted_ed25519_keypair,
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file,
    _generate_and_write_ecdsa_keypair,
    generate_and_write_ecdsa_keypair,
    generate_and_write_ecdsa_keypair_with_prompt,
    generate_and_write_unencrypted_ecdsa_keypair,
    import_ecdsa_publickey_from_file,
    import_ecdsa_privatekey_from_file,
    import_publickeys_from_file,
    import_privatekey_from_file)



class TestInterfaceFunctions(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.test_data_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data")

    cls.path_rsa = os.path.join(
        cls.test_data_dir, "keystore", "rsa_key")
    cls.path_ed25519 = os.path.join(
        cls.test_data_dir, "keystore", "ed25519_key")
    cls.path_ecdsa = os.path.join(
        cls.test_data_dir, "keystore", "ecdsa_key")
    cls.path_no_key = os.path.join(
        cls.test_data_dir, "keystore", "no_key")

    cls.orig_cwd = os.getcwd()

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp(dir=self.orig_cwd)
    os.chdir(self.tmp_dir)

  def tearDown(self):
    os.chdir(self.orig_cwd)
    shutil.rmtree(self.tmp_dir)


  def test_rsa(self):
    """Test RSA key _generation and import interface functions. """

    # TEST: Generate default keys and import
    # Assert location and format
    fn_default = "default"
    fn_default_ret = _generate_and_write_rsa_keypair(filepath=fn_default)

    pub = import_rsa_publickey_from_file(fn_default + ".pub")
    priv = import_rsa_privatekey_from_file(fn_default)

    self.assertEqual(fn_default, fn_default_ret)
    self.assertTrue(RSAKEY_SCHEMA.matches(pub))
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))
    self.assertTrue(RSAKEY_SCHEMA.matches(priv))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])


    # TEST: Generate unencrypted keys with empty prompt
    # Assert importable without password
    fn_empty_prompt = "empty_prompt"
    with mock.patch("securesystemslib.interface.get_password", return_value=""):
      _generate_and_write_rsa_keypair(filepath=fn_empty_prompt, prompt=True)
    import_rsa_privatekey_from_file(fn_empty_prompt)


    # TEST: Generate keys with auto-filename, i.e. keyid
    # Assert filename is keyid
    fn_keyid = _generate_and_write_rsa_keypair()
    pub = import_rsa_publickey_from_file(fn_keyid + ".pub")
    priv = import_rsa_privatekey_from_file(fn_keyid)
    self.assertTrue(
        os.path.basename(fn_keyid) == pub["keyid"] == priv["keyid"])


    # TEST: Generate keys with custom bits
    # Assert length
    bits = 4096
    fn_bits = "bits"
    _generate_and_write_rsa_keypair(filepath=fn_bits, bits=bits)

    priv = import_rsa_privatekey_from_file(fn_bits)
    # NOTE: Parse PEM with pyca/cryptography to get the key size property
    obj_bits = load_pem_private_key(
        priv["keyval"]["private"].encode("utf-8"),
        password=None,
        backend=default_backend())

    self.assertEqual(obj_bits.key_size, bits)


    # TEST: Generate two keypairs with encrypted private keys using ...
    pw = "pw"
    fn_encrypted = "encrypted"
    fn_prompt = "prompt"

    # ... a passed pw ...
    _generate_and_write_rsa_keypair(filepath=fn_encrypted, password=pw)
    with mock.patch("securesystemslib.interface.get_password", return_value=pw):
      # ... and a prompted pw.
      _generate_and_write_rsa_keypair(filepath=fn_prompt, prompt=True)

      # Assert that both private keys are importable using the prompted pw ...
      import_rsa_privatekey_from_file(fn_prompt, prompt=True)
      import_rsa_privatekey_from_file(fn_encrypted, prompt=True)

    # ... and the passed pw.
    import_rsa_privatekey_from_file(fn_prompt, password=pw)
    import_rsa_privatekey_from_file(fn_encrypted, password=pw)


    # TEST: Import existing keys with encrypted private key (test regression)
    # Assert format
    pub = import_rsa_publickey_from_file(self.path_rsa + ".pub")
    priv = import_rsa_privatekey_from_file(self.path_rsa, "password")

    self.assertTrue(RSAKEY_SCHEMA.matches(pub))
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))
    self.assertTrue(RSAKEY_SCHEMA.matches(priv))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])


    # TEST: Generation errors
    for idx, (kwargs, err_msg) in enumerate([
        # Error on empty password
        ({"password": ""},
          "encryption password must be 1 or more characters long"),
        # Error on 'password' and 'prompt=True'
        ({"password": pw, "prompt": True},
          "passing 'password' and 'prompt=True' is not allowed")]):

      with self.assertRaises(ValueError, msg="(row {})".format(idx)) as ctx:
        _generate_and_write_rsa_keypair(**kwargs)

      self.assertEqual(err_msg, str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))

    # Error on bad argument format
    for idx, kwargs in enumerate([
        {"bits": 1024}, # Too low
        {"bits": "not-an-int"},
        {"filepath": 123456}, # Not a string
        {"password": 123456}, # Not a string
        {"prompt": "not-a-bool"}]):
      with self.assertRaises(FormatError, msg="(row {})".format(idx)):
        _generate_and_write_rsa_keypair(**kwargs)


    # TEST: Import errors

    # Error public key import
    err_msg = "Invalid public pem"
    with self.assertRaises(Error) as ctx:
      import_rsa_publickey_from_file(fn_default)

    self.assertTrue(err_msg in str(ctx.exception),
        "expected: '{}' got: '{}'".format(err_msg, ctx.exception))

    # Error on private key import...
    for idx, (args, kwargs, err, err_msg) in enumerate([
        # Error on not a private key
        ([fn_default + ".pub"], {}, CryptoError,
          "Could not deserialize key data"),
        # Error on not encrypted
        ([fn_default], {"password": pw}, CryptoError,
          "Password was given but private key is not encrypted"),
        # Error on encrypted but no pw
        ([fn_encrypted], {}, CryptoError,
          "Password was not given but private key is encrypted"),
        # Error on encrypted but empty pw passed
        ([fn_encrypted], {"password": ""}, CryptoError,
          "Password was not given but private key is encrypted"),
        # Error on encrypted but bad pw passed
        ([fn_encrypted], {"password": "bad pw"}, CryptoError,
          "Bad decrypt. Incorrect password?"),
        # Error on pw and prompt
        ([fn_default], {"password": pw, "prompt": True}, ValueError,
          "passing 'password' and 'prompt=True' is not allowed")]):

      with self.assertRaises(err, msg="(row {})".format(idx)) as ctx:
        import_rsa_privatekey_from_file(*args, **kwargs)

      self.assertTrue(err_msg in str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))

    # Error on encrypted but bad pw prompted
    err_msg = "Password was not given but private key is encrypted"
    with self.assertRaises(CryptoError) as ctx, mock.patch(
        "securesystemslib.interface.get_password", return_value="bad_pw"):
      import_rsa_privatekey_from_file(fn_encrypted)

    self.assertTrue(err_msg in str(ctx.exception),
        "expected: '{}' got: '{}'".format(err_msg, ctx.exception))

    # Error on bad argument format
    for idx, (args, kwargs) in enumerate([
          ([123456], {}), # bad path
          ([fn_default], {"scheme": 123456}), # bad scheme
          ([fn_default], {"scheme": "bad scheme"}) # bad scheme
        ]):
      with self.assertRaises(FormatError, msg="(row {})".format(idx)):
        import_rsa_publickey_from_file(*args, **kwargs)
      with self.assertRaises(FormatError, msg="(row {})".format(idx)):
        import_rsa_privatekey_from_file(*args, **kwargs)

    # bad password
    with self.assertRaises(FormatError):
      import_rsa_privatekey_from_file(fn_default, password=123456)

    # bad prompt
    with self.assertRaises(FormatError):
      import_rsa_privatekey_from_file(fn_default, prompt="not-a-bool")



  def test_ed25519(self):
    """Test ed25519 key _generation and import interface functions. """

    # TEST: Generate default keys and import
    # Assert location and format
    fn_default = "default"
    fn_default_ret = _generate_and_write_ed25519_keypair(filepath=fn_default)

    pub = import_ed25519_publickey_from_file(fn_default + ".pub")
    priv = import_ed25519_privatekey_from_file(fn_default)

    self.assertEqual(fn_default, fn_default_ret)
    self.assertTrue(ED25519KEY_SCHEMA.matches(pub))
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))
    self.assertTrue(ED25519KEY_SCHEMA.matches(priv))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])


    # TEST: Generate unencrypted keys with empty prompt
    # Assert importable with empty prompt password and without password
    fn_empty_prompt = "empty_prompt"
    with mock.patch("securesystemslib.interface.get_password", return_value=""):
      _generate_and_write_ed25519_keypair(filepath=fn_empty_prompt)
      import_ed25519_privatekey_from_file(fn_empty_prompt, prompt=True)
    import_ed25519_privatekey_from_file(fn_empty_prompt)


    # TEST: Generate keys with auto-filename, i.e. keyid
    # Assert filename is keyid
    fn_keyid = _generate_and_write_ed25519_keypair()
    pub = import_ed25519_publickey_from_file(fn_keyid + ".pub")
    priv = import_ed25519_privatekey_from_file(fn_keyid)
    self.assertTrue(
        os.path.basename(fn_keyid) == pub["keyid"] == priv["keyid"])


    # TEST: Generate two keypairs with encrypted private keys using ...
    pw = "pw"
    fn_encrypted = "encrypted"
    fn_prompt = "prompt"
    # ... a passed pw ...
    _generate_and_write_ed25519_keypair(filepath=fn_encrypted, password=pw)
    with mock.patch("securesystemslib.interface.get_password", return_value=pw):
      # ... and a prompted pw.
      _generate_and_write_ed25519_keypair(filepath=fn_prompt, prompt=True)

      # Assert that both private keys are importable using the prompted pw ...
      import_ed25519_privatekey_from_file(fn_prompt, prompt=True)
      import_ed25519_privatekey_from_file(fn_encrypted, prompt=True)

    # ... and the passed pw.
    import_ed25519_privatekey_from_file(fn_prompt, password=pw)
    import_ed25519_privatekey_from_file(fn_encrypted, password=pw)


    # TEST: Import existing keys with encrypted private key (test regression)
    # Assert format
    pub = import_ed25519_publickey_from_file(self.path_ed25519 + ".pub")
    priv = import_ed25519_privatekey_from_file(self.path_ed25519, "password")

    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))
    self.assertTrue(ED25519KEY_SCHEMA.matches(pub))
    self.assertTrue(ED25519KEY_SCHEMA.matches(priv))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])


    # TEST: Unexpected behavior
    # FIXME: Should 'import_ed25519_publickey_from_file' be able to import a
    # a non-encrypted ed25519 private key? I think it should not, but it is:
    priv = import_ed25519_publickey_from_file(fn_default)
    self.assertTrue(ED25519KEY_SCHEMA.matches(priv))
    self.assertTrue(priv["keyval"]["private"])

    # FIXME: Should 'import_ed25519_privatekey_from_file' be able to import a
    # an ed25519 public key? I think it should not, but it is:
    pub = import_ed25519_privatekey_from_file(fn_default + ".pub")
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))


    # TEST: Generation errors
    for idx, (kwargs, err_msg) in enumerate([
        # Error on empty password
        ({"password": ""},
          "encryption password must be 1 or more characters long"),
        # Error on 'password' and 'prompt=True'
        ({"password": pw, "prompt": True},
          "passing 'password' and 'prompt=True' is not allowed")]):

      with self.assertRaises(ValueError, msg="(row {})".format(idx)) as ctx:
        _generate_and_write_ed25519_keypair(**kwargs)

      self.assertEqual(err_msg, str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))

    # Error on bad argument format
    for idx, kwargs in enumerate([
        {"filepath": 123456}, # Not a string
        {"password": 123456}, # Not a string
        {"prompt": "not-a-bool"}]):
      with self.assertRaises(FormatError, msg="(row {})".format(idx)):
        _generate_and_write_ed25519_keypair(**kwargs)


    # TEST: Import errors
    # Error on public key import...
    for idx, (fn, err_msg) in enumerate([
        # Error on invalid json (custom key format)
        (fn_encrypted, "Cannot deserialize to a Python object"),
        # Error on invalid custom key format
        (self.path_no_key, "Missing key" ),
        # Error on invalid key type
        (self.path_ecdsa + ".pub", "Invalid key type loaded")]):
      with self.assertRaises(Error, msg="(row {})".format(idx)) as ctx:
        import_ed25519_publickey_from_file(fn)

      self.assertTrue(err_msg in str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))

    # Error on private key import...
    for idx, (args, kwargs, err, err_msg) in enumerate([
        # Error on not an ed25519 private key
        ([self.path_ecdsa], {}, CryptoError,
          "Malformed Ed25519 key JSON, possibly due to encryption, "
          "but no password provided?"),
        # Error on not encrypted
        ([fn_default], {"password": pw}, CryptoError,
          "Invalid encrypted file."),
        # Error on encrypted but no pw
        ([fn_encrypted], {}, CryptoError,
          "Malformed Ed25519 key JSON, possibly due to encryption, "
          "but no password provided?"),
        # Error on encrypted but empty pw
        ([fn_encrypted], {"password": ""}, CryptoError,
          "Decryption failed."),
        # Error on encrypted but bad pw passed
        ([fn_encrypted], {"password": "bad pw"}, CryptoError,
          "Decryption failed."),
        # Error on pw and prompt
        ([fn_default], {"password": pw, "prompt": True}, ValueError,
          "passing 'password' and 'prompt=True' is not allowed")]):

      with self.assertRaises(err, msg="(row {})".format(idx)) as ctx:
        import_ed25519_privatekey_from_file(*args, **kwargs)

      self.assertTrue(err_msg in str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))


    # Error on encrypted but bad pw prompted
    err_msg = ("Malformed Ed25519 key JSON, possibly due to encryption, "
        "but no password provided?")
    with self.assertRaises(CryptoError) as ctx, mock.patch(
        "securesystemslib.interface.get_password", return_value="bad_pw"):
      import_ed25519_privatekey_from_file(fn_encrypted)

    self.assertTrue(err_msg in str(ctx.exception),
        "expected: '{}' got: '{}'".format(err_msg, ctx.exception))


    # Error on bad path format
    with self.assertRaises(FormatError):
      import_ed25519_publickey_from_file(123456)
    with self.assertRaises(FormatError):
      import_ed25519_privatekey_from_file(123456)

    # Error on bad password format
    with self.assertRaises(FormatError):
      import_ed25519_privatekey_from_file(fn_default, password=123456)

    # Error on bad prompt format
    with self.assertRaises(FormatError):
      import_ed25519_privatekey_from_file(fn_default, prompt="not-a-bool")


  def test_ecdsa(self):
    """Test ecdsa key _generation and import interface functions. """
    # TEST: Generate default keys and import
    # Assert location and format
    fn_default = "default"
    fn_default_ret = _generate_and_write_ecdsa_keypair(filepath=fn_default)

    pub = import_ecdsa_publickey_from_file(fn_default + ".pub")
    priv = import_ecdsa_privatekey_from_file(fn_default)

    self.assertEqual(fn_default, fn_default_ret)
    self.assertTrue(ECDSAKEY_SCHEMA.matches(pub))
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))
    self.assertTrue(ECDSAKEY_SCHEMA.matches(priv))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])

    # TEST: Generate unencrypted keys with empty prompt
    # Assert importable with empty prompt password and without password
    fn_empty_prompt = "empty_prompt"
    with mock.patch("securesystemslib.interface.get_password", return_value=""):
      _generate_and_write_ecdsa_keypair(filepath=fn_empty_prompt)
      import_ecdsa_privatekey_from_file(fn_empty_prompt, prompt=True)
    import_ecdsa_privatekey_from_file(fn_empty_prompt)


    # TEST: Generate keys with auto-filename, i.e. keyid
    # Assert filename is keyid
    fn_keyid = _generate_and_write_ecdsa_keypair()
    pub = import_ecdsa_publickey_from_file(fn_keyid + ".pub")
    priv = import_ecdsa_privatekey_from_file(fn_keyid)
    self.assertTrue(
        os.path.basename(fn_keyid) == pub["keyid"] == priv["keyid"])


    # TEST: Generate two key pairs with encrypted private keys using ...
    pw = "pw"
    fn_encrypted = "encrypted"
    fn_prompt = "prompt"
    # ...  a passed pw ...
    _generate_and_write_ecdsa_keypair(filepath=fn_encrypted, password=pw)
    with mock.patch("securesystemslib.interface.get_password", return_value=pw):
      # ... and a prompted pw.
      _generate_and_write_ecdsa_keypair(filepath=fn_prompt, prompt=True)

      # Assert that both private keys are importable using the prompted pw ...
      import_ecdsa_privatekey_from_file(fn_prompt, prompt=True)
      import_ecdsa_privatekey_from_file(fn_encrypted, prompt=True)

    # ... and the passed pw.
    import_ecdsa_privatekey_from_file(fn_prompt, password=pw)
    import_ecdsa_privatekey_from_file(fn_encrypted, password=pw)


    # TEST: Import existing keys with encrypted private key (test regression)
    # Assert format
    pub = import_ecdsa_publickey_from_file(self.path_ecdsa + ".pub")
    priv = import_ecdsa_privatekey_from_file(self.path_ecdsa, "password")

    self.assertTrue(ECDSAKEY_SCHEMA.matches(pub))
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))
    self.assertTrue(ECDSAKEY_SCHEMA.matches(priv))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])


    # FIXME: Should 'import_ecdsa_publickey_from_file' be able to import a
    # an ed25519 public key? I think it should not, but it is:
    import_ecdsa_publickey_from_file(self.path_ed25519 + ".pub")
    self.assertTrue(ECDSAKEY_SCHEMA.matches(pub))


    # TEST: Generation errors
    for idx, (kwargs, err_msg) in enumerate([
        # Error on empty password
        ({"password": ""},
          "encryption password must be 1 or more characters long"),
        # Error on 'password' and 'prompt=True'
        ({"password": pw, "prompt": True},
          "passing 'password' and 'prompt=True' is not allowed")]):

      with self.assertRaises(ValueError, msg="(row {})".format(idx)) as ctx:
        _generate_and_write_ecdsa_keypair(**kwargs)

      self.assertEqual(err_msg, str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))

    # Error on bad argument format
    for idx, kwargs in enumerate([
        {"filepath": 123456}, # Not a string
        {"password": 123456}, # Not a string
        {"prompt": "not-a-bool"}]):
      with self.assertRaises(FormatError, msg="(row {})".format(idx)):
        _generate_and_write_ecdsa_keypair(**kwargs)


    # TEST: Import errors

    # Error on public key import...
    for idx, (fn, err_msg) in enumerate([
        # Error on invalid json (custom key format)
        (fn_encrypted, "Cannot deserialize to a Python object"),
        # Error on invalid custom key format
        (self.path_no_key, "Missing key")]):
      with self.assertRaises(Error, msg="(row {})".format(idx)) as ctx:
        import_ecdsa_publickey_from_file(fn)

      self.assertTrue(err_msg in str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))


    # Error on private key import...
    for idx, (args, kwargs, err, err_msg) in enumerate([
        # Error on not an ecdsa private key
        ([self.path_ed25519], {}, Error,
          "Cannot deserialize to a Python object"),
        # Error on not encrypted
        ([fn_default], {"password": pw}, CryptoError,
          "Invalid encrypted file."),
        # Error on encrypted but no pw
        ([fn_encrypted], {}, Error,
          "Cannot deserialize to a Python object"),
        # Error on encrypted but empty pw
        ([fn_encrypted], {"password": ""}, CryptoError,
          "Decryption failed."),
        # Error on encrypted but bad pw passed
        ([fn_encrypted], {"password": "bad pw"}, CryptoError,
          "Decryption failed."),
        # Error on pw and prompt
        ([fn_default], {"password": pw, "prompt": True}, ValueError,
          "passing 'password' and 'prompt=True' is not allowed")]):

      with self.assertRaises(err, msg="(row {})".format(idx)) as ctx:
        import_ecdsa_privatekey_from_file(*args, **kwargs)

      self.assertTrue(err_msg in str(ctx.exception),
          "expected: '{}' got: '{}' (row {})".format(
          err_msg, ctx.exception, idx))

    # Error on encrypted but bad pw prompted
    err_msg = ("Decryption failed")
    with self.assertRaises(CryptoError) as ctx, mock.patch(
        "securesystemslib.interface.get_password", return_value="bad_pw"):
      import_ecdsa_privatekey_from_file(fn_encrypted, prompt=True)

    self.assertTrue(err_msg in str(ctx.exception),
        "expected: '{}' got: '{}'".format(err_msg, ctx.exception))


    # Error on bad path format
    with self.assertRaises(FormatError):
      import_ecdsa_publickey_from_file(123456)
    with self.assertRaises(FormatError):
      import_ecdsa_privatekey_from_file(123456)

    # Error on bad password format
    with self.assertRaises(FormatError): # bad password
      import_ecdsa_privatekey_from_file(fn_default, password=123456)

    # Error on bad prompt format
    with self.assertRaises(FormatError):
      import_ecdsa_privatekey_from_file(fn_default, prompt="not-a-bool")



  def test_generate_keypair_wrappers(self):
    """Basic tests for thin wrappers around _generate_and_write_*_keypair.
    See 'test_rsa', 'test_ed25519' and 'test_ecdsa' for more thorough key
    generation tests for each key type.

    """
    key_pw = "pw"
    for idx, (gen, gen_prompt, gen_plain, import_priv, schema) in enumerate([
        (
          generate_and_write_rsa_keypair,
          generate_and_write_rsa_keypair_with_prompt,
          generate_and_write_unencrypted_rsa_keypair,
          import_rsa_privatekey_from_file,
          RSAKEY_SCHEMA
        ),
        (
          generate_and_write_ed25519_keypair,
          generate_and_write_ed25519_keypair_with_prompt,
          generate_and_write_unencrypted_ed25519_keypair,
          import_ed25519_privatekey_from_file,
          ED25519KEY_SCHEMA
        ),
        (
          generate_and_write_ecdsa_keypair,
          generate_and_write_ecdsa_keypair_with_prompt,
          generate_and_write_unencrypted_ecdsa_keypair,
          import_ecdsa_privatekey_from_file,
          ECDSAKEY_SCHEMA)]):

      assert_msg = "(row {})".format(idx)
      # Test generate_and_write_*_keypair creates an encrypted private key
      fn_encrypted = gen(key_pw)
      priv = import_priv(fn_encrypted, key_pw)
      self.assertTrue(schema.matches(priv), assert_msg)

      # Test generate_and_write_*_keypair errors if password is None or empty
      with self.assertRaises(FormatError, msg=assert_msg):
        fn_encrypted = gen(None)
      with self.assertRaises(ValueError, msg=assert_msg):
        fn_encrypted = gen("")

      # Test generate_and_write_*_keypair_with_prompt creates encrypted private
      # key
      with mock.patch(
          "securesystemslib.interface.get_password", return_value=key_pw):
        fn_prompt = gen_prompt()
      priv = import_priv(fn_prompt, key_pw)
      self.assertTrue(schema.matches(priv), assert_msg)

      # Test generate_and_write_*_keypair_with_prompt creates unencrypted
      # private key if no password is entered
      with mock.patch(
          "securesystemslib.interface.get_password", return_value=""):
        fn_empty_prompt = gen_prompt()
      priv = import_priv(fn_empty_prompt)
      self.assertTrue(schema.matches(priv), assert_msg)

      # Test generate_and_write_unencrypted_*_keypair doesn't encrypt
      fn_unencrypted = gen_plain()
      priv = import_priv(fn_unencrypted)
      self.assertTrue(schema.matches(priv), assert_msg)



  def test_import_publickeys_from_file(self):
    """Test import multiple public keys with different types. """

    # Successfully import key dict with one key per supported key type
    key_dict = import_publickeys_from_file([
        self.path_rsa + ".pub",
        self.path_ed25519  + ".pub",
        self.path_ecdsa  + ".pub"],
        [KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA])

    ANY_PUBKEY_DICT_SCHEMA.check_match(key_dict)
    self.assertListEqual(
        sorted([key["keytype"] for key in key_dict.values()]),
        sorted([KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA])
      )

    # Successfully import default rsa key
    key_dict = import_publickeys_from_file([self.path_rsa + ".pub"])
    ANY_PUBKEY_DICT_SCHEMA.check_match(key_dict)
    RSAKEY_SCHEMA.check_match(
        list(key_dict.values()).pop())

    # Bad default rsa key type for ed25519
    with self.assertRaises(Error):
      import_publickeys_from_file([self.path_ed25519 + ".pub"])

    # Bad ed25519 key type for rsa key
    with self.assertRaises(Error):
      import_publickeys_from_file(
          [self.path_rsa + ".pub"], [KEY_TYPE_ED25519])

    # Unsupported key type
    with self.assertRaises(FormatError):
      import_publickeys_from_file(
          [self.path_ed25519 + ".pub"], ["KEY_TYPE_UNSUPPORTED"])

    # Mismatching arguments lists lenghts
    with self.assertRaises(FormatError):
      import_publickeys_from_file(
          [self.path_rsa + ".pub", self.path_ed25519 + ".pub"],
          [KEY_TYPE_ED25519])


  def test_import_privatekey_from_file(self):
    """Test generic private key import function. """

    pw = "password"
    for idx, (path, key_type, key_schema) in enumerate([
        (self.path_rsa, None, RSAKEY_SCHEMA), # default key type
        (self.path_rsa, KEY_TYPE_RSA, RSAKEY_SCHEMA),
        (self.path_ed25519, KEY_TYPE_ED25519, ED25519KEY_SCHEMA),
        (self.path_ecdsa, KEY_TYPE_ECDSA, ECDSAKEY_SCHEMA)]):

      # Successfully import key per supported type, with ...
      # ... passed password
      key = import_privatekey_from_file(path, key_type=key_type, password=pw)
      self.assertTrue(key_schema.matches(key), "(row {})".format(idx))

      # ... entered password on mock-prompt
      with mock.patch("securesystemslib.interface.get_password", return_value=pw):
        key = import_privatekey_from_file(path, key_type=key_type, prompt=True)
      self.assertTrue(key_schema.matches(key), "(row {})".format(idx))

    # Error on wrong key for default key type
    with self.assertRaises(Error):
      import_privatekey_from_file(self.path_ed25519, password=pw)

    # Error on unsupported key type
    with self.assertRaises(FormatError):
      import_privatekey_from_file(
          self.path_rsa, key_type="KEY_TYPE_UNSUPPORTED", password=pw)



# Run the test cases.
if __name__ == '__main__':
  unittest.main()
