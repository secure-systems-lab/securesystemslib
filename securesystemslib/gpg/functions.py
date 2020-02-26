"""
<Module Name>
  functions.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  publicly-usable functions for exporting public-keys, signing data and
  verifying signatures.
"""
import logging
import time

import securesystemslib.exceptions
import securesystemslib.gpg.common
import securesystemslib.gpg.exceptions
from securesystemslib.gpg.constants import (GPG_EXPORT_PUBKEY_COMMAND,
    GPG_SIGN_COMMAND, SIGNATURE_HANDLERS, FULLY_SUPPORTED_MIN_VERSION, SHA256,
    HAVE_GPG, NO_GPG_MSG)

import securesystemslib.process
import securesystemslib.formats
from securesystemslib.gpg.rsa import CRYPTO

log = logging.getLogger(__name__)

NO_CRYPTO_MSG = "GPG support requires the cryptography library"



def create_signature(content, keyid=None, homedir=None):
  """
  <Purpose>
    Calls the gpg command line utility to sign the passed content with the key
    identified by the passed keyid from the gpg keyring at the passed homedir.

    The executed base command is defined in
    securesystemslib.gpgp.constants.GPG_SIGN_COMMAND.

    NOTE: On not fully supported versions of GPG, i.e. versions below
    securesystemslib.gpg.constants.FULLY_SUPPORTED_MIN_VERSION the returned
    signature does not contain the full keyid. As a work around, we export the
    public key bundle identified by the short keyid to compute the full keyid
    and add it to the returned signature.

  <Arguments>
    content:
            The content to be signed. (bytes)

    keyid: (optional)
            The keyid of the gpg signing keyid. If not passed the default
            key in the keyring is used.

    homedir: (optional)
            Path to the gpg keyring. If not passed the default keyring is used.

  <Exceptions>
    securesystemslib.exceptions.FormatError:
            If the keyid was passed and does not match
            securesystemslib.formats.KEYID_SCHEMA

    ValueError:
            If the gpg command failed to create a valid signature.

    OSError:
            If the gpg command is not present or non-executable.

    securesystemslib.exceptions.UnsupportedLibraryError:
            If the gpg command is not available, or
            the cryptography library is not installed.

    securesystemslib.gpg.exceptions.CommandError:
            If the gpg command returned a non-zero exit code

    securesystemslib.gpg.exceptions.KeyNotFoundError:
            If the used gpg version is not fully supported
            and no public key can be found for short keyid.

  <Side Effects>
    None.

  <Returns>
    The created signature in the format:
    securesystemslib.formats.GPG_SIGNATURE_SCHEMA.

  """
  if not HAVE_GPG: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_GPG_MSG)

  if not CRYPTO: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

  keyarg = ""
  if keyid:
    securesystemslib.formats.KEYID_SCHEMA.check_match(keyid)
    keyarg = "--local-user {}".format(keyid)

  homearg = ""
  if homedir:
    homearg = "--homedir {}".format(homedir).replace("\\", "/")

  command = GPG_SIGN_COMMAND.format(keyarg=keyarg, homearg=homearg)

  process = securesystemslib.process.run(command, input=content, check=False,
      stdout=securesystemslib.process.PIPE,
      stderr=securesystemslib.process.PIPE)

  # TODO: It's suggested to take a look at `--status-fd` for proper error
  # reporting, as there is no clear distinction between the return codes
  # https://lists.gnupg.org/pipermail/gnupg-devel/2005-December/022559.html
  if process.returncode != 0:
    raise securesystemslib.gpg.exceptions.CommandError("Command '{}' returned "
        "non-zero exit status '{}', stderr was:\n{}.".format(process.args,
        process.returncode, process.stderr.decode()))

  signature_data = process.stdout
  signature = securesystemslib.gpg.common.parse_signature_packet(
      signature_data)

  # On GPG < 2.1 we cannot derive the full keyid from the signature data.
  # Instead we try to compute the keyid from the public part of the signing
  # key or its subkeys, identified by the short keyid.
  # parse_signature_packet is guaranteed to return at least one of keyid or
  # short_keyid.
  # Exclude the following code from coverage for consistent coverage across
  # test environments.
  if not signature["keyid"]: # pragma: no cover
    log.warning("The created signature does not include the hashed subpacket"
        " '33' (full keyid). You probably have a gpg version <{}."
        " We will export the public keys associated with the short keyid to"
        " compute the full keyid.".format(FULLY_SUPPORTED_MIN_VERSION))

    short_keyid = signature["short_keyid"]

    # Export public key bundle (master key including with optional subkeys)
    public_key_bundle = export_pubkey(short_keyid, homedir)

    # Test if the short keyid matches the master key ...
    master_key_full_keyid = public_key_bundle["keyid"]
    if master_key_full_keyid.endswith(short_keyid.lower()):
      signature["keyid"] = master_key_full_keyid

    # ... or one of the subkeys, and add the full keyid to the signature dict.
    else:
      for sub_key_full_keyid in list(
          public_key_bundle.get("subkeys", {}).keys()):

        if sub_key_full_keyid.endswith(short_keyid.lower()):
          signature["keyid"] = sub_key_full_keyid
          break

  # If there is still no full keyid something went wrong
  if not signature["keyid"]: # pragma: no cover
    raise ValueError("Full keyid could not be determined for signature '{}'".
        format(signature))

  # It is okay now to remove the optional short keyid to save space
  signature.pop("short_keyid", None)

  return signature


def verify_signature(signature_object, pubkey_info, content):
  """
  <Purpose>
    Verifies the passed signature against the passed content using the
    passed public key, or one of its subkeys, associated by the signature's
    keyid.

    The function selects the appropriate verification algorithm (rsa or dsa)
    based on the "type" field in the passed public key object.

  <Arguments>
    signature_object:
            A signature object in the format:
            securesystemslib.formats.GPG_SIGNATURE_SCHEMA

    pubkey_info:
            A public key object in the format:
            securesystemslib.formats.GPG_PUBKEY_SCHEMA

    content:
            The content to be verified. (bytes)

  <Exceptions>
    securesystemslib.gpg.exceptions.KeyExpirationError:
            if the passed public key has expired

    securesystemslib.exceptions.UnsupportedLibraryError:
            if the cryptography module is unavailable

  <Side Effects>
    None.

  <Returns>
    True if signature verification passes, False otherwise.

  """
  if not CRYPTO: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

  securesystemslib.formats.GPG_PUBKEY_SCHEMA.check_match(pubkey_info)
  securesystemslib.formats.GPG_SIGNATURE_SCHEMA.check_match(signature_object)

  handler = SIGNATURE_HANDLERS[pubkey_info['type']]
  sig_keyid = signature_object["keyid"]

  verification_key = pubkey_info

  # If the keyid on the signature matches a subkey of the passed key,
  # we use that subkey for verification instead of the master key.
  if sig_keyid in list(pubkey_info.get("subkeys", {}).keys()):
    verification_key = pubkey_info["subkeys"][sig_keyid]


  creation_time = verification_key.get("creation_time")
  validity_period = verification_key.get("validity_period")

  if creation_time and validity_period and \
      creation_time + validity_period < time.time():
    raise securesystemslib.gpg.exceptions.KeyExpirationError(verification_key)

  return handler.verify_signature(
      signature_object, verification_key, content, SHA256)


def export_pubkey(keyid, homedir=None):
  """
  <Purpose>
    Calls gpg command line utility to export the gpg public key bundle
    identified by the passed keyid from the gpg keyring at the passed homedir
    in a securesystemslib-style format.

    NOTE: The identified key is exported including the corresponding master
    key and all subkeys.

    The executed base export command is defined in
    securesystemslib.gpg.constants.GPG_EXPORT_PUBKEY_COMMAND.

  <Arguments>
    keyid:
            The GPG keyid in format: securesystemslib.formats.KEYID_SCHEMA

    homedir: (optional)
            Path to the gpg keyring. If not passed the default keyring is used.

  <Exceptions>
    ValueError:
            if the keyid does not match the required format.

    securesystemslib.exceptions.UnsupportedLibraryError:
            If the gpg command is not available, or
            the cryptography library is not installed.

    securesystemslib.gpg.execeptions.KeyNotFoundError:
            if no key or subkey was found for that keyid.


  <Side Effects>
    None.

  <Returns>
    The exported public key object in the format:
    securesystemslib.formats.GPG_PUBKEY_SCHEMA.

  """
  if not HAVE_GPG: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_GPG_MSG)

  if not CRYPTO: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

  if not securesystemslib.formats.KEYID_SCHEMA.matches(keyid):
    # FIXME: probably needs smarter parsing of what a valid keyid is so as to
    # not export more than one pubkey packet.
    raise ValueError("we need to export an individual key. Please provide a "
        " valid keyid! Keyid was '{}'.".format(keyid))

  homearg = ""
  if homedir:
    homearg = "--homedir {}".format(homedir).replace("\\", "/")

  # TODO: Consider adopting command error handling from `create_signature`
  # above, e.g. in a common 'run gpg command' utility function
  command = securesystemslib.gpg.constants.GPG_EXPORT_PUBKEY_COMMAND.format(
      keyid=keyid, homearg=homearg)
  process = securesystemslib.process.run(command,
      stdout=securesystemslib.process.PIPE,
      stderr=securesystemslib.process.PIPE)

  key_packet = process.stdout
  key_bundle = securesystemslib.gpg.common.get_pubkey_bundle(key_packet, keyid)

  return key_bundle
