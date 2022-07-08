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

from securesystemslib import exceptions
from securesystemslib import formats
from securesystemslib.gpg.common import (
    get_pubkey_bundle, parse_signature_packet)
from securesystemslib.gpg.exceptions import (
    CommandError, KeyExpirationError)
from securesystemslib.gpg.constants import (
    FULLY_SUPPORTED_MIN_VERSION,
    GPG_EXPORT_PUBKEY_COMMAND,
    GPG_SIGN_COMMAND,
    HAVE_GPG,
    NO_GPG_MSG,
    SHA256)
from securesystemslib.gpg.handlers import (
    SIGNATURE_HANDLERS)

from securesystemslib import process
from securesystemslib.gpg.rsa import CRYPTO

log = logging.getLogger(__name__)

NO_CRYPTO_MSG = "GPG support requires the cryptography library"



def create_signature(content, keyid=None, homedir=None):
  """
  <Purpose>
    Calls the gpg command line utility to sign the passed content with the key
    identified by the passed keyid from the gpg keyring at the passed homedir.

    The executed base command is defined in
    securesystemslib.gpg.constants.GPG_SIGN_COMMAND.

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
    raise exceptions.UnsupportedLibraryError(NO_GPG_MSG)

  if not CRYPTO: # pragma: no cover
    raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

  keyarg = ""
  if keyid:
    formats.KEYID_SCHEMA.check_match(keyid)
    keyarg = "--local-user {}".format(keyid)

  homearg = ""
  if homedir:
    homearg = "--homedir {}".format(homedir).replace("\\", "/")

  command = GPG_SIGN_COMMAND.format(keyarg=keyarg, homearg=homearg)

  gpg_process = process.run(command, input=content, check=False,
      stdout=process.PIPE, stderr=process.PIPE)

  # TODO: It's suggested to take a look at `--status-fd` for proper error
  # reporting, as there is no clear distinction between the return codes
  # https://lists.gnupg.org/pipermail/gnupg-devel/2005-December/022559.html
  if gpg_process.returncode != 0:
    raise CommandError("Command '{}' returned "
        "non-zero exit status '{}', stderr was:\n{}.".format(gpg_process.args,
        gpg_process.returncode, gpg_process.stderr.decode()))

  signature_data = gpg_process.stdout
  signature = parse_signature_packet(signature_data)

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
    raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

  formats.GPG_PUBKEY_SCHEMA.check_match(pubkey_info)
  formats.GPG_SIGNATURE_SCHEMA.check_match(signature_object)

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
    raise KeyExpirationError(verification_key)

  return handler.verify_signature(
      signature_object, verification_key, content, SHA256)


def export_pubkey(keyid, homedir=None):
  """Exports a public key from a GnuPG keyring.

  Arguments:
    keyid: An OpenPGP keyid in KEYID_SCHEMA format.
    homedir (optional): A path to the GnuPG home directory. If not set the
        default GnuPG home directory is used.

  Raises:
    ValueError: Keyid is not a string.
    UnsupportedLibraryError: The gpg command or pyca/cryptography are not
        available.
    KeyNotFoundError: No key or subkey was found for that keyid.

  Side Effects:
    Calls system gpg command in a subprocess.

  Returns:
    An OpenPGP public key object in GPG_PUBKEY_SCHEMA format.

  """
  if not HAVE_GPG: # pragma: no cover
    raise exceptions.UnsupportedLibraryError(NO_GPG_MSG)

  if not CRYPTO: # pragma: no cover
    raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

  if not formats.KEYID_SCHEMA.matches(keyid):
    # FIXME: probably needs smarter parsing of what a valid keyid is so as to
    # not export more than one pubkey packet.
    raise ValueError("we need to export an individual key. Please provide a "
        " valid keyid! Keyid was '{}'.".format(keyid))

  homearg = ""
  if homedir:
    homearg = "--homedir {}".format(homedir).replace("\\", "/")

  # TODO: Consider adopting command error handling from `create_signature`
  # above, e.g. in a common 'run gpg command' utility function
  command = GPG_EXPORT_PUBKEY_COMMAND.format(keyid=keyid, homearg=homearg)
  gpg_process = process.run(command, stdout=process.PIPE, stderr=process.PIPE)

  key_packet = gpg_process.stdout
  key_bundle = get_pubkey_bundle(key_packet, keyid)

  return key_bundle


def export_pubkeys(keyids, homedir=None):
  """Exports multiple public keys from a GnuPG keyring.

  Arguments:
    keyids: A list of OpenPGP keyids in KEYID_SCHEMA format.
    homedir (optional): A path to the GnuPG home directory. If not set the
        default GnuPG home directory is used.

  Raises:
    TypeError: Keyids is not iterable.
    ValueError: A Keyid is not a string.
    UnsupportedLibraryError: The gpg command or pyca/cryptography are not
        available.
    KeyNotFoundError: No key or subkey was found for that keyid.

  Side Effects:
    Calls system gpg command in a subprocess.

  Returns:
    A dict of OpenPGP public key objects in GPG_PUBKEY_SCHEMA format as values,
    and their keyids as dict keys.


  """
  public_key_dict = {}
  for gpg_keyid in keyids:
    public_key = export_pubkey(gpg_keyid, homedir=homedir)
    keyid = public_key["keyid"]
    public_key_dict[keyid] = public_key

  return public_key_dict
