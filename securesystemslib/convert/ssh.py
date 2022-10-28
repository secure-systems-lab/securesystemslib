"""
This module contains functions to import OpenSSH keys.
"""

import re
import typing

from cryptography.hazmat.primitives.serialization.ssh import (
    load_ssh_private_key,
    load_ssh_public_key,
)

from .hazmat import import_hazmat_key

openssh_text_format_marker_re = re.compile(
    b"^-{2,}BEGIN OPENSSH PRIVATE KEY-{2,}$"
)


def import_ssh_key(
    key: typing.Union[str, bytes], password: typing.Optional[bytes] = None
):
    """
    <Purpose>
      Imports either a public or a private key in OpenSSH format

    <Arguments>
      key:
        A string in OpenSSH format, usually Base64-encoded.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

      securesystemslib.exceptions.UnsupportedAlgorithmError, if 'pem' specifies
      an unsupported key type.

    <Side Effects>
      None.

    <Returns>
      A dictionary containing the keys, conforming to 'securesystemslib.formats.KEY_SCHEMA'.
    """

    if isinstance(key, str):
        key = key.encode("utf-8")

    first_line = key.split(b"\n", 1)[0]
    if openssh_text_format_marker_re.match(first_line):
        return import_hazmat_key(load_ssh_private_key(key, password))

    return import_hazmat_key(load_ssh_public_key(key))
