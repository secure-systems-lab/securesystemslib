"""Signer utils for internal use."""

from typing import Any, Dict, Union

from securesystemslib.exceptions import FormatError
from securesystemslib.formats import encode_canonical
from securesystemslib.hash import digest


def compute_default_keyid(keytype: str, scheme, keyval: Dict[str, Any]) -> str:
    """Return sha256 hexdigest of the canonical json of the key."""
    data: Union[str, None] = encode_canonical(
        {
            "keytype": keytype,
            "scheme": scheme,
            "keyval": keyval,
        }
    )
    if isinstance(data, str):
        byte_data: bytes = data.encode("utf-8")
    else:
        raise FormatError("Failed to encode data into canonical json")
    hasher = digest("sha256")
    hasher.update(byte_data)
    return hasher.hexdigest()
