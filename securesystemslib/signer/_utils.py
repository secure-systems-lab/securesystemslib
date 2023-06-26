"""Signer utils for internal use. """

from typing import Any, Dict

from securesystemslib.formats import encode_canonical
from securesystemslib.hash import digest


def compute_default_keyid(keytype: str, scheme, keyval: Dict[str, Any]) -> str:
    """Return sha256 hexdigest of the canonical json of the key."""
    data = encode_canonical(
        {
            "keytype": keytype,
            "scheme": scheme,
            "keyval": keyval,
        }
    ).encode("utf-8")
    hasher = digest("sha256")
    hasher.update(data)
    return hasher.hexdigest()
