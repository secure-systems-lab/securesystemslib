"""Internal utilities"""

import base64
import binascii


def b64enc(data: bytes) -> str:
    """To encode byte sequence into base64 string

    Arguments:
        data: Byte sequence to encode

    Exceptions:
        TypeError: If "data" is not byte sequence

    Returns:
        base64 string
    """

    return base64.standard_b64encode(data).decode("utf-8")


def b64dec(string: str) -> bytes:
    """To decode byte sequence from base64 string

    Arguments:
        string: base64 string to decode

    Raises:
        binascii.Error: If invalid base64-encoded string

    Returns:
        A byte sequence
    """

    data = string.encode("utf-8")
    try:
        return base64.b64decode(data, validate=True)
    except binascii.Error:
        # altchars for urlsafe encoded base64 - instead of + and _ instead of /
        return base64.b64decode(data, altchars=b"-_", validate=True)
