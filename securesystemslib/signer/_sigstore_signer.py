"""Signer implementation for project sigstore.

"""

import io
import logging
from typing import Any, Dict, Optional, Tuple
from urllib import parse

from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer._signer import (
    Key,
    SecretsHandler,
    Signature,
    Signer,
)

IMPORT_ERROR = "sigstore library required to use 'sigstore-oidc' keys"

logger = logging.getLogger(__name__)


class SigstoreKey(Key):
    """Sigstore verifier.

    NOTE: unstable API - routines and metadata formats may change!
    """

    DEFAULT_KEY_TYPE = "sigstore-oidc"
    DEFAULT_SCHEME = "Fulcio"

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "SigstoreKey":
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")

        for content in ["identity", "issuer"]:
            if content not in keyval or not isinstance(keyval[content], str):
                raise ValueError(
                    f"{content} string required for scheme {scheme}"
                )

        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> Dict:
        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        # pylint: disable=import-outside-toplevel,import-error
        result = None
        try:
            from sigstore.verify import VerificationMaterials, Verifier
            from sigstore.verify.policy import Identity
            from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle

            verifier = Verifier.production()
            identity = Identity(
                identity=self.keyval["identity"], issuer=self.keyval["issuer"]
            )
            bundle = Bundle().from_dict(signature.unrecognized_fields["bundle"])
            materials = VerificationMaterials.from_bundle(
                input_=io.BytesIO(data), bundle=bundle, offline=True
            )
            result = verifier.verify(materials, identity)

        except Exception as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e

        if not result:
            logger.info(
                "Key %s failed to verify sig: %s",
                self.keyid,
                getattr(result, "reason", ""),
            )
            raise UnverifiedSignatureError(
                f"Failed to verify signature by {self.keyid}"
            )


class SigstoreSigner(Signer):
    """Sigstore signer.

    NOTE: unstable API - routines and metadata formats may change!

    All signers should be instantiated with ``Signer.from_priv_key_uri()``.
    Unstable ``SigstoreSigner`` currently requires opt-in via
    ``securesystemslib.signer.SIGNER_FOR_URI_SCHEME``.

    Usage::

        identity = "luk.puehringer@gmail.com"  # change, unless you know pw
        issuer = "https://github.com/login/oauth"

        # Create signer URI and public key for identity and issuer
        uri, public_key = SigstoreSigner.import_(identity, issuer, ambient=False)

        # Load signer from URI -- requires browser login with GitHub
        signer = SigstoreSigner.from_priv_key_uri(uri, public_key)

        # Sign with signer and verify public key
        signature = signer.sign(b"data")
        public_key.verify_signature(signature, b"data")

    The private key URI scheme is "sigstore:?<PARAMS>", where PARAMS is
    optional and toggles ambient credential usage. Example URIs:

    * "sigstore:":
        Sign with ambient credentials.
    * "sigstore:?ambient=false":
        Sign with OAuth2 + OpenID via browser login.

    Arguments:
        token: The OIDC identity token used for signing.
        public_key: The related public key instance.

    Raises:
        UnsupportedLibraryError: sigstore library not found.
    """

    SCHEME = "sigstore"

    def __init__(self, token: str, public_key: Key):
        # TODO: Vet public key
        # - signer eligible for keytype/scheme?
        # - token matches identity/issuer?
        self.public_key = public_key
        self._token = token

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "SigstoreSigner":
        # pylint: disable=import-outside-toplevel
        try:
            from sigstore.oidc import Issuer, detect_credential
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        if not isinstance(public_key, SigstoreKey):
            raise ValueError(f"expected SigstoreKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"SigstoreSigner does not support {priv_key_uri}")

        params = dict(parse.parse_qsl(uri.query))

        if params.get("ambient") == "false":
            # TODO: Restrict oauth flow to use identity/issuer from public_key
            # TODO: Use secrets_handler for identity_token() secret arg
            issuer = Issuer.production()
            token = issuer.identity_token()
        else:
            token = detect_credential()

        return cls(token, public_key)

    @classmethod
    def _get_uri(cls, ambient: bool) -> str:
        return f"{cls.SCHEME}:{'' if ambient else '?ambient=false'}"

    @classmethod
    def import_(
        cls, identity: str, issuer: str, ambient: bool = True
    ) -> Tuple[str, SigstoreKey]:
        """Create public key and signer URI.

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. import_() should be called once and the returned URI and public
        key should be stored for later use.

        Arguments:
            identity: The OIDC identity used to create a signing token.
            issuer: The OIDC issuer URL used to create a signing token.
            ambient: Toggle usage of ambient credentials in returned URI.
        """
        keytype = SigstoreKey.DEFAULT_KEY_TYPE
        scheme = SigstoreKey.DEFAULT_SCHEME
        keyval = {"identity": identity, "issuer": issuer}
        keyid = cls._get_keyid(keytype, scheme, keyval)
        key = SigstoreKey(keyid, keytype, scheme, keyval)
        uri = cls._get_uri(ambient)

        return uri, key

    def sign(self, payload: bytes) -> Signature:
        """Signs payload using the OIDC token on the signer instance.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from sigstore-python.

        Returns:
            Signature.

            NOTE: The relevant data is in `unrecognized_fields["bundle"]`.

        """
        # pylint: disable=import-outside-toplevel
        try:
            from sigstore.sign import Signer as _Signer
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        signer = _Signer.production()
        result = signer.sign(io.BytesIO(payload), self._token)
        # TODO: Ask upstream if they can make this public
        bundle = result._to_bundle()  # pylint: disable=protected-access

        return Signature(
            self.public_key.keyid,
            bundle.message_signature.signature.hex(),
            {"bundle": bundle.to_dict()},
        )
