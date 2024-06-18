import json

from joserfc import jwe
from joserfc.jwk import OctKey


class Encryption:
    JWE_ALGORITHM = "dir"
    JWE_ENCRYPTION = "A128CBC-HS256"

    def __init__(self, secret: bytes):
        self._key = OctKey.import_key(secret.ljust(32)[:32])

    def encrypt_dict(self, payload: dict) -> str:
        """Encrypt a dictionary as a JWE."""
        protected = {"alg": self.JWE_ALGORITHM, "enc": self.JWE_ENCRYPTION}
        return jwe.encrypt_compact(
            protected, json.dumps(payload).encode("utf-8"), self._key
        )

    def decrypt_dict(self, encrypted_json: str) -> dict:
        """Return `encrypted_json` decrypted and deserialized to a dict."""
        data = jwe.decrypt_compact(encrypted_json, self._key).plaintext

        # This decrypt_dict() method is only used to decrypt dicts from the
        # encrypt_dict() method above, so we know that the decrypted data is
        # always a non-empty dict, never None or {}.
        assert data

        return json.loads(data)
