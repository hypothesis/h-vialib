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

    def decrypt_dict(self, payload: str) -> dict:
        """Decrypts payloads created by `encrypt_dict`."""
        data = jwe.decrypt_compact(payload, self._key).plaintext
        return json.loads(data)
