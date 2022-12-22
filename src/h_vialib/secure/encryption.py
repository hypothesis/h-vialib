import json

from jose import constants, jwe


class Encryption:
    JWE_ALGORITHM = constants.ALGORITHMS.DIR
    JWE_ENCRYPTION = constants.ALGORITHMS.A128CBC_HS256

    def __init__(self, secret: bytes):
        self._secret = secret.ljust(32)[:32]

    def encrypt_dict(self, payload: dict) -> str:
        """Encrypt a dictionary as a JWE."""

        return jwe.encrypt(
            json.dumps(payload),
            self._secret,
            algorithm=self.JWE_ALGORITHM,
            encryption=self.JWE_ENCRYPTION,
        ).decode("utf-8")

    def decrypt_dict(self, payload: str) -> dict:
        """Decrypts payloads created by `encrypt_dict`."""

        return json.loads(jwe.decrypt(payload, self._secret))
