import base64
import json
from typing import Tuple

from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad


class Encryption:
    def __init__(self, secret: bytes):
        self._secret = pad(secret, 16)

    def encrypt_dict(self, payload: dict) -> str:
        """
        Encrypt a dictionary using AES.

        The returned string is a json encoded dictionary containing both the AES IV
        and the cipher text.
        """
        dict_json = json.dumps(payload).encode("utf-8")
        aes_iv, encrypted_json = self._encrypt(dict_json)

        return json.dumps(
            {
                "iv": base64.urlsafe_b64encode(aes_iv).decode("utf-8"),
                "payload": base64.urlsafe_b64encode(encrypted_json).decode("utf-8"),
            }
        )

    def decrypt_dict(self, payload: str) -> dict:
        """Decypts payloads created by `encrypt_dict`."""
        payload_dict = json.loads(payload)

        aes_iv = payload_dict.get("iv", "")
        cipher = payload_dict.get("payload", "")

        aes_iv = base64.urlsafe_b64decode(aes_iv)
        cipher = base64.urlsafe_b64decode(cipher)

        return json.loads(self._decrypt(aes_iv, cipher))

    def _decrypt(self, aes_iv, encrypted) -> bytes:
        cipher = AES.new(self._secret, AES.MODE_CFB, aes_iv)
        return cipher.decrypt(encrypted)

    def _encrypt(self, plain_text: bytes) -> Tuple[bytes, bytes]:
        aes_iv = Random.new().read(AES.block_size)
        return (aes_iv, AES.new(self._secret, AES.MODE_CFB, aes_iv).encrypt(plain_text))
