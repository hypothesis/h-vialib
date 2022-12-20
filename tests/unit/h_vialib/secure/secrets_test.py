import pytest
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad

from h_vialib.secure import SecureSecrets


class TestSecureSecrets:
    def test_encrypt_dict_round_trip(self, secure_secrets):
        payload_dict = {"some": "data"}

        encrypted = secure_secrets.encrypt_dict(payload_dict)

        assert secure_secrets.decrypt_dict(encrypted) == payload_dict

    def test_encrypt_dict(self, secure_secrets, secret, AES, Random, base64, json):
        payload_dict = {"some": "data"}

        encrypted = secure_secrets.encrypt_dict(payload_dict)

        Random.new.return_value.read.assert_called_once_with(AES.block_size)
        AES.new.assert_called_once_with(
            pad(secret, 16), AES.MODE_CFB, Random.new.return_value.read.return_value
        )

        AES.new.return_value.encrypt.assert_called_once_with(
            json.dumps.return_value.encode.return_value
        )
        json.dumps.assert_called_with(
            {
                "iv": base64.urlsafe_b64encode.return_value.decode.return_value,
                "payload": base64.urlsafe_b64encode.return_value.decode.return_value,
            }
        )
        assert encrypted == json.dumps.return_value

    def test_decrypt_dict(self, secure_secrets, secret, AES, base64, json):
        plain_text_dict = secure_secrets.decrypt_dict("payload")

        AES.new.assert_called_once_with(
            pad(secret, 16), AES.MODE_CFB, base64.urlsafe_b64decode.return_value
        )
        AES.new.return_value.decrypt.assert_called_once_with(
            base64.urlsafe_b64decode.return_value
        )
        assert plain_text_dict == json.loads.return_value

    @pytest.fixture
    def secret(self):
        return get_random_bytes(12)

    @pytest.fixture
    def secure_secrets(self, secret):
        return SecureSecrets(secret)

    @pytest.fixture
    def AES(self, patch):
        return patch("h_vialib.secure.secrets.AES")

    @pytest.fixture
    def Random(self, patch):
        return patch("h_vialib.secure.secrets.Random")

    @pytest.fixture
    def base64(self, patch):
        return patch("h_vialib.secure.secrets.base64")

    @pytest.fixture
    def json(self, patch):
        return patch("h_vialib.secure.secrets.json")
