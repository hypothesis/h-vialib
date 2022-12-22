import pytest
from jose import constants

from h_vialib.secure import Encryption


class TestEncryption:
    def test_encrypt_dict_round_trip(self, encryption):
        payload_dict = {"some": "data"}

        encrypted = encryption.encrypt_dict(payload_dict)

        assert encryption.decrypt_dict(encrypted) == payload_dict

    def test_encrypt_dict(self, encryption, secret, json, jwe):
        payload_dict = {"some": "data"}

        encrypted = encryption.encrypt_dict(payload_dict)

        json.dumps.assert_called_with(payload_dict)
        jwe.encrypt.assert_called_once_with(
            json.dumps.return_value,
            secret.ljust(32),
            algorithm=constants.ALGORITHMS.DIR,
            encryption=constants.ALGORITHMS.A128CBC_HS256,
        )
        assert encrypted == jwe.encrypt.return_value.decode.return_value

    def test_decrypt_dict(self, encryption, secret, jwe, json):
        plain_text_dict = encryption.decrypt_dict("payload")

        jwe.decrypt.assert_called_once_with("payload", secret.ljust(32))
        json.loads.assert_called_once_with(jwe.decrypt.return_value)
        assert plain_text_dict == json.loads.return_value

    @pytest.fixture
    def secret(self):
        return b"VERY SECRET"

    @pytest.fixture
    def encryption(self, secret):
        return Encryption(secret)

    @pytest.fixture
    def json(self, patch):
        return patch("h_vialib.secure.encryption.json")

    @pytest.fixture
    def jwe(self, patch):
        return patch("h_vialib.secure.encryption.jwe")
