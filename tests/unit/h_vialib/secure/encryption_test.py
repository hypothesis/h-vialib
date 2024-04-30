import pytest

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
        jwe.encrypt_compact.assert_called_once_with(
            {"alg": encryption.JWE_ALGORITHM, "enc": encryption.JWE_ENCRYPTION},
            json.dumps.return_value.encode.return_value,
            secret.ljust(32),
        )
        assert encrypted == jwe.encrypt_compact.return_value

    def test_decrypt_dict(self, encryption, secret, json, jwe):
        plain_text_dict = encryption.decrypt_dict("payload")

        jwe.decrypt_compact.assert_called_once_with("payload", secret.ljust(32))
        json.loads.assert_called_once_with(jwe.decrypt_compact.return_value.plaintext)
        assert plain_text_dict == json.loads.return_value

    def test_decrypt_dict_hardcoded(self, encryption):
        # Copied from the output of decrypt_dict.
        # Useful to check backwards compatibility when updating the crypto backend
        encrypted = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..q7UXaHtenyFA5VD3QhrxXA.gkAmUrzmW5UFpuF_tZLmcUzUfS9FuLAiV_xqRJBVJ3Y.U42rUD65NVjH-SoFfeDoOw"

        plain_text_dict = encryption.decrypt_dict(encrypted)

        assert plain_text_dict == {"some": "data"}

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
