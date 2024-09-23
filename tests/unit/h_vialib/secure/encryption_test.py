import pytest

from h_vialib.secure import Encryption


class TestEncryption:
    """Tests for h_vialib.secure.encryption that *do not* patch joserfc."""

    def test_encrypt_dict_decrypt_dict_round_trip(self, encryption):
        payload_dict = {"some": "data"}

        encrypted = encryption.encrypt_dict(payload_dict)

        assert encryption.decrypt_dict(encrypted) == payload_dict

    def test_decrypt_dict_hardcoded(self, encryption):
        # Copied from the output of decrypt_dict.
        # Useful to check backwards compatibility when updating the crypto backend
        encrypted = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..q7UXaHtenyFA5VD3QhrxXA.gkAmUrzmW5UFpuF_tZLmcUzUfS9FuLAiV_xqRJBVJ3Y.U42rUD65NVjH-SoFfeDoOw"

        plain_text_dict = encryption.decrypt_dict(encrypted)

        assert plain_text_dict == {"some": "data"}


class TestEncryptionPatched:
    """Tests for h_vialib.secure.encryption that patch joserfc."""

    # pylint:disable=too-many-positional-arguments
    def test_encrypt_dict(self, encryption, secret, OctKey, json, jwe):
        payload_dict = {"some": "data"}

        encrypted = encryption.encrypt_dict(payload_dict)

        OctKey.import_key.assert_called_once_with(secret.ljust(32))
        json.dumps.assert_called_with(payload_dict)
        jwe.encrypt_compact.assert_called_once_with(
            {"alg": encryption.JWE_ALGORITHM, "enc": encryption.JWE_ENCRYPTION},
            json.dumps.return_value.encode.return_value,
            OctKey.import_key.return_value,
        )
        assert encrypted == jwe.encrypt_compact.return_value

    # pylint:disable=too-many-positional-arguments
    def test_decrypt_dict(self, encryption, secret, json, jwe, OctKey):
        plain_text_dict = encryption.decrypt_dict("payload")

        OctKey.import_key.assert_called_once_with(secret.ljust(32))
        jwe.decrypt_compact.assert_called_once_with(
            "payload", OctKey.import_key.return_value
        )
        json.loads.assert_called_once_with(jwe.decrypt_compact.return_value.plaintext)
        assert plain_text_dict == json.loads.return_value

    @pytest.fixture(autouse=True)
    def json(self, patch):
        return patch("h_vialib.secure.encryption.json")

    @pytest.fixture(autouse=True)
    def jwe(self, patch):
        return patch("h_vialib.secure.encryption.jwe")

    @pytest.fixture(autouse=True)
    def OctKey(self, patch):
        return patch("h_vialib.secure.encryption.OctKey")


@pytest.fixture
def secret():
    return b"VERY SECRET"


@pytest.fixture
def encryption(secret):
    """Return the h_vialib.encryption.Encryption object to be tested."""
    return Encryption(secret)
