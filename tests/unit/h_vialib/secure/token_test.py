from datetime import datetime, timedelta

import jwt
import pytest
from h_matchers import Any
from jwt import DecodeError, ExpiredSignatureError, InvalidSignatureError

from h_vialib.exceptions import InvalidToken, MissingToken
from h_vialib.secure.token import SecureToken


def decode_token(token_string):
    return jwt.decode(token_string, "a_very_secret_secret", SecureToken.TOKEN_ALGORITHM)


class TestSecureToken:
    def test_create_works(self, token):
        expires = datetime.now() + timedelta(seconds=10)

        token_string = token.create({"a": 2}, expires=expires)

        assert token_string == Any.string()
        assert decode_token(token_string) == {"a": 2, "exp": Any.int()}

    def test_create_works_with_a_max_age(self, token):
        token_string = token.create({"a": 2}, max_age=10)

        assert token_string == Any.string()
        assert decode_token(token_string) == {"a": 2, "exp": Any.int()}

    def test_create_fails_if_no_expiry_is_set(self, token):
        with pytest.raises(ValueError):
            token.create({})

    def test_verify_decodes_a_good_token(self, token):
        token_string = token.create({"a": 2}, max_age=10)

        decoded = token.verify(token_string)

        assert decoded == {"a": 2, "exp": Any.int()}

    @pytest.mark.parametrize("token_string", (None, ""))
    def test_verify_catches_there_being_no_value(self, token, token_string):
        with pytest.raises(MissingToken):
            token.verify(token_string)

    @pytest.mark.parametrize(
        "exception",
        (
            InvalidSignatureError,
            ExpiredSignatureError,
            DecodeError,
        ),
    )
    def test_verify_translates_errors(self, token, jwt, exception):
        jwt.decode.side_effect = exception
        with pytest.raises(InvalidToken):
            token.verify("fake_token")

    @pytest.fixture
    def token(self):
        return SecureToken("a_very_secret_secret")

    @pytest.fixture
    def jwt(self, patch):
        return patch("h_vialib.secure.token.jwt")
