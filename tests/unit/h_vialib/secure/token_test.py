from datetime import datetime, timedelta, timezone

import jwt
import pytest
from h_matchers import Any
from jwt import DecodeError, ExpiredSignatureError, InvalidSignatureError

from h_vialib.exceptions import InvalidToken, MissingToken
from h_vialib.secure.token import SecureToken, SecureURLToken, ViaSecureURLToken


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


class TestSecureURLToken:
    def test_create_normalizes_and_packs_the_url(self, token):
        expires = datetime.now() + timedelta(seconds=10)

        token_string = token.create("http://example.com", {"a": 2}, expires)

        assert token_string == Any.string()
        assert decode_token(token_string) == {
            "url": "http://example.com/",
            "a": 2,
            "exp": Any.int(),
        }

    @pytest.mark.parametrize("url", (None, ""))
    def test_create_requires_the_url(self, token, url):
        with pytest.raises(ValueError):
            token.create(url, {}, max_age=10)

    def test_verify_works_with_a_matching_url(self, token):
        token_string = token.create("http://example.com", {}, max_age=10)

        decoded = token.verify(token_string, "http://example.com/")

        assert decoded == Any.dict.containing({"url": "http://example.com/"})

    def test_verify_fails_if_there_is_no_url_in_the_token(self, token):
        no_url_token = SecureToken(token._secret).create({}, max_age=10)

        with pytest.raises(InvalidToken):
            token.verify(no_url_token, "http://any.example.com/")

    def test_verify_fails_if_there_is_url_mismatch(self, token):
        token_string = token.create("http://example.com", {}, max_age=10)

        with pytest.raises(InvalidToken):
            token.verify(token_string, "http://DIFFERENT.example.com/")

    @pytest.mark.parametrize(
        "url,normalized",
        (
            ("http://example.com/", "http://example.com/"),
            ("http://example.com", "http://example.com/"),
            ("http://example.com]", "http://example.com]"),
        ),
    )
    @pytest.mark.parametrize("query_string", ("", "?a=b"))
    def test_normalize_url(self, token, url, normalized, query_string):
        result = token.normalize_url(url + query_string)

        assert result == normalized + query_string

    @pytest.fixture
    def token(self):
        return SecureURLToken("a_very_secret_secret")


class TestViaSecureURLToken:
    def test_create_works(self, token):
        token_string = token.create("http://example.com?via.config=blah")

        assert token_string == Any.string()
        assert decode_token(token_string) == {
            "url": "http://example.com/",
            "exp": Any.int(),
        }

    def test_create_uses_a_quantized_expiry(self, token, quantized_expiry):
        quantized_expiry.return_value = datetime.now(tz=timezone.utc)

        token_string = token.create("*any*")

        quantized_expiry.assert_called_once_with(token.MAX_AGE)
        assert decode_token(token_string) == Any.dict.containing(
            {"exp": int(quantized_expiry.return_value.timestamp())}
        )

    def test_normalize_url_strips_via_params(self, token):
        url = token.normalize_url("http://example.com?a=b&via.config=boo")

        assert url == "http://example.com/?a=b"

    @pytest.fixture
    def token(self):
        return ViaSecureURLToken("a_very_secret_secret")

    @pytest.fixture
    def quantized_expiry(self, patch):
        return patch("h_vialib.secure.token.quantized_expiry")
