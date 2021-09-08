from datetime import datetime, timedelta, timezone

import pytest
from h_matchers import Any

from h_vialib.exceptions import InvalidToken, MissingToken
from h_vialib.secure import SecureToken
from h_vialib.secure.url import SecureURL, ViaSecureURL


class TestSecureURL:
    def test_round_tripping(self, secure_url):
        url = "http://example.com?a=1&tok.sec=OLD_TOKEN&a=2"

        signed_url = secure_url.create(url, {"extra": "value"}, max_age=10)
        decoded = secure_url.verify(signed_url)

        assert signed_url == Any.url.matching(url).with_query(
            [("a", "1"), ("a", "2"), ("tok.sec", Any.string())]
        )
        assert decoded == {
            "extra": "value",
            "exp": Any.int(),
        }

    @pytest.mark.parametrize("bad_url", (None, ""))
    def test_create_requires_a_url(self, secure_url, bad_url):
        with pytest.raises(ValueError):
            secure_url.create(bad_url, {}, max_age=10)

    def test_verify_fails_with_a_missing_token(self, secure_url):
        with pytest.raises(MissingToken):
            secure_url.verify("http://example.com")

    @pytest.mark.parametrize("payload", ({}, {"h": "not_a_hash_at_all"}))
    def test_verify_fails_with_bad_tokens(self, secure_url, payload):
        # Use a vanilla secret token to make a broken token
        url = "http://example.com?tok.sec=" + SecureToken("not_a_secret").create(
            payload, max_age=10
        )

        with pytest.raises(InvalidToken):
            secure_url.verify(url)

    def test_hashes_have_a_fixed_length(self, secure_url):
        short_url = "http://example.com"
        long_url = "http://example.com/" + ("path/" * 1000)

        short_secure = secure_url.create(short_url, {}, max_age=10)
        long_secure = secure_url.create(long_url, {}, max_age=10)

        # Check that the extra added to the end of the URL (minus the length
        # of the original URL) is the same
        assert len(short_secure) - len(short_url) == len(long_secure) - len(long_url)

    @pytest.fixture
    def secure_url(self):
        return SecureURL("not_a_secret", "tok.sec")


class TestViaSecureURL:
    @pytest.mark.parametrize(
        "given_max_age,expected_max_age",
        [
            # The default expiry time is one hour.
            (None, timedelta(hours=1)),
            # If a custom expiry time is given it will be used instead.
            (timedelta(hours=25), timedelta(hours=25)),
        ],
    )
    def test_round_tripping(self, quantized_expiry, given_max_age, expected_max_age):
        token = ViaSecureURL("not_a_secret")

        signed_url = token.create("http://example.com?via.sec=OLD_TOKEN", given_max_age)
        decoded = token.verify(signed_url)

        assert signed_url == Any.url.matching(signed_url).with_query(
            {"via.sec": Any.string()}
        )
        quantized_expiry.assert_called_once_with(expected_max_age)
        assert decoded == {
            "exp": int(quantized_expiry.return_value.timestamp()),
        }

    @pytest.fixture
    def quantized_expiry(self, patch):
        quantized_expiry = patch("h_vialib.secure.url.quantized_expiry")
        quantized_expiry.return_value = datetime.now(tz=timezone.utc) + timedelta(
            seconds=10
        )

        return quantized_expiry
