from datetime import datetime, timezone
from unittest.mock import create_autospec

import pytest

from h_vialib.exceptions import MissingToken
from h_vialib.secure import SecureToken
from h_vialib.secure.cookie import Cookie, TokenBasedCookie


class TestCookie:
    def test_create(self):
        expires = datetime(2010, 11, 21, 4, 34, 38, tzinfo=timezone.utc)

        cookie = Cookie("name").create("value", expires=expires)

        assert cookie == (
            "Set-Cookie",
            "name=value; expires=Sun, 21 Nov 2010 04:34:38 UTC; HttpOnly; Path=/; SameSite=None; Secure",
        )

    def test_create_can_make_a_non_secure_cookie(self):
        header, value = Cookie("name", secure=False).create("value", max_age=10)

        assert "SameSite" not in value
        assert "Secure" not in value

    def test_create_with_max_age(self):
        cookie = Cookie("name").create("value", max_age=321)

        assert cookie == (
            "Set-Cookie",
            "name=value; HttpOnly; Max-Age=321; Path=/; SameSite=None; Secure",
        )

    def test_create_requires_an_expiry(self):
        with pytest.raises(ValueError):
            Cookie("any").create("value", expires=None, max_age=None)

    def test_create_raises_if_the_expiry_has_no_timezone(self):
        with pytest.raises(ValueError):
            Cookie("any").create("value", expires=datetime.now())

    @pytest.mark.parametrize(
        "cookies,value",
        (
            ("noise=irrelevant name=value", "value"),
            ("noise=irrelevant", None),
            ("", None),
            (None, None),
        ),
    )
    def test_verify(self, cookies, value):
        result = Cookie("name").verify(cookies)

        assert result == value


class TestTokenBasedCookie:
    def test_create(self, cookie, token_provider):
        token_provider.create.return_value = "token-value"
        expires = datetime(2010, 11, 21, 4, 34, 38, tzinfo=timezone.utc)

        result = cookie.create(
            payload={"pass-through": "args"},
            expires=expires,
        )

        assert result == (
            "Set-Cookie",
            "name=token-value; expires=Sun, 21 Nov 2010 04:34:38 UTC; HttpOnly; Path=/; SameSite=None; Secure",
        )
        token_provider.create.assert_called_once_with(
            expires=expires,
            payload={"pass-through": "args"},
        )

    def test_verify(self, cookie, token_provider):
        result = cookie.verify("noise=irrelevant name=token-value")

        assert result == token_provider.verify.return_value
        token_provider.verify.assert_called_once_with("token-value")

    def test_verify_raises_if_cookie_missing(self, cookie):
        with pytest.raises(MissingToken):
            cookie.verify("noise=irrelevant")

    @pytest.fixture
    def cookie(self, token_provider):
        return TokenBasedCookie("name", token_provider)

    @pytest.fixture
    def token_provider(self):
        return create_autospec(SecureToken, instance=True, spec_set=True)
