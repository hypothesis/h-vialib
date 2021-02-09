from datetime import datetime, timedelta, timezone

import pytest

from h_vialib.exceptions import InvalidToken
from h_vialib.secure import RandomSecureNonce, RepeatableSecureNonce


def in_ten_seconds():
    return datetime.now(tz=timezone.utc) + timedelta(seconds=10)


class TestCommonNonce:
    def test_round_trip(self, nonce):
        nonce_string = nonce.create(expires=in_ten_seconds())

        assert nonce.verify(nonce_string)

    def test_we_can_detect_a_fake(self, nonce):
        real_nonce = nonce.create(expires=in_ten_seconds())

        fake_nonce = (
            real_nonce[:10] + "G" if real_nonce[11] == "F" else "F" + real_nonce[11:]
        )

        with pytest.raises(InvalidToken):
            nonce.verify(fake_nonce)

    @pytest.fixture(params=[RandomSecureNonce, RepeatableSecureNonce])
    def nonce(self, request):
        return request.param("not_a_secret")


class TestRandomSecureNonce:
    def test_two_nonces_are_different(self, nonce):
        expires = in_ten_seconds()

        nonce_1 = nonce.create(expires=expires)
        nonce_2 = nonce.create(expires=expires)

        assert nonce_1 != nonce_2

    @pytest.fixture
    def nonce(self):
        return RandomSecureNonce("not_a_secret")


class TestRepeatableSecureNonce:
    def test_two_nonces_are_the_same(self, nonce):
        expires = in_ten_seconds()

        nonce_1 = nonce.create(expires=expires)
        nonce_2 = nonce.create(expires=expires)

        assert nonce_1 == nonce_2

    @pytest.fixture
    def nonce(self):
        return RepeatableSecureNonce("not_a_secret")
