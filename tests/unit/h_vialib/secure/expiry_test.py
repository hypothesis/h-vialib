from datetime import datetime, timedelta, timezone

import pytest

from h_vialib.secure.expiry import YEAR_ZERO, as_expires, quantized_expiry


class TestQuantizedExpiry:
    @pytest.mark.parametrize("max_age", (99, timedelta(seconds=99)))
    def test_it_is_quantized(self, max_age):
        expires = quantized_expiry(max_age=max_age, divisions=3)

        assert isinstance(expires, datetime)
        diff = expires - YEAR_ZERO
        assert diff.total_seconds() % (99 / 3) == 0

    def test_it_is_in_the_range_we_expect(self):
        now = datetime.now(tz=timezone.utc)
        expires = quantized_expiry(max_age=120, divisions=4)

        diff = expires - now

        # It's in the future
        assert diff > timedelta(seconds=0)
        # It's at least max_age * divisions - 1 / divisions
        assert diff >= timedelta(seconds=120 * (3 / 4))
        # It's at most max_age
        assert diff <= timedelta(seconds=120)

    @pytest.mark.parametrize("max_age", (None, "foo"))
    def test_it_raises_with_invalid_max_age(self, max_age):
        with pytest.raises(ValueError):
            quantized_expiry(max_age=max_age)


class TestAsExpires:
    def test_it_passes_through_expiry(self):
        expires = datetime.utcnow()

        assert as_expires(expires, None) == expires

    def test_it_raises_if_expires_is_not_valid(self):
        with pytest.raises(ValueError):
            as_expires("not a date", None)

    def test_it_raises_if_max_age_is_not_valid(self):
        with pytest.raises(ValueError):
            as_expires(None, "not a delta")

    def test_it_raise_if_no_value_is_provided(self):
        with pytest.raises(ValueError):
            as_expires(None, None)

    @pytest.mark.parametrize("max_age", (30, timedelta(seconds=30)))
    def test_it_calculates_an_offset(self, datetime, now, max_age):
        result = as_expires(None, max_age=max_age)

        assert result == now + timedelta(seconds=30)

    @pytest.fixture
    def now(self):
        return datetime.utcnow()

    @pytest.fixture
    def datetime(self, patch, now):
        datetime = patch("h_vialib.secure.expiry.datetime")
        datetime.utcnow.return_value = now

        return datetime
