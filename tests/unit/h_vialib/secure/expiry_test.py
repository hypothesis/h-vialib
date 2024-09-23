from datetime import datetime as _datetime
from datetime import timedelta, timezone

import pytest
from pytest import param

from h_vialib.secure.expiry import YEAR_ZERO, as_expires, quantized_expiry


class TestQuantizedExpiry:
    @pytest.mark.parametrize("max_age", (99, timedelta(seconds=99)))
    def test_it_is_quantized(self, max_age):
        expires = quantized_expiry(max_age=max_age, divisions=3)

        assert isinstance(expires, _datetime)
        diff = expires - YEAR_ZERO
        assert not diff.total_seconds() % (99 / 3)

    def test_it_is_in_the_range_we_expect(self):
        now = _datetime.now(tz=timezone.utc)
        expires = quantized_expiry(max_age=120, divisions=4)

        diff = expires - now

        # It's in the future
        assert diff > timedelta(seconds=0)
        # It's at least max_age * divisions - 1 / divisions
        assert diff >= timedelta(seconds=120 * (3 / 4))
        # It's at most max_age
        assert diff <= timedelta(seconds=120)

    # pylint:disable=too-many-positional-arguments
    @pytest.mark.parametrize(
        "max_age,divisions,time_offset,expiry_offset",
        (
            # One progression through seconds 0 - 8, max_age=8, divisions=2
            param(8, 2, 0, 8, id="At the start of a period, we get the full offset"),
            param(8, 2, 1, 8, id="Through the period we get the same offset"),
            param(8, 2, 3, 8, id="Right before the change over, we still have it"),
            param(8, 2, 4, 12, id="At max_age/divisions we get a new quantization"),
            param(8, 2, 7, 12, id="And keep that one too"),
            param(8, 2, 8, 16, id="Until we get to the next period"),
            # Specific scenarios
            param(8, 4, 2, 10, id="With more divisions the offset is smaller"),
            param(8, 8, 3, 13, id="With max_age=divisions quantization is 1 second"),
            param(9, 3, 2, 12, id="There's nothing special about even numbers"),
        ),
    )
    def test_quantization(
        self, datetime, max_age, divisions, time_offset, expiry_offset
    ):
        # Set it so that we are time_offset seconds past "YEAR_ZERO", making
        # all of our time offsets small and easy to see
        datetime.now.return_value = YEAR_ZERO + timedelta(seconds=time_offset)

        expires = quantized_expiry(max_age=max_age, divisions=divisions)

        offset = (expires - YEAR_ZERO).seconds
        assert offset, expiry_offset

    @pytest.mark.parametrize("max_age", (None, "foo"))
    def test_it_raises_with_invalid_max_age(self, max_age):
        with pytest.raises(ValueError):
            quantized_expiry(max_age=max_age)


class TestAsExpires:
    def test_it_passes_through_expiry(self):
        expires = _datetime.utcnow()

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
    def test_it_calculates_an_offset(self, datetime, max_age):
        now = datetime.now.return_value = _datetime.utcnow()
        result = as_expires(None, max_age=max_age)

        assert result == now + timedelta(seconds=30)

    @pytest.mark.parametrize("max_age", (30, timedelta(seconds=30)))
    def test_it_returns_times_with_a_timezone(self, max_age):
        result = as_expires(None, max_age=max_age)

        assert result.tzinfo == timezone.utc


@pytest.fixture
def datetime(patch):
    return patch("h_vialib.secure.expiry.datetime")
