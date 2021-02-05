"""Functions for calculating expiry."""

from datetime import datetime, timedelta, timezone

# An arbitrary time in the past to quantize our expiry times to
YEAR_ZERO = datetime(year=2020, month=1, day=1, tzinfo=timezone.utc)


def quantized_expiry(max_age, divisions=2):
    """Create a quantized expiry time.

    This allows you to repeatedly issue the same expiry time over a period of
    time, which can be useful for generating more stable tokens, which in turn
    can help with caching.

    The idea here is to issue times which are always in the future, but "snap"
    to fixed points `max_age / divisions` seconds long. The division is
    required to ensure that your tokens vary between being the `max_age` in the
    future and a fixed percentage of that age, rather than 0 without it.

    A higher division will guarantee that more of your max age is preserved as
    the minimum bound, but will issue more different tokens in that period.

    The exact time returned is guaranteed be:
        * A multiple of `max_age / divisions`
        * At most `max_age` seconds in the future
        * At least `max_age * (divisions - 1) / divisions` seconds in the
        future

    :param max_age: The maximum age to issue (int, or timedelta)
    :param divisions: How many subdivisions of the max age for quantization
    :return: A datetime object
    """
    max_age = _to_int(max_age)
    quantization = max_age // divisions

    # Timezone aware dates are annoying, but allow you to include the TZ in a
    # serialisation, which is required for cookie expiry times
    delta = datetime.now(tz=timezone.utc) - YEAR_ZERO

    quantized_expire = (delta.total_seconds() // quantization) * quantization

    return YEAR_ZERO + timedelta(seconds=quantized_expire + max_age)


def as_expires(expires=None, max_age=None):
    """Convert either an expiry time or max age to an expiry time.

    :param expires: Datetime by which this token will expire
    :param max_age: ... or max age in seconds after which this will expire
        (or timedelta)
    :return: An expiry datetime object

    :raise ValueError: if neither expires nor max_age is specified
    """

    if expires:
        if not isinstance(expires, datetime):
            raise ValueError(
                f"Expected expires to be a datetime, not: '{type(expires)}'"
            )
        return expires

    if not max_age:
        raise ValueError("You must specify an expiry time")

    return datetime.now(tz=timezone.utc) + _to_delta(max_age)


def _to_int(max_age):
    if max_age is None:
        raise ValueError("max_age cannot be None")

    if isinstance(max_age, int):
        return max_age

    if isinstance(max_age, timedelta):
        return int(max_age.total_seconds())

    raise ValueError(
        f"Expected max_age to be a timedelta or int, not: '{type(max_age)}'"
    )


def _to_delta(max_age):
    if isinstance(max_age, timedelta):
        return max_age

    if isinstance(max_age, int):
        return timedelta(seconds=max_age)

    raise ValueError(
        f"Expected max_age to be a timedelta or int, not: '{type(max_age)}'"
    )
