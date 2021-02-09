"""Create values we can check we created."""

from uuid import uuid4

from h_vialib.secure.token import SecureToken


class RandomSecureNonce(SecureToken):
    """Source of random tokens we can verify we made with expiry."""

    def create(self, expires=None, max_age=None):  # pylint: disable=arguments-differ
        """Return a random nonce. Each call returns a different nonce."""
        return super().create(
            payload={"salt": uuid4().hex}, expires=expires, max_age=max_age
        )


class RepeatableSecureNonce(SecureToken):
    """Source of repeatable tokens which we can verify we made with expiry."""

    def create(self, expires=None):  # pylint: disable=arguments-differ
        """Create a repeatable nonce based on the expiry."""
        return super().create({}, expires=expires)
