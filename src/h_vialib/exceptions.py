"""Exceptions."""


class InvalidToken(Exception):
    """A security check has failed on a token."""


class MissingToken(InvalidToken):
    """An expected token is missing."""

    # The missing token is a child of InvalidToken so you can distinguish
    # between the two, or catch them together as you see fit
