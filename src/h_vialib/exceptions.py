"""Exceptions."""


class TokenException(Exception):
    """A security check has failed on a token."""


class InvalidToken(TokenException):
    """A token is present, but failed one or more checks."""


class MissingToken(TokenException):
    """An expected token is missing."""
