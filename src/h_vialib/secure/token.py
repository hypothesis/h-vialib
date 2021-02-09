"""JWT based tokens which can be used to create verifiable, expiring tokens."""

import jwt
from jwt import DecodeError, ExpiredSignatureError, InvalidSignatureError

from h_vialib.exceptions import InvalidToken, MissingToken
from h_vialib.secure.expiry import as_expires


class SecureToken:
    """A standardized and simplified JWT token."""

    TOKEN_ALGORITHM = "HS256"

    def __init__(self, secret):
        """Initialise a token creator.

        :param secret: The secret to sign and check tokens with
        """
        self._secret = secret

    def create(self, payload=None, expires=None, max_age=None):
        """Create a secure token.

        :param payload: Dict of information to put in the token
        :param expires: Datetime by which this token with expire
        :param max_age: ... or max age in seconds after which this will expire
        :return: A JWT encoded token as a string

        :raise ValueError: if neither expires nor max_age is specified
        """
        payload["exp"] = as_expires(expires, max_age)

        return jwt.encode(payload, self._secret, self.TOKEN_ALGORITHM)

    def verify(self, token):
        """Decode a token and check for validity.

        :param token: Token string to check
        :return: The token payload if valid

        :raise InvalidToken: If the token is invalid or expired
        :raise MissingToken: If no token is provided
        """
        if not token:
            raise MissingToken("Missing secure token")

        try:
            return jwt.decode(token, self._secret, self.TOKEN_ALGORITHM)
        except InvalidSignatureError as err:
            raise InvalidToken("Invalid secure token") from err
        except ExpiredSignatureError as err:
            raise InvalidToken("Expired secure token") from err
        except DecodeError as err:
            raise InvalidToken("Malformed secure token") from err
