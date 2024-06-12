"""JWT based tokens which can be used to create verifiable, expiring tokens."""

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OctKey

from h_vialib.exceptions import InvalidToken, MissingToken
from h_vialib.secure.expiry import as_expires


class SecureToken:
    """A standardized and simplified JWT token."""

    TOKEN_ALGORITHM = "HS256"

    def __init__(self, secret):
        """Initialise a token creator.

        :param secret: The secret to sign and check tokens with
        """
        self._key = OctKey.import_key(secret)

    def create(self, payload=None, expires=None, max_age=None) -> str:
        """Create a secure token.

        :param payload: Dict of information to put in the token
        :param expires: Datetime by which this token with expire
        :param max_age: ... or max age in seconds after which this will expire
        :return: A JWT encoded token as a string

        :raise ValueError: if neither expires nor max_age is specified
        """
        payload["exp"] = int(as_expires(expires, max_age).timestamp())
        return jwt.encode({"alg": self.TOKEN_ALGORITHM}, payload, self._key)

    def verify(self, token: str) -> dict:
        """Decode a token and check for validity.

        :param token: Token string to check
        :return: The token payload if valid

        :raise InvalidToken: If the token is invalid or expired
        :raise MissingToken: If no token is provided
        """
        if not token:
            raise MissingToken("Missing secure token")

        try:
            claims = jwt.decode(token, self._key).claims
            jwt.JWTClaimsRegistry().validate(claims)
        except JoseError as err:
            raise InvalidToken() from err

        return claims
