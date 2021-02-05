"""JWT based tokens which can be used to create verifiable, expiring tokens."""

from urllib.parse import urlparse, urlunparse

import jwt
from jwt import DecodeError, ExpiredSignatureError, InvalidSignatureError

from h_vialib import Configuration
from h_vialib.exceptions import InvalidToken, MissingToken
from h_vialib.secure.expiry import as_expires, quantized_expiry


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


class SecureURLToken(SecureToken):
    """A secure token used for signing and checking URLs."""

    def create(
        self, url, payload, expires=None, max_age=None
    ):  # pylint: disable=arguments-differ
        """Create a secure token.

        :param url: The URL to include in the signature
        :param payload: Dict of information to put in the token
        :param expires: Datetime by which this token with expire
        :param max_age: ... or max age in seconds after which this will expire
        :return: A JWT encoded token as a string

        :raise ValueError: if neither expires nor max_age is specified, or no
            URL is provided
        """
        if not url:
            raise ValueError("A URL is required to create a token")

        payload["url"] = self.normalize_url(url)

        return super().create(payload, expires, max_age)

    def verify(self, token, comparison_url):  # pylint: disable=arguments-differ
        """Decode a token and check for validity and a matching URL.

        :param token: Token string to check
        :param comparison_url: URL to check against the contents of the token
        :return: The token payload if valid
        :raise InvalidToken: If the token is invalid or expired, or if
            the URLs do not match

        :raise MissingToken: If no token is provided
        """
        decoded = super().verify(token)

        signed_url = decoded.get("url")
        if not signed_url:
            raise InvalidToken("Secure URL token contains no URL")

        comparison_url = self.normalize_url(comparison_url)
        if signed_url != comparison_url:
            raise InvalidToken(
                f"Secure URL token path mismatch: Got '{comparison_url}' expected '{signed_url}'"
            )

        return decoded

    @classmethod
    def normalize_url(cls, url):
        """Normalize a URL for comparison."""

        try:
            parts = urlparse(url)
        except ValueError:
            # This URL is unparseable, so this is the best we can do
            return url

        # Ensure that http://example.com and http://example.com/ are considered
        # the same
        if not parts.path:
            parts = parts._replace(path="/")

        return urlunparse(parts)


class ViaSecureURLToken(SecureURLToken):
    """A token for signing proxied URLs."""

    MAX_AGE = 60 * 60  # An hour

    def create(self, proxied_url):  # pylint: disable=arguments-differ
        """Create a secure token for a Via proxied URL.

        :param proxied_url: The URL you intend to proxy.
        :return: A JWT encoded token as a string
        """
        return super().create(
            proxied_url, payload={}, expires=quantized_expiry(self.MAX_AGE)
        )

    @classmethod
    def normalize_url(cls, url):
        """Normalize a URL for comparison."""

        # We strip any Via config off before comparison, to ensure config
        # doesn't change the token, and to allow the token to be included in
        # that config
        return Configuration.strip_from_url(super().normalize_url(url))
