"""Routines for signing and checking URLs."""
import hashlib
from datetime import timedelta
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

from h_vialib.exceptions import InvalidToken
from h_vialib.secure import SecureToken, quantized_expiry


class SecureURL(SecureToken):
    """Sign and check URLs with a JWT."""

    def __init__(self, secret, token_param):
        """Initialise the SecureURL.

        :param secret: Secret to sign and check with
        :param token_param: The URL parameter to use for the token
        """
        super().__init__(secret)
        self._token_param = token_param

    def create(
        self, url, payload, expires=None, max_age=None
    ):  # pylint: disable=arguments-differ
        """Create a signed URL which can be checked with this class.

        The entire URL should be added that you want to sign, without any
        modifications. This will remove any existing signature, create a new
        one, and append it to the URL as the parameter

        :param url: The URL to sign
        :param payload: Dict of extra information to put in the token
        :param expires: Datetime by which this token with expire
        :param max_age: ... or max age in seconds after which this will expire
        :return: A URL with an extra parameter

        :raise ValueError: if neither expires nor max_age is specified, or no
            URL is provided
        """
        if not url:
            raise ValueError("A URL is required to create a token")

        url = self._strip_token(url)

        payload["url"] = url
        token = super().create(payload, expires, max_age)

        return self._add_token(url, token)

    def verify(self, url):  # pylint: disable=arguments-differ
        """Check a URL to see if it's been signed by this service.

        :param url: URL to check
        :return: A dict of details from the token if verified

        :raises InvalidToken: If the token is invalid or the URL does not match
        """
        token = self._get_token(url)
        decoded = super().verify(token)

        signed_url = decoded.get("url")
        if not signed_url:
            raise InvalidToken("Secure URL token contains no URL")

        comparison_url = self._strip_token(url)
        if signed_url != comparison_url:
            raise InvalidToken(
                f"Secure URL token path mismatch: Got '{comparison_url}' expected '{signed_url}'"
            )

        return decoded

    def _get_token(self, url):
        params = dict(parse_qsl(urlparse(url).query))

        return params.get(self._token_param)

    def _strip_token(self, url):
        parsed_url = urlparse(url)
        query = [
            item for item in parse_qsl(parsed_url.query) if item[0] != self._token_param
        ]

        return parsed_url._replace(query=urlencode(query)).geturl()

    def _add_token(self, url, token):
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        query[self._token_param] = [token]

        return parsed_url._replace(query=urlencode(query, doseq=True)).geturl()


class HashedSecureURL(SecureURL):
    """Sign and check URLs with a hash of JWT.

    Tokens are generated by `SecureURL` and hashed with sha256

    As all the information to generate the hashes for comparison needs to be
    present in the URL this class loses:
        - the ability to include extra payload on the JWT token itself
        - can't expire at a relative point in time, only at an absolute `expires`
    """

    def create(
        self,
        url,
        expires=None,
    ):  # pylint: disable=arguments-differ
        """Create a signed URL which can be checked with this class.

        The entire URL should be added that you want to sign, without any
        modifications. This will remove any existing signature, create a new
        one, and append it to the URL as the parameter

        :param url: The URL to sign
        :param expires: Datetime by which this token with expire
        :return: A URL with an extra parameter
        """
        signed_url = super().create(url, {}, expires=expires)

        token = self._get_token(signed_url)
        hashed_token = self._hash_token(token)

        return self._add_token(url, hashed_token)

    @classmethod
    def _hash_token(cls, token):
        return hashlib.sha256(token.encode()).hexdigest()

    def verify(self, url, expires=None):  # pylint: disable=arguments-differ
        """Check a URL to see if it's been signed by this service.

        :param url: URL to check
        :return: A dict of details from the token if verified
        :param expires: Datetime by which this token with expire

        :raises InvalidToken: If the hash present in the URL doesn't match
            the expected value.
        """
        hashed_token = self._get_token(url)

        comparison_url = super().create(url, payload={}, expires=expires)
        comparison_token = self._get_token(comparison_url)
        comparison_hashed_token = self._hash_token(comparison_token)

        if hashed_token != comparison_hashed_token:
            raise InvalidToken("Secure URL hashes don't match")

        # Return contents of the token for compatibility with SecureURL
        return super().verify(comparison_url)


class ViaSecureURL(HashedSecureURL):
    """A token for signing proxied URLs."""

    MAX_AGE = timedelta(hours=1)

    def __init__(self, secret):
        super().__init__(secret, token_param="via.sec")

    def create(self, url):  # pylint: disable=arguments-differ
        """Create a secure token for a Via proxied URL.

        :param url: The whole URL of the request to Via with all params
        :return: `url` with an added (or replaced) `via.sec` hashed signature.
        """
        return super().create(url, expires=quantized_expiry(self.MAX_AGE))

    def verify(self, url):  # pylint: disable=arguments-differ
        """Verify a secure hashed token for a Via proxied URL.

        :param url: The whole URL to verify
        :return: Contents of the hashed JWT
        """

        return super().verify(url, expires=quantized_expiry(self.MAX_AGE))
