"""Routines for signing and checking URLs."""

from base64 import b64encode
from datetime import timedelta
from hashlib import blake2b
from hmac import compare_digest
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

from h_vialib.exceptions import InvalidToken
from h_vialib.secure import SecureToken, quantized_expiry


class SecureURL(SecureToken):
    """Sign and check URLs with a JWT."""

    # We want to keep our tokens as skinny as possible, so we'll use a short
    # name for the hash parameter we store inside the JWT
    _HASH_PARAM = "h"

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

        payload[self._HASH_PARAM] = self._hash_url_v1(url)

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

        decoded_hash = decoded.get(self._HASH_PARAM)
        if not decoded_hash:
            raise InvalidToken("Secure URL token contains no URL hash")

        comparison_hash = self._hash_url_v1(url)
        if not compare_digest(decoded_hash, comparison_hash):
            raise InvalidToken("Secure URL hash mismatch")

        # This is of no interest to anyone bar us, and removing it prevents any
        # external code from ending up relying on any specifics of the hash
        decoded.pop("h")

        return decoded

    def _hash_url_v1(self, url):
        url = self._strip_token(url)

        # We don't use this hash for authentication, just verification, so 60
        # bits of entropy is going to be enough to make collisions unlikely.
        # We use blake here because we can precisely control the length.
        # Setting this to 15 chars means we fit into 20 base64 chars, instead
        # of tripping over and requiring padding causing 24 base64 chars.
        # Essentially one char less of hash results in 4 chars less of base64
        digest = blake2b(digest_size=15)
        digest.update(url.encode("utf-8"))

        # We use base64 as it saves us a ton of space
        return b64encode(digest.digest()).decode("utf-8")

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


class ViaSecureURL(SecureURL):
    """A token for signing proxied URLs."""

    MAX_AGE = timedelta(hours=1)

    def __init__(self, secret):
        super().__init__(secret, token_param="via.sec")

    def create(self, url):  # pylint: disable=arguments-differ
        """Create a secure token for a Via proxied URL.

        :param url: The whole URL of the request to Via with all params
        :return: A JWT encoded token as a string
        """
        return super().create(url, payload={}, expires=quantized_expiry(self.MAX_AGE))
