"""Cookie helpers to create secure cookies."""

from http.cookies import Morsel, SimpleCookie

from h_vialib.exceptions import MissingToken
from h_vialib.secure.expiry import as_expires

# Monkey patch the Python 3.6 version of cookies to understand the SameSite
# attribute added in 3.8
# https://stackoverflow.com/questions/50813091/how-do-i-set-the-samesite-attribute-of-http-cookies-in-python
Morsel._reserved["samesite"] = "SameSite"  # pylint: disable=protected-access


class Cookie:
    """A simplified Cookie for security purposes."""

    def __init__(self, name, secure=True):
        """Initialise this cookie object.

        :param name: Cookie name to read and write
        :param secure: Make a secure cookie to be used in iframes with HTTPS
        """
        self._name = name
        self._secure = secure

    _DATE_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"

    def create(self, value, expires=None, max_age=None):
        """Create a cookie with a specified value and expiry.

        This cookie is for security purposes and has a number of default
        behaviors:

         * The path is '/'
         * HTTP Only is enabled
         * The name is controlled to be the same as this class was intialised with

        :param value: The value to store in the cookie
        :param expires: Expiry time for the cookie
        :param max_age: ... or max age of the cookie

        :return: A tuple of the correct header and value to set this cookie

        :raises ValueError: If no expiry is provided
        """
        cookie = SimpleCookie()

        cookie[self._name] = value
        cookie[self._name]["path"] = "/"
        cookie[self._name]["httponly"] = True

        if self._secure:
            cookie[self._name]["samesite"] = None
            cookie[self._name]["secure"] = True

        if expires is not None:
            if expires.tzinfo is None:
                raise ValueError("The expires date must have a timezone")

            cookie[self._name]["expires"] = expires.strftime(self._DATE_FORMAT)
        elif max_age is not None:
            cookie[self._name]["max-age"] = int(max_age)
        else:
            raise ValueError("You must specify an expiry time")

        return tuple(cookie.output().split(": "))

    def verify(self, cookies_header):
        """Check for the presence of our cookie and get the value.

        :param cookies_header: Full content of the "Cookies" header
        :returns: The value matching our name, or None
        """
        if not cookies_header:
            return None

        cookie = SimpleCookie(cookies_header)
        try:
            return cookie[self._name].value
        except KeyError:
            return None


class TokenBasedCookie(Cookie):
    """A cookie which stores it's contents using a SecureToken."""

    def __init__(self, name, token_provider, secure=True):
        """Initialize the cookie.

        :param name: Cookie name to read and write
        :param secure: Make a secure cookie to be used in iframes with HTTPS
        :param token_provider: Sub-class of SecureToken to use for creating
            and verifying the value
        """
        self._token_provider = token_provider

        super().__init__(name, secure)

    def create(
        self, expires=None, max_age=None, **kwargs
    ):  # pylint: disable=arguments-differ
        """Create a cookie.

        This passes through any arguments to the underlying token provider to
        create the value. Any arguments understood by the token provider will
        be accepted.

        :param expires: Expiry time for the cookie
        :param max_age: ... or max age of the cookie
        :param kwargs: Arguments to pass to the token provider
        :return: A tuple of the correct header and value to set this cookie
        """
        expires = as_expires(expires, max_age)
        token = self._token_provider.create(expires=expires, **kwargs)

        return super().create(value=token, expires=expires)

    def verify(self, cookies_header, **kwargs):  # pylint: disable=arguments-differ
        """Get a cookie value and check it with the token provider.

        All extra args and kwargs are passed through to the verify method
        of the token provider.

        :param cookies_header: Full content of the "Cookies" header
        :param kwargs: Arguments to pass to the token provider
        :returns: The decoded value of the cookie according to the token
            provider

        :raises MissingToken: If the cookie cannot be found
        """
        token = super().verify(cookies_header)
        if not token:
            raise MissingToken("No secure cookie")

        return self._token_provider.verify(token, **kwargs)
