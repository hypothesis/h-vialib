"""Tools for reading and writing Via configuration."""

from urllib.parse import parse_qsl, urlencode, urlparse

from h_vialib._flat_dict import FlatDict
from h_vialib._params import Params


class Configuration:
    """Extracts configuration from params.

    This class will extract and separate Client and Via configuration from a
    mapping by interpreting the keys as dot delimited values.

     * After splitting on '.' the parts are interpreted as nested dict keys
     * Any keys starting with `via.*` will be processed
     * Any keys starting with `via.client.*` will be separated out
     * Keys for the client which don't match a whitelist are discarded

    For example:

    {
        "other": "ignored",
        "via.option": "value",
        "via.client.nestOne.nestTwo": "value2"
    }

    Results in:

     * Via: {"option": "value"}
     * Client : {"nestOne": {"nextTwo": "value2"}}

    No attempt is made to interpret the values for the client. The client will
    get what we were given. If this was called from query parameters, that will
    mean a string.
    """

    @classmethod
    def extract_from_params(cls, params, add_defaults=True):
        """Extract Via and H config from query parameters.

        :param params: A mapping of query parameters
        :param add_defaults: Fill out sensible default values
        :return: A tuple of Via, and H config
        """

        merged_params = FlatDict.unflatten(params)
        return Params.split(merged_params, add_defaults)

    @classmethod
    def extract_from_wsgi_environment(cls, http_env, add_defaults=True):
        """Extract Via and H config from a WSGI environment object.

        :param http_env: WSGI provided environment variable
        :param add_defaults: Fill out sensible default values
        :return: A tuple of Via, and H config
        """
        params = dict(parse_qsl(http_env.get("QUERY_STRING")))

        return cls.extract_from_params(params, add_defaults)

    @classmethod
    def extract_from_url(cls, url, add_defaults=True):
        """Extract Via and H config from a URL.

        :param url: A URL to extract config from
        :param add_defaults: Fill out sensible default values
        :return: A tuple of Via, and H config
        """
        params = dict(parse_qsl(urlparse(url).query))

        return cls.extract_from_params(params, add_defaults)

    @classmethod
    def strip_from_url(cls, url):
        """Remove any Via configuration parameters from the URL.

        If the URL has no parameters left, remove the query string entirely.
        :param url: URL to strip
        :return: A string URL with the via parts removed
        """

        # Quick exit if this cannot contain any of our params
        if Params.KEY_PREFIX not in url:
            return url

        url_parts = urlparse(url)
        _, non_via = Params.separate(parse_qsl(url_parts.query))

        return url_parts._replace(query=urlencode(non_via)).geturl()

    @classmethod
    def add_to_url(cls, url, via_params, client_params):
        """Add configuration parameters to a given URL.

        This will merge and preserve any parameters already on the URL.

        :param url: URL to extract from
        :param via_params: Configuration to add for Via
        :param client_params: Configuration to add for the client
        :return: The URL with expected parameters added
        """
        url_parts = urlparse(url)
        _, non_via = Params.separate(parse_qsl(url_parts.query))

        flat_params = FlatDict.flatten(Params.join(via_params, client_params))

        non_via.extend(flat_params.items())

        return url_parts._replace(query=urlencode(non_via)).geturl()
