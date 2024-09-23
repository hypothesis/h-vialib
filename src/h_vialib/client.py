"""Helper classes for clients using Via proxying."""

import re
from enum import Enum
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse

from webob.multidict import MultiDict

from h_vialib.secure import Encryption, ViaSecureURL


class ContentType(str, Enum):
    PDF = "pdf"
    HTML = "html"
    YOUTUBE = "youtube"


class ViaDoc:
    """A doc we want to proxy with content type."""

    _GOOGLE_DRIVE_REGEX = re.compile(
        r"^https://drive.google.com/uc\?id=(.*)&export=download$", re.IGNORECASE
    )

    def __init__(self, url, content_type=None):
        """Initialize a new doc with it's url and content_type if known."""
        self.url = url

        if content_type is None and self._GOOGLE_DRIVE_REGEX.match(url):
            content_type = ContentType.PDF

        self.content_type = content_type


class ViaClient:  # pylint: disable=too-few-public-methods
    """A small wrapper to make calling Via easier."""

    def __init__(self, secret, service_url=None, html_service_url=None):
        """Initialize a ViaClient pointing to a `via_url` via server.

        :param secret: Shared secret to sign the URL
        :param service_url: Location of the via server
        :param html_service_url: Location of the Via HTML presenter
        """
        self._secure_secrets = Encryption(secret.encode("utf-8"))
        self._secure_url = ViaSecureURL(secret)
        self._service_url = urlparse(service_url) if service_url else None
        self._html_service_url = html_service_url

        # Default via parameters
        self.options = {
            "via.client.ignoreOtherConfiguration": "1",
            "via.client.openSidebar": "1",
            "via.external_link_mode": "new-tab",
        }

    # pylint:disable=too-many-arguments,too-many-positional-arguments
    def url_for(
        self,
        url,
        content_type: Optional[ContentType] = None,
        options=None,
        blocked_for=None,
        query=None,
        headers=None,
    ):
        """Generate a Via URL to display a given URL.

        If provided, the options will be merged with default Via options.

        :param url: URL to proxy thru Via
        :param content_type: content type, if known, of the document ("pdf"
            or "html")
        :param options: Any additional params to add to the URL
        :param blocked_for: context for the blocked pages
        :param query: Any extra query params needed to make the request to `url`.
            These are sent encrypted to Via.
            Note that the headers are only used when the content is proxied with
            python, ie only PDFs from certain sources.
        :param headers: Any headers needed to make the request to `url`.
            The headers are sent encrypted to Via.
            Note that the headers are only used when the content is proxied with
            python, ie only PDFs from certain sources.
        :return: Full Via URL suitable for redirecting a user to
        """
        doc = ViaDoc(url, content_type)

        params = dict(self.options)
        if options:
            params.update(options)

        if query:
            params["via.secret.query"] = self._secure_secrets.encrypt_dict(query)

        if headers:
            params["via.secret.headers"] = self._secure_secrets.encrypt_dict(headers)

        if blocked_for:
            params["via.blocked_for"] = blocked_for

        if doc.content_type == ContentType.HTML:
            # Optimisation to skip routing for documents we know are HTML
            via_url = self._url_for_html(doc.url, params)
        else:
            via_url = self._secure_url.create(self._url_for(doc, params))

        return via_url

    def _url_for(self, doc, query):
        if self._service_url is None:
            raise ValueError("Cannot rewrite URLs without a service URL")

        # Optimisation to skip routing for documents we know the type of
        content_type_paths = {
            ContentType.PDF: "/pdf",
            ContentType.YOUTUBE: "/video/youtube",
        }
        path = content_type_paths.get(doc.content_type, "/route")

        query["url"] = doc.url

        return self._service_url._replace(path=path, query=urlencode(query)).geturl()

    def _url_for_html(self, url, query):
        if self._html_service_url is None:
            raise ValueError("Cannot rewrite HTML URLs without an HTML service URL")

        # pywb is annoying. If we send a URL with a bare hostname and no path
        # it will issue a redirect to the same URL with a trailing slash, which
        # makes our token invalid. So we beat it to the punch
        url = self._fix_bare_hostname(url)

        rewriter_url = urlparse(f"{self._html_service_url}/{url}")

        # Merge our options and the params from the URL
        query = MultiDict(query)

        items = parse_qsl(rewriter_url.query)
        for key, _ in items:
            query.pop(key, None)

        query.extend(items)
        if "via.sec" in query:
            # Remove any already present signing parameters not needed for viahtml
            del query["via.sec"]

        return rewriter_url._replace(query=urlencode(query)).geturl()

    @classmethod
    def _fix_bare_hostname(cls, url):
        """Add a trailing slash to URLs without a path."""

        parsed_url = urlparse(url)
        if parsed_url.path:
            return url

        return parsed_url._replace(path="/").geturl()
