"""Helper classes for clients using Via proxying."""

import re
from urllib.parse import parse_qsl, urlencode, urlparse

from webob.multidict import MultiDict

from h_vialib.secure import ViaSecureURL


class ViaDoc:  # pylint: disable=too-few-public-methods
    """A doc we want to proxy with content type."""

    _GOOGLE_DRIVE_REGEX = re.compile(
        r"^https://drive.google.com/uc\?id=(.*)&export=download$", re.IGNORECASE
    )

    def __init__(self, url, content_type=None):
        """Initialize a new doc with it's url and content_type if known."""
        self.url = url

        if content_type is None and self._GOOGLE_DRIVE_REGEX.match(url):
            content_type = "pdf"

        self._content_type = content_type

    @property
    def is_html(self):
        """Check if document is known to be a HTML."""
        return self._content_type == "html"

    @property
    def is_pdf(self):
        """Check if document is known to be a pdf."""
        return self._content_type == "pdf"


class ViaClient:  # pylint: disable=too-few-public-methods
    """A small wrapper to make calling Via easier."""

    def __init__(self, secret, service_url=None, html_service_url=None):
        """Initialize a ViaClient pointing to a `via_url` via server.

        :param secret: Shared secret to sign the URL
        :param service_url: Location of the via server
        :param html_service_url: Location of the Via HTML presenter
        """
        self._secure_url = ViaSecureURL(secret)
        self._service_url = urlparse(service_url) if service_url else None
        self._html_service_url = html_service_url

        # Default via parameters
        self.options = {
            "via.client.ignoreOtherConfiguration": "1",
            "via.client.openSidebar": "1",
            "via.external_link_mode": "new-tab",
        }

    def url_for(self, url, content_type=None, options=None, blocked_for=None):
        """Generate a Via URL to display a given URL.

        If provided, the options will be merged with default Via options.

        :param url: URL to proxy thru Via
        :param content_type: content type, if known, of the document ("pdf"
            or "html")
        :param options: Any additional params to add to the URL
        :param blocked_for: context for the blocked pages
        :return: Full Via URL suitable for redirecting a user to
        """
        doc = ViaDoc(url, content_type)

        query = dict(self.options)
        if options:
            query.update(options)

        if blocked_for:
            query["via.blocked_for"] = blocked_for

        if doc.is_html:
            # Optimisation to skip routing for documents we know are HTML
            via_url = self._url_for_html(doc.url, query)
        else:
            via_url = self._secure_url.create(self._url_for(doc, query))

        return via_url

    def _url_for(self, doc, query):
        if self._service_url is None:
            raise ValueError("Cannot rewrite URLs without a service URL")

        # Optimisation to skip routing for documents we know are PDFs
        path = "/pdf" if doc.is_pdf else "/route"

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
