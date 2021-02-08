"""Helper classes for clients using Via proxying."""

import re
from urllib.parse import urlencode, urlparse

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
    def is_pdf(self):
        """Check if document is known to be a pdf."""
        return self._content_type == "pdf"


class ViaClient:  # pylint: disable=too-few-public-methods
    """A small wrapper to make calling Via easier."""

    def __init__(self, service_url, host_url, secret):
        """Initialize a ViaClient pointing to a `via_url` via server.

        ￼
        :param service_url: location of the via server
        :param host_url: origin of the request
        :param secret: shared secret to sign the URL
        """
        self._service_url = urlparse(service_url)
        self._secure_url = ViaSecureURL(secret)

        # Default via parameters
        self.options = {
            "via.client.openSidebar": "1",
            "via.client.requestConfigFromFrame.origin": host_url,
            "via.client.requestConfigFromFrame.ancestorLevel": "2",
            "via.external_link_mode": "new-tab",
        }

    def url_for(self, url, content_type=None):
        """Generate a Via url to proxy `doc`.

        :param url: URL to proxy thru Via
        :param content_type: content type, if known, of the document
        :return: Full via url to proxy `url` including signature
        """
        doc = ViaDoc(url, content_type)

        # Optimisation to skip routing for documents we know are PDFs
        path = "/pdf" if doc.is_pdf else "/route"

        options = {"url": doc.url}
        options.update(self.options)

        via_url = self._service_url._replace(path=path, query=urlencode(options))

        return self._secure_url.create(via_url.geturl())
