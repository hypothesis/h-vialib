"""Helper classes for clients using Via proxying."""

import re
from urllib.parse import urlencode, urlparse

from h_vialib import securelink


class ViaDoc:  # pylint: disable=too-few-public-methods
    """A doc we want to proxy with content type."""

    GOOGLE_DRIVE_REGEX = re.compile(
        r"^https://drive.google.com/uc\?id=(.*)&export=download$", re.IGNORECASE
    )

    def __init__(self, url, content_type=None):
        """Initialize a new doc with it's url and content_type if known."""
        self.url = url

        if content_type is None and self.GOOGLE_DRIVE_REGEX.match(url):
            content_type = "pdf"

        self._content_type = content_type

    @property
    def is_pdf(self):
        """Check if document is known to be a pdf."""
        return self._content_type == "pdf"


class ViaClient:  # pylint: disable=too-few-public-methods
    """A small wrapper to make calling Via easier."""

    def __init__(self, via_url, host_url, signing_secret):
        """Initialize a ViaClient pointing to a `via_url` via server.

        :param via_url location of the via server
        :param host_url origin of the request
        :signing_secret signing secret used by the server
        """
        self.via_url = urlparse(via_url)
        self._signing_secret = signing_secret

        # Default via parameters
        self.options = {
            "via.client.openSidebar": "1",
            "via.client.requestConfigFromFrame.origin": host_url,
            "via.client.requestConfigFromFrame.ancestorLevel": "2",
            "via.external_link_mode": "new-tab",
        }

    def url_for(self, doc, expires_at):
        """Generate a Via url to proxy `doc`.

        Resulting URL will be signed and will expire at `expire_at`

        :param doc a ViaDoc representation of a resource
        :param expires_at datetime after which
            the URL signature will no longer be valid
        """
        # Optimisation to skip routing for documents we know are PDFs
        path = "/pdf" if doc.is_pdf else "/route"
        expires_timestamp = int(expires_at.timestamp())

        options = {
            "url": doc.url,
            "exp": expires_timestamp,
        }
        options.update(self.options)

        url = self.via_url._replace(path=path, query=urlencode(options))

        options["sig"] = securelink.digest(self._signing_secret, url)
        signed_url = self.via_url._replace(path=path, query=urlencode(options))

        return signed_url.geturl()
