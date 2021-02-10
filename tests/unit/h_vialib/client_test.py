import pytest
from h_matchers import Any

from h_vialib import ViaClient, ViaDoc


class TestViaDoc:
    @pytest.mark.parametrize(
        "url,content_type,is_pdf",
        (
            ("http://example.com", None, False),
            ("http://example.com", "html", False),
            ("http://example.com", "pdf", True),
            # We know about Google Drive links and assume them to be PDF
            ("https://drive.google.com/uc?id=0&export=download", None, True),
        ),
    )
    def test_is_pdf(self, url, content_type, is_pdf):
        doc = ViaDoc(url, content_type)

        assert doc.is_pdf == is_pdf

    @pytest.mark.parametrize(
        "url,content_type,is_html",
        (
            ("http://example.com", None, False),
            ("http://example.com", "pdf", False),
            ("http://example.com", "html", True),
        ),
    )
    def test_is_htmlf(self, url, content_type, is_html):
        doc = ViaDoc(url, content_type)

        assert doc.is_html == is_html


class TestViaClient:
    VIA_URL = "http://via.localhost"
    VIAHTML_URL = "http://viahtml.localhost"
    ORIGIN_URL = "http://random.localhost"

    DEFAULT_VALUES = {
        "via.client.openSidebar": "1",
        "via.client.requestConfigFromFrame.origin": ORIGIN_URL,
        "via.client.requestConfigFromFrame.ancestorLevel": "2",
        "via.external_link_mode": "new-tab",
    }

    @pytest.mark.parametrize("content_type,path", ((None, "/route"), ("pdf", "/pdf")))
    def test_url_for(self, client, content_type, path):
        url = "http://example.com&a=1&a=2"

        final_url = client.url_for(url, content_type)

        expected_query = dict(self.DEFAULT_VALUES)
        expected_query["url"] = url
        expected_query["via.sec"] = Any.string()

        assert final_url == Any.url.matching(self.VIA_URL + path).with_query(
            expected_query
        )

    def test_url_for_with_html(self, client):
        url = "http://example.com/path?a=1&a=2"

        final_url = client.url_for(url, "html")

        # Use a list instead of a dict to capture repeated values
        expected_query = list(self.DEFAULT_VALUES.items())
        expected_query.extend(
            (
                ("via.sec", Any.string()),
                # With ViaHTML we blend our params with the original URL's
                ("a", "1"),
                ("a", "2"),
            )
        )

        assert final_url == Any.url.matching(self.VIAHTML_URL + "/" + url).with_query(
            expected_query
        )

    @pytest.mark.parametrize("content_type", (None, "pdf", "html"))
    def test_url_for_allows_you_to_override_options(self, client, content_type):
        override = {"via.client.openSidebar": "0"}
        final_url = client.url_for("http://example.com", content_type, options=override)

        assert final_url == Any.url.containing_query(override)

    @pytest.mark.parametrize("content_type", (None, "pdf", "html"))
    def test_url_for_raises_without_a_service_url(self, content_type):
        client = ViaClient(
            service_url=None,
            html_service_url=None,
            host_url=self.ORIGIN_URL,
            secret="not_a_secret",
        )

        with pytest.raises(ValueError):
            client.url_for("http://example.com", content_type)

    @pytest.mark.parametrize(
        "url,path",
        (
            # Note the addition of the trailing slash
            ("http://bare.example.com", "http://bare.example.com/"),
            # These should be left alone
            ("http://example.com/", "http://example.com/"),
            ("http://example.com/path", "http://example.com/path"),
        ),
    )
    def test_it_fixes_html_urls_with_bare_hostnames(self, client, url, path):
        signed_url = client.url_for(url, "html")

        assert signed_url == Any.url.with_path(path)

    @pytest.fixture
    def client(self):
        return ViaClient(
            service_url=self.VIA_URL,
            html_service_url=self.VIAHTML_URL,
            host_url=self.ORIGIN_URL,
            secret="not_a_secret",
        )
