import pytest
from h_matchers import Any

from h_vialib import ContentType, ViaClient, ViaDoc


class TestViaDoc:
    @pytest.mark.parametrize(
        "url,content_type,expected_content_type",
        (
            ("http://example.com", None, None),
            ("http://example.com", ContentType.HTML, ContentType.HTML),
            ("http://example.com", ContentType.PDF, ContentType.PDF),
            # We know about Google Drive links and assume them to be PDF
            ("https://drive.google.com/uc?id=0&export=download", None, ContentType.PDF),
        ),
    )
    def test_content_type(self, url, content_type, expected_content_type):
        doc = ViaDoc(url, content_type)

        assert doc.content_type == expected_content_type


class TestViaClient:
    VIA_URL = "http://via.localhost"
    VIAHTML_URL = "http://viahtml.localhost"
    ORIGIN_URL = "http://random.localhost"

    DEFAULT_VALUES = {
        "via.client.ignoreOtherConfiguration": "1",
        "via.client.openSidebar": "1",
        "via.external_link_mode": "new-tab",
    }

    @pytest.mark.parametrize(
        "content_type,path",
        (
            (None, "/route"),
            (ContentType.PDF, "/pdf"),
            (ContentType.YOUTUBE, "/video/youtube"),
        ),
    )
    def test_url_for(self, client, content_type, path):
        url = "http://example.com&a=1&a=2"

        final_url = client.url_for(url, content_type)

        expected_query = dict(self.DEFAULT_VALUES)
        expected_query["url"] = url
        expected_query["via.sec"] = Any.string()

        assert final_url == Any.url.matching(self.VIA_URL + path).with_query(
            expected_query
        )

    @pytest.mark.parametrize("content_type,path", ((None, "/route"), ("pdf", "/pdf")))
    def test_url_for_with_blocked_for(self, client, content_type, path):
        url = "http://example.com&a=1&a=2"

        final_url = client.url_for(url, content_type, blocked_for="lms")

        expected_query = dict(self.DEFAULT_VALUES)
        expected_query["url"] = url
        expected_query["via.blocked_for"] = "lms"
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
                # No url signing for viahtml
                ("a", "1"),
                ("a", "2"),
            )
        )

        assert final_url == Any.url.matching(self.VIAHTML_URL + "/" + url).with_query(
            expected_query
        )

    def test_url_for_with_html_and_blocked_for(self, client):
        url = "http://example.com/path?a=1&a=2&via.sec=THIS_SHOULD_BE_REMOVED"

        final_url = client.url_for(url, "html", blocked_for="lms")

        # Use a list instead of a dict to capture repeated values
        expected_query = list(self.DEFAULT_VALUES.items())
        expected_query.extend(
            (
                ("via.blocked_for", "lms"),
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

        assert final_url == Any.url().containing_query(override)

    def test_url_for_with_headers(self, client, Encryption):
        headers = {"some": "header"}
        Encryption.return_value.encrypt_dict.return_value = "secure headers"

        final_url = client.url_for("http://example.com", headers=headers)

        Encryption.return_value.encrypt_dict.assert_called_once_with(headers)
        assert final_url == Any.url().containing_query(
            {"via.secret.headers": "secure headers"}
        )

    def test_url_for_with_query(self, client, Encryption):
        query = {"some": "parameter"}
        Encryption.return_value.encrypt_dict.return_value = "secure query"

        final_url = client.url_for("http://example.com", query=query)

        Encryption.return_value.encrypt_dict.assert_called_once_with(query)
        assert final_url == Any.url().containing_query(
            {"via.secret.query": "secure query"}
        )

    @pytest.mark.parametrize("content_type", (None, "pdf", "html"))
    def test_url_for_raises_without_a_service_url(self, content_type):
        client = ViaClient(
            service_url=None,
            html_service_url=None,
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
    def Encryption(self, patch):
        return patch("h_vialib.client.Encryption")

    @pytest.fixture
    def client(self, Encryption):  # pylint:disable=unused-argument
        return ViaClient(
            service_url=self.VIA_URL,
            html_service_url=self.VIAHTML_URL,
            secret="not_a_secret",
        )
