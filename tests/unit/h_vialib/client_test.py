import pytest
from h_matchers import Any

from h_vialib import ViaClient, ViaDoc


class TestViaDoc:
    def test_no_content_type(self):
        doc = ViaDoc("http://random.document.com")
        assert doc.is_pdf == False

    def test_explicit_content_type(self):
        doc = ViaDoc("http://random.document.com", content_type="pdf")
        assert doc.is_pdf == True

    def test_url_matches_gdrive_pdf(self):
        doc = ViaDoc("https://drive.google.com/uc?id=0&export=download")
        assert doc.is_pdf == True


class TestViaClient:
    VIA_URL = "http://via.localhost"
    ORIGIN_URL = "http://random.localhost"

    def test_client_default_options(self, client):
        proxied_url = "http://example.com"

        final_url = client.url_for(proxied_url)
        assert final_url == Any.url.matching(
            "{}/route".format(self.VIA_URL)
        ).with_query(
            {
                "via.client.openSidebar": "1",
                "via.client.requestConfigFromFrame.origin": self.ORIGIN_URL,
                "via.client.requestConfigFromFrame.ancestorLevel": "2",
                "via.external_link_mode": "new-tab",
                "via.sec": Any.string(),
                "url": proxied_url,
            }
        )

    def test_client_proxy_pdf(self, client):
        final_url = client.url_for("http://example.com", content_type="pdf")

        assert final_url.startswith("{}/pdf".format(self.VIA_URL))

    @pytest.fixture
    def client(self):
        return ViaClient(self.VIA_URL, self.ORIGIN_URL, "SECRET")
