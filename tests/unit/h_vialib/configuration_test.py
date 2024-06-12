from unittest.mock import patch

import pytest
from h_matchers import Any

from h_vialib.configuration import Configuration


class FakeMultiDict:
    """Mimic things like WebOb multivalue dicts."""

    def __init__(self, items):
        self._items = items

    def items(self):
        yield from self._items


class TestConfiguration:
    def test_extract_from_params(self, param_pairs):
        via_params, client_params = Configuration.extract_from_params(dict(param_pairs))

        self.assert_correct_params(via_params, client_params)

    def test_extract_from_params_with_multi_dict(self, param_pairs):
        via_params, client_params = Configuration.extract_from_params(
            FakeMultiDict(param_pairs)
        )

        self.assert_correct_params(via_params, client_params)

    def test_extract_from_wsgi_environment(self, query_string):
        via_params, client_params = Configuration.extract_from_wsgi_environment(
            {"QUERY_STRING": query_string}
        )

        self.assert_correct_params(via_params, client_params)

    def test_extract_from_url(self, url_with_params):
        via_params, client_params = Configuration.extract_from_url(url_with_params)

        self.assert_correct_params(via_params, client_params)

    def test_strip_from_url(self, url_with_params):
        url = Configuration.strip_from_url(url_with_params)

        assert url == Any.url.matching("http://example.com").with_query(
            (
                ("irrelevant", "missing_1"),
                ("irrelevant", "missing_2"),
                ("viable", "decoy"),
            )
        )

    @patch("h_vialib.configuration.urlparse")
    def test_strip_from_url_shortcut_without_via_params(self, urlparse):
        url = "http://example.com/path"

        stripped_url = Configuration.strip_from_url(url)

        assert stripped_url == url
        urlparse.assert_not_called()

    def test_add_to_url(self):
        url = "http://example.com?a=1&a=2&via.client.focus=3"

        url_with_config = Configuration.add_to_url(
            url, {"option": "4"}, {"openSidebar": "5"}
        )

        assert url_with_config == Any.url.matching(url).containing_query(
            (
                ("a", "1"),
                ("a", "2"),
                ("via.option", "4"),
                ("via.client.openSidebar", "5"),
            )
        )

        # Original via settings are wiped
        assert url_with_config != Any.url().containing_query({"via.client.focus": "3"})

    def assert_correct_params(self, via_params, client_params):
        assert via_params == {"setting": "setting_last"}
        assert client_params == Any.dict().containing({"focus": "focus_last"})

    @pytest.fixture
    def url_with_params(self, query_string):
        return f"http://example.com?{query_string}"

    @pytest.fixture
    def query_string(self, param_pairs):
        return "&".join(f"{key}={value}" for key, value in param_pairs)

    @pytest.fixture
    def param_pairs(self):
        return (
            ("irrelevant", "missing_1"),
            ("irrelevant", "missing_2"),
            ("viable", "decoy"),
            ("via.setting", "setting_first"),
            ("via.setting", "setting_last"),
            ("via.client.focus", "focus_first"),
            ("via.client.focus", "focus_last"),
        )
