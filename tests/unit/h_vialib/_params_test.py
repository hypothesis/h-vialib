from h_vialib._params import Params


class TestParams:
    def test_separate(self):
        via_params, non_via_params = Params.separate(
            (
                ("via.1.key", "via"),
                ("via.2.key", "via"),
                ("viable", "non-via"),
                ("other", "non-via"),
                ("other", "non-via-duplicate"),
            )
        )

        assert via_params == [
            ("via.1.key", "via"),
            ("via.2.key", "via"),
        ]

        assert non_via_params == [
            ("viable", "non-via"),
            ("other", "non-via"),
            ("other", "non-via-duplicate"),
        ]

    def test_split(self):
        via_params, client_params = Params.split(
            {
                "via": {
                    "any_option": 1,
                    # This should get moved to client params
                    "open_sidebar": True,
                    "client": {
                        "ignoreOtherConfiguration": "allowed",
                        "focus": "allowed",
                        "random": "blocked",
                        "requestConfigFromFrame": {"anyNestedStuff": "allowed"},
                    },
                }
            }
        )

        assert via_params == {"any_option": 1}
        assert client_params == {
            "openSidebar": True,
            "ignoreOtherConfiguration": "allowed",
            "focus": "allowed",
            "requestConfigFromFrame": {"anyNestedStuff": "allowed"},
            # Defaults
            "appType": "via",
            "showHighlights": True,
        }

    def test_split_without_defaults(self):
        via_params, client_params = Params.split(
            {
                "via": {
                    "any_option": 1,
                    "client": {
                        "focus": 2,
                    },
                }
            },
            add_defaults=False,
        )
        assert via_params == {"any_option": 1}
        assert client_params == {"focus": 2}

    def test_join(self):
        merged = Params.join(
            via_params={
                "any_option": 1,
                "open_sidebar": True,
            },
            client_params={
                "ignoreOtherConfiguration": "allowed",
                "focus": "allowed",
                "random": "blocked",
                "requestConfigFromFrame": {"anyNestedStuff": "allowed"},
            },
        )

        assert merged == {
            "via": {
                "any_option": 1,
                "client": {
                    "openSidebar": True,
                    "ignoreOtherConfiguration": "allowed",
                    "focus": "allowed",
                    "requestConfigFromFrame": {"anyNestedStuff": "allowed"},
                    # Defaults
                    "appType": "via",
                    "showHighlights": True,
                },
            }
        }

    def test_join_without_defaults(self):
        merged = Params.join(
            via_params={"any_option": 1}, client_params={"focus": 2}, add_defaults=False
        )

        assert merged == {"via": {"any_option": 1, "client": {"focus": 2}}}
