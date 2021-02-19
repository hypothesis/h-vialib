"""Logic for manipulating and separating Via, Client and non-Via params."""


class Params:
    """Split, separate and join Via parameters."""

    # Certain configuration options include URLs which we will read, write or
    # direct the user to. This would allow an attacker to craft a URL which
    # could do that to a user, so we whitelist harmless parameters instead
    # From: https://h.readthedocs.io/projects/client/en/latest/publishers/config/#config-settings
    CLIENT_CONFIG_WHITELIST = {
        # Things we use now
        "openSidebar",
        "requestConfigFromFrame",
        # Things which seem safe
        "enableExperimentalNewNoteButton",
        "experimental",  # Nested value for experimental features
        "externalContainerSelector",
        "focus",
        "showHighlights",
        "theme",
    }

    KEY_PREFIX = "via"

    @classmethod
    def separate(cls, items):
        """Separate params into via and non-via params.

        :param items: An iterable of key value pairs
        :return: A tuple of (via, non-via) key-value lists
        """

        via_params = []
        non_via_params = []

        for key, value in items:
            if key.split(".")[0] == cls.KEY_PREFIX:
                via_params.append((key, value))
            else:
                non_via_params.append((key, value))

        return via_params, non_via_params

    @classmethod
    def split(cls, merged_params, add_defaults=True):
        """Split merged nested Via and Client params.

        :param merged_params: Nested Via parameters
        :return: A tuple of Via and Client params
        :param add_defaults: Fill out sensible default values
        """

        via_params = merged_params.get(cls.KEY_PREFIX, {})
        client_params = via_params.pop("client", {})

        return cls._clean_params(via_params, client_params, add_defaults)

    @classmethod
    def join(cls, via_params, client_params, add_defaults=True):
        """Join Via and Client params into a single nested structure.

        :param via_params: Params for Via
        :param client_params: Params to pass to the client
        :param add_defaults: Fill out sensible default values
        :return: A single nested dict of params
        """
        via_params, client_params = cls._clean_params(
            via_params, client_params, add_defaults
        )

        return {cls.KEY_PREFIX: dict(via_params, client=client_params)}

    @classmethod
    def _clean_params(cls, via_params, client_params, add_defaults=True):
        # Remove keys which are not in the whitelist
        for key in set(client_params.keys()) - cls.CLIENT_CONFIG_WHITELIST:
            client_params.pop(key)

        # Handle legacy params which we can't move for now
        legacy_side_bar = via_params.pop("open_sidebar", None)
        if legacy_side_bar is None and add_defaults:
            legacy_side_bar = False

        if legacy_side_bar is not None:
            client_params.setdefault("openSidebar", legacy_side_bar)

        # Set some defaults
        if add_defaults:
            client_params["appType"] = "via"
            client_params.setdefault("showHighlights", True)

        return via_params, client_params
