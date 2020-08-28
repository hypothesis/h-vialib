"""Tools for representing dicts as flat lists and converting them back."""


class FlatDict:
    """Convert from and to a flat format for dicts."""

    SEPARATOR = "."

    @classmethod
    def unflatten(cls, flat):
        """Convert dot delimited flat data into nested dicts.

        This will convert a flat dict with keys like "a.b.c" into a nested
        dict with the same keys. With repeated elements, the last value will
        be chosen.

        :param flat: A mapping of dot delimited keys to values
        :return: A nested dict
        """

        nested = {}

        for key, value in flat.items():
            parts = key.split(cls.SEPARATOR)
            target = nested

            # Skip the last part
            for part in parts[:-1]:
                target = target.setdefault(part, {})

            # Finally set the last key to the value
            target[parts[-1]] = value

        return nested

    @classmethod
    def flatten(cls, nested):
        """Flatten a nested dict into a flat dict with dot delimited keys.

        :param nested: A nested dict
        :return: A dict with dot delimited keys
        """
        return cls._flatten(nested)

    @classmethod
    def _flatten(cls, nested, flat=None, key_prefix=None):
        if key_prefix is None:
            key_prefix = ""
        else:
            key_prefix += cls.SEPARATOR

        if flat is None:
            flat = {}

        for key, value in nested.items():
            flat_key = key_prefix + key
            if isinstance(value, dict):
                cls._flatten(value, flat=flat, key_prefix=flat_key)
            else:
                flat[flat_key] = value

        return flat
