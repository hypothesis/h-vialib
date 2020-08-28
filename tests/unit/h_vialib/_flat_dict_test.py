from h_vialib._flat_dict import FlatDict


class TestFlatDict:
    NESTED = {"a": {"b": {"c": 1}}, "d": [2, 3], "e": 4}

    FLAT = {"a.b.c": 1, "d": [2, 3], "e": 4}

    def test_flatten(self):
        assert FlatDict.flatten(self.NESTED) == self.FLAT

    def test_unflatten(self):
        assert FlatDict.unflatten(self.FLAT) == self.NESTED
