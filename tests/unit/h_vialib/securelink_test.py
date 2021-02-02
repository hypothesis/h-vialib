from h_vialib import securelink


class TestSecureLink:

    HASH_SECRET = "SECRET"
    URL_TEMPLATE = "/location/{exp}/"

    def test_digest_success(self):
        hash_ = securelink.digest(
            self.HASH_SECRET, "/location/1609455600/"  # datetime(2021, 1, 1)
        )

        # Matches output from:
        # echo -n '/location/1609455600/ SECRET' | \
        # openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =
        assert hash_ == "nylQvIaceqvrj67dUgXQ6A"

    def test_compare_digest_equal(self):
        assert securelink.compare_digest("a", "a") == True
        assert securelink.compare_digest(b"a", b"a") == True

    def test_compare_digest_distinct(self):
        assert securelink.compare_digest("a", "b") == False
        assert securelink.compare_digest(b"a", b"b") == False
