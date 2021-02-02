"""Python implementation of Nginx's securelink extension.

https://nginx.org/en/docs/http/ngx_http_secure_link_module.html
"""

import base64
import hashlib
import hmac


def digest(secret, url):
    """Generate a signed url hash.

    :param secret Secret to sign the links with
    :param url_template str.format template with at least a {exp} parameter
    """
    hash_ = hashlib.md5()
    hash_.update(f"{url} {secret}".encode("utf-8"))
    sec = hash_.digest()
    sec = base64.urlsafe_b64encode(sec)
    sec = sec.replace(b"=", b"")

    return sec.decode()


def compare_digest(hash_a, hash_b):
    """Return hash_a == hash_b.

    This function uses an approach designed to prevent timing analysis by
    avoiding content-based short circuiting behaviour,
    making it appropriate for cryptography.

    hash_a and hash_b must both be of the same type: either str
    (ASCII only, as e.g. returned by HMAC.hexdigest()), or a bytes-like object.
    """
    return hmac.compare_digest(hash_a, hash_b)
