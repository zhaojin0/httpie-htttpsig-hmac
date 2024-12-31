"""
ApisixHttpsigAuth auth plugin for HTTPie.
"""
import base64
import datetime
import hashlib
import hmac
import os

from httpie.plugins import AuthPlugin

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import itertools

__version__ = "0.1.0"
__author__ = "Zhao Jin"
__licence__ = "MIT"


_http_date_fmt = '%a, %d %b %Y %H:%M:%S GMT'



def url_to_target_url(request_url):
  _url = urlparse(request_url)
  return "?".join([_url.path, _url.query])


class ApisixHttpsigAuth:
    key_id: str
    secret_key: str
    signed_headers: str
    alg: str = "hmac-sha256"

    def __init__(self, key_id: str, secret_key: str, signed_headers: str, alg: str):
        self.key_id = key_id
        self.secret_key = bytes(secret_key, "utf8")
        self.signed_headers = signed_headers
        self.alg = alg
        self._debug = os.environ.get("DEBUG", "false").casefold() == "true".casefold()

    def __call__(self, r):
        method = r.method.upper()

        httpdate = r.headers.get("date")

        if not httpdate:
            now = datetime.datetime.now(datetime.timezone.utc)
            httpdate = now.strftime(_http_date_fmt)
            r.headers["Date"] = httpdate

        target_url = url_to_target_url(r.url)
        #path = url.path
        #query = ""
        #if url.query:
        #    query = _build_canonical_query_string(url.query)
        if (self._debug):
            print("origin headers: " + str(r.headers))

        string_to_sign = f"""{self.key_id}
{method} {target_url}
"""

        headers = self.signed_headers.split(";")

        header_keys = list(map(lambda x: x.lower(), headers))

        req_headers = {k.lower():v for k, v in r.headers.items()}

        for key in header_keys:
            if key == "@request-target":
                continue
            value = req_headers.get(key)
            if not value:
                value = ""
                if key == "host":
                  value = target_url.hostname

            if isinstance(value, bytes):
                value = str(value, encoding="utf8")
            string_to_sign += f"{key}: {value}\n"

        sig_headers = " ".join(["@request-target"] + header_keys)

        if self._debug:
            print(f"""===To Be Sign===
{string_to_sign}===End To Be Sign===
            """)

        to_be_sign = bytes(string_to_sign, "utf8")

        if self.alg == "hmac-sha1":
            hash_alg = hashlib.sha1
        else:
            hash_alg = hashlib.sha256

        hash = hmac.new(self.secret_key, to_be_sign, hash_alg)

        signature = base64.b64encode(hash.digest()).decode('utf-8')

        authorization = f'Signature keyId="{self.key_id}", algorithm="{self.alg}", headers="{sig_headers}", signature="{signature}"'

        r.headers["Authorization"] = authorization

        return r


class ApisixHttpsigAuthPlugin(AuthPlugin):
    name = "Apisix HTTPSIG auth"
    auth_type = "apisix-httpsig"
    description = "Sign requests using the Apisix HMAC after version 3.11 authentication method"

    def get_auth(self, username: str, password: str):
        signed_headers = os.environ.get(
            "HMAC_SIGNED_HEADERS", "@request-target;date"
        )
        alg = os.environ.get("HMAC_ALGORITHM", "hmac-sha256")
        return ApisixHttpsigAuth(username, password, signed_headers, alg)
