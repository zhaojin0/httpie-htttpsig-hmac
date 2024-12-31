
from httpie_apisix_httpsig import ApisixHttpsigAuth
from collections import namedtuple

from pyparsing import *

AUTH = Keyword("Authorization")
ident = Word(alphas,alphanums)
EQ = Suppress("=")
quotedString.setParseAction(removeQuotes)

valueDict = Dict(delimitedList(Group(ident + EQ + quotedString)))
authentry = ident("protocol") + valueDict


USER_KEY = "user-key"
SECRET_KEY = "my-secret-key"

SIGNED_HEADERS="date;user-agent"

Request = namedtuple("Request", ["method", "url", "headers"])



def test_signature():
    auth = ApisixHttpsigAuth(USER_KEY, SECRET_KEY, SIGNED_HEADERS, "hmac-sha256")
    request = Request(
        method="GET",
        url="/index.html?age=36&name=james",
        headers={
            "date": "Tue, 19 Jan 2021 11:33:20 GMT",
            "User-Agent": "curl/7.29.0",
            "x-custom-a": "test"
        }
    )

    signed_req = auth(request)

    head_auth_text = signed_req.headers["Authorization"]

    [scheme, *props] = authentry.parse_string(head_auth_text)

    auth_props = {}


    for [k,v] in props:
        auth_props[k] = v

    assert scheme == "Signature"
    assert auth_props["keyId"] == "user-key"
    assert auth_props["algorithm"] == "hmac-sha256"
    assert auth_props["headers"] == "@request-target date user-agent"
    assert auth_props["signature"] == "xyfc4k0cvUN1fI5ji1R07Y/CGsPqu7/6ooPwXg2tBWQ="
