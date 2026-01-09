# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "requests",
# ]
# ///
"""
Based on
https://www.camiloterevinto.com/post/oauth-pkce-flow-from-python-desktop
https://www.stefaanlippens.net/oauth-code-flow-pkce.html
"""

from ast import Return
import secrets
import hashlib
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import webbrowser
import requests
import html
import json
import os
import re

# Configured in Keycloak:
PROVIDER = "http://localhost:9090/auth/realms/pkce-test"
CLIENT_ID = "pkce"
USERNAME = "python"
PASSWORD = "pixie"
# redirect_uri = "http://localhost/foobar"

def main():
    ...


class OAuthHttpServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authorization_code = None


class OAuthHttpHander(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("COntent-Type", "text/html")
        self.end_headers()
        self.wfile.write("<script type=\"application/javascript\">window.close();</script>".encode("UTF-8"))

        parsed = parse.urlparse(self.path)
        qs = parse.parse_qs(parsed.query)

        self.server.authorization_code = qs.get('code', [None])[0]


# Adapted from https://github.com/RomeoDespres/pkce
def generate_code_verifier(length: int=128)->str:
    if not 43 <= length <= 128:
        raise ValueError('Parameter `length` must be between 43 and 128.')

    # Need to generate enough bytes to get `length` characters:
    code_verifier = secrets.token_urlsafe(128)[:length]
    return code_verifier


def compute_code_challenge(code_verifier: str) -> str:
    hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    return encoded.decode('ascii').rstrip("=")


def generate_pkce_pair(code_verifier_length: int = 128) -> tuple[str, str]:
    code_verifier = generate_code_verifier(code_verifier_length)
    code_challenge = compute_code_challenge(code_verifier)
    return code_verifier, code_challenge


if __name__ == "__main__":
    main()
