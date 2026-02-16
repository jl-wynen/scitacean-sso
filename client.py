# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "httpx",
#   "rich",
#   "scitacean",
# ]
# ///
"""
Based on
https://www.camiloterevinto.com/post/oauth-pkce-flow-from-python-desktop
https://www.stefaanlippens.net/oauth-code-flow-pkce.html
"""

import secrets
import hashlib
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import webbrowser
import logging

from scitacean._internal import jwt
from rich import print
from rich.logging import RichHandler
import httpx

# Configured in Keycloak:
PROVIDER = "http://keycloak.local:8080/realms/pkce-test"
# PROVIDER = "http://localhost:8080/realms/pkce-test"
CLIENT_ID = "pkce"
USERNAME = "python"
PASSWORD = "pixie"
SCOPES = ["openid", "profile"]

# Relative to `PROVIDER`
AUTH_URI = "protocol/openid-connect/auth"
TOKEN_URI = "protocol/openid-connect/token"

PORT = 8081
REDIRECT_URI = f"http://localhost:{PORT}"

SCICAT_URL = "http://localhost:3000/api/v3"


def main():
    logging.basicConfig(
        level="INFO",
        format="[%(name)s] %(message)s",
        datefmt="[%X]",
        handlers=[RichHandler()],
    )
    keycloak_token = login()
    print("=== Keycloak ===")
    print(jwt.decode(keycloak_token))

    scicat_token = get_scicat_token(keycloak_token)
    print("=== SciCat ===")
    print(scicat_token)
    # print(jwt.decode(scicat_token))

def get_scicat_token(keycloak_token:str)->str:
    response = httpx.post(f"{SCICAT_URL}/auth/oidc/token", json={"idToken": keycloak_token})
    response.raise_for_status()
    return response.json()


def login() -> str:
    code_verifier, code_challenge = generate_pkce_pair()

    with httpx.Client(base_url=PROVIDER) as client:
        auth_uri = build_login_uri(client, code_challenge)

        # Start a server to handle the OAuth redirect with the auth code:
        with OAuthHttpServer(("", PORT), OAuthHttpHandler) as httpd:
            # Prompt the user to log in:
            open_in_browser(auth_uri)
            httpd.handle_request()

        auth_code = httpd.authorization_code
        assert auth_code is not None

        # Exchange the auth code for a token:
        data = {
            "code": auth_code,
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            # space-delimited (https://www.keycloak.org/securing-apps/token-exchange):
            "scopes": " ".join(SCOPES),
            "redirect_uri": REDIRECT_URI,
            "code_verifier": code_verifier,
        }
        response = client.post(TOKEN_URI, data=data)
        response.raise_for_status()
        j = response.json()
    assert j["token_type"] == "Bearer"
    access_token = j["access_token"]
    return access_token


def build_login_uri(client: httpx.Client, code_challenge: str) -> str:
    """Build a URL to open in a browser for the user to log in."""
    url = client.build_request(
        "GET",
        AUTH_URI,
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            # join by " " which translated to "+" when escaped:
            "scope": " ".join(SCOPES),
            "state": "test-state",  # TODO use nonce (can encode data here, but length is limited)
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",  # hard-coded in the code generator
        },
    ).url
    return str(url)


class OAuthHttpServer(HTTPServer):
    """Server to receive the authorization code."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.authorization_code = None


class OAuthHttpHandler(BaseHTTPRequestHandler):
    """Handler for the OAuth HTTP server."""

    def do_GET(self) -> None:
        html = SUCCESS_HTML
        data = html.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        # TODO doesn't close the window on first login but does close when login is cached
        #   In the latter case, the user interacted with the window which triggered a page change
        #   and scripts are not allowed to close the window in that case.
        #   See https://developer.mozilla.org/en-US/docs/Web/API/Window/close
        self.wfile.write(data)

        parsed = parse.urlparse(self.path)
        qs = parse.parse_qs(parsed.query)
        # TODO do we need to check more fields?

        self.server.authorization_code = qs.get("code", [None])[0]

    def log_request(self, code: int, *args, **kwargs) -> None:
        # `self.path` contains the auth token, so only show basics about the request
        logging.getLogger("OAuth-server").info(
            f"{self.command} ({code}) from {self.client_address}"
        )

    def log_error(self, *args, **kwargs) -> None:
        # Override to avoid leaking the auth token
        logging.getLogger("OAuth-server").error("Received error")

    def log_message(self, *args, **kwargs) -> None:
        # Override to avoid leaking the auth token
        logging.getLogger("OAuth-server").info("Received message")


def open_in_browser(url: str):
    try:
        result = webbrowser.open_new_tab(url)
    except webbrowser.Error as error:
        error.add_note(f"Please open the following URL in your browser: {url}")
        raise
    if not result:
        raise ValueError("Failed to open URL in browser")


# Adapted from https://github.com/RomeoDespres/pkce
def generate_code_verifier(length: int = 128) -> str:
    if not 43 <= length <= 128:
        raise ValueError("Parameter `length` must be between 43 and 128.")

    # Need to generate enough bytes to get `length` characters:
    code_verifier = secrets.token_urlsafe(128)[:length]
    return code_verifier


def compute_code_challenge(code_verifier: str) -> str:
    hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    return encoded.decode("ascii").rstrip("=")


def generate_pkce_pair(code_verifier_length: int = 128) -> tuple[str, str]:
    code_verifier = generate_code_verifier(code_verifier_length)
    code_challenge = compute_code_challenge(code_verifier)
    return code_verifier, code_challenge


SUCCESS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="color-scheme" content="dark light" />
    <title>Authenticated</title>
    <script type="application/javascript">
        window.close();
    </script>
</head>
<body style="text-align: center;">
    <svg style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1;"
        xmlns="http://www.w3.org/2000/svg">
        <defs>
            <filter id="noiseFilter">
                <feTurbulence
                        type="fractalNoise"
                        baseFrequency="0.5"
                        numOctaves="2"
                        stitchTiles="stitch"/>
                <feColorMatrix type="matrix" values="
                0 0 0 0.09 0
                0 0 0 0.09 0
                0 0 0 0.09 0
                0 0 0 1 0"/>
            </filter>
            <pattern id="noisePattern" x="0" y="0" width="400" height="400" patternUnits="userSpaceOnUse">
                <rect width="400" height="400" filter="url(#noiseFilter)"/>
            </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#noisePattern)" opacity="0.1" style="mix-blend-mode: overlay;"/>
    </svg>

    <h1>Success</h1>
    <p>You can now close this window and return to Python.</p>
</body>
</html>"""


if __name__ == "__main__":
    main()
