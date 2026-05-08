# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "httpx",
#   "rich",
#   "scitacean>=26",
# ]
# ///
"""
PKCE impl Based on
https://www.camiloterevinto.com/post/oauth-pkce-flow-from-python-desktop
https://www.stefaanlippens.net/oauth-code-flow-pkce.html
"""

import secrets
import webbrowser
import logging

from scitacean._internal import jwt
from scitacean import Client
from rich import print
from rich.logging import RichHandler
import httpx

from oauth_server import launch_auth_server
from pkce import generate_pkce_pair

# Configured in Keycloak:
# PROVIDER = "http://keycloak.local:8080/realms/pkce-test"
PROVIDER = "http://localhost:8080/realms/pkce-test"
CLIENT_ID = "scicat-native-normal"
# USERNAME = "python"
# PASSWORD = "pixie"
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
    return

    scicat_token = get_scicat_token(keycloak_token)
    print("=== SciCat ===")
    print(jwt.decode(scicat_token))

    client = Client.from_token(url=SCICAT_URL, token=scicat_token)
    identity = client.scicat.call_endpoint(
        cmd="GET", url="users/my/identity", operation="get_user_info"
    )
    print(identity)


def get_scicat_token(keycloak_token: str) -> str:
    response = httpx.post(
        f"{SCICAT_URL}/auth/oidc/token", json={"idToken": keycloak_token}
    )
    response.raise_for_status()
    return response.json()["access_token"]


def login() -> str:
    state = secrets.token_urlsafe()
    code_verifier, code_challenge = generate_pkce_pair()

    with httpx.Client(base_url=PROVIDER) as client:
        auth_uri = build_login_uri(client, code_challenge, state=state)

        # Start a server to handle the OAuth redirect with the auth code:
        with launch_auth_server(
            port=PORT, timeout=30, issuer=PROVIDER, state=state
        ) as server:
            # Prompt the user to log in:
            open_in_browser(auth_uri)
            server.handle_request()

        auth_code = server.authorization_code
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


def build_login_uri(client: httpx.Client, code_challenge: str, state: str) -> str:
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
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",  # hard-coded in the code generator
        },
    ).url
    return str(url)


def open_in_browser(url: str):
    try:
        result = webbrowser.open_new_tab(url)
    except webbrowser.Error as error:
        error.add_note(f"Please open the following URL in your browser: {url}")
        raise
    if not result:
        raise ValueError("Failed to open URL in browser")


if __name__ == "__main__":
    main()
