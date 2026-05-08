# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "httpx",
#   "rich",
#   "scitacean>=26",
# ]
# ///

import webbrowser
import logging
import time

from scitacean._internal import jwt
from scitacean import Client
from rich import print
from rich.logging import RichHandler
import httpx

from pkce import generate_pkce_pair

# Configured in Keycloak:
# PROVIDER = "http://keycloak.local:8080/realms/pkce-test"
PROVIDER = "http://localhost:8080/realms/pkce-test"
CLIENT_ID = "scicat-native-device"
# USERNAME = "python"
# PASSWORD = "pixie"
SCOPES = ["openid", "profile"]

# Relative to `PROVIDER`
AUTH_URI = "protocol/openid-connect/auth"
TOKEN_URI = "protocol/openid-connect/token"

SCICAT_URL = "http://localhost:3000/api/v3"


def main():
    logging.basicConfig(
        level="INFO",
        format="[%(name)s] %(message)s",
        datefmt="[%X]",
        handlers=[RichHandler()],
    )

    keycloak_token = token_with_device_flow()
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


def token_with_device_flow() -> str:
    code_verifier, code_challenge = generate_pkce_pair()

    r = httpx.post(
        f"{PROVIDER}/{AUTH_URI}/device",
        data={
            "client_id": CLIENT_ID,
            "scope": "openid",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",  # hard-coded in the code generator
        },
    )
    r.raise_for_status()
    initial_data = r.json()
    # keycloak returns this combined url as well, but other IdPs might not
    verification_uri = (
        initial_data["verification_uri"] + "?user_code=" + initial_data["user_code"]
    )
    # print(f"""
# vvv OPEN URL: vvv
    # {verification_uri}
# ^^^^^^^^^^^^^^^^^""")
    open_in_browser(verification_uri)

    for _ in range(30):
        r = httpx.post(
            f"{PROVIDER}/{TOKEN_URI}",
            data={
                "client_id": CLIENT_ID,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": initial_data["device_code"],
                "code_verifier": code_verifier,
            },
        )
        print(f"Got {r} {r.text}")
        if r.is_success:
            return r.json()["access_token"]
        # With the DMSC keycloak, this returns a HTML page with a nondescript error message
        # instead of JSON. But checking only for code=400 and looping works fine.
        if r.status_code != 400 or r.json().get("error") != "authorization_pending":
            raise RuntimeError(f"Bad reply: {r} {r.text}")

        time.sleep(initial_data["interval"])

    raise RuntimeError("Did not authenticate within timeout")

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
