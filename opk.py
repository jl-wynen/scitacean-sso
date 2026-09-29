# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "cryptography>=50.0.1",
#   "httpx",
#   "paramiko",
#   "rich",
#   "scitacean>=26",
# ]
# ///

import base64
import hashlib
import json
import logging
import pathlib
import secrets
import webbrowser
from typing import Any
import paramiko

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rich import print
from rich.logging import RichHandler
from scitacean._internal import jwt
import io
from oauth_server import launch_auth_server
from pkce import generate_pkce_pair

# Configured in Keycloak:
# PROVIDER = "http://keycloak.local:8080/realms/pkce-test"
PROVIDER = "http://localhost:8080/realms/pkce-test"
CLIENT_ID = "scicat-native-normal"

# DMSC Keycloak:
PROVIDER = "https://identity.esss.dk/realms/iam"
CLIENT_ID = "openpubkey"

SCOPES = ["openid", "email", "profile"]

# Relative to `PROVIDER`
AUTH_URI = "protocol/openid-connect/auth"
TOKEN_URI = "protocol/openid-connect/token"

PORT = 10001
PATH = "/login-callback"
REDIRECT_URI = f"http://localhost:{PORT}{PATH}"


# see https://eprint.iacr.org/2023/296.pdf
def main():
    logging.basicConfig(
        level="INFO",
        format="[%(name)s] %(message)s",
        datefmt="[%X]",
        handlers=[RichHandler()],
    )
    logging.getLogger("paramiko").setLevel(logging.DEBUG)

    key = Ed25519PrivateKey.generate()
    # private_key = key.private_bytes(
    #     crypto_serialization.Encoding.PEM,
    #     crypto_serialization.PrivateFormat.PKCS8,
    #     crypto_serialization.NoEncryption(),
    # )
    # public_key = (
    #     key.public_key()
    #     .public_bytes(
    #         # TODO? Encoding.Raw and PublicFormat.Raw ?
    #         crypto_serialization.Encoding.OpenSSH,
    #         crypto_serialization.PublicFormat.OpenSSH,
    #     )
    #     .decode()
    # )
    # print(private_key)
    # print(public_key)

    rz = secrets.token_urlsafe()
    cic_protected_b64, nonce = make_cic(key=key, rz=rz)

    idp_tokens = get_idp_tokens(nonce)
    print("=== IdP ===")
    print("--- ID token ---")
    id_token = idp_tokens["id_token"]
    print(jwt.decode(id_token))
    op_protected_b64, payload_b64, op_sig_b64 = id_token.split(".")
    op_protected, payload, op_sig = jwt.decode(id_token)
    assert payload["nonce"] == nonce  # sanity check

    print("=== client ===")
    signing_input = f"{cic_protected_b64}.{payload_b64}".encode("ascii")
    user_sig = key.sign(signing_input)
    try:
        key.public_key().verify(user_sig, signing_input)
    except InvalidSignature:
        print("invalid\n")
    else:
        print("valid\n")

    pk_token = {
        "payload": payload_b64,
        "signatures": [
            {"protected": op_protected_b64, "signature": op_sig_b64},
            {"protected": cic_protected_b64, "signature": b64u(user_sig)},
        ],
    }
    print(pk_token)

    print("=== serialize ===")
    cert = create_cert(pk_token, payload_b64, key,
        principals=["opkssh-wildcard"],
        # principals=["janlukaswynen"],
        # principals=[payload["email"]],
    )
    print(cert)

    priv = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.OpenSSH,   # not PKCS8 — ssh wants this
        crypto_serialization.NoEncryption(),
    )
    d = pathlib.Path.home() / ".ssh"
    (d / "id_opk").write_bytes(priv)
    (d / "id_opk").chmod(0o600)
    (d / "id_opk-cert.pub").write_text(cert + "\n")


    ssh_key = paramiko_key_from(key, cert)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(
        hostname="sftp.esss.dk",
        username="janlukaswynen",
        key_filename="/home/jl/.ssh/id_opk",
        # pkey=ssh_key,
        allow_agent=False,      # otherwise the agent may win before your key is tried
        look_for_keys=False,    # don't fall back to ~/.ssh/id_*
    )
    sftp = client.open_sftp()

    print(sftp.listdir("/ess/data"))

def paramiko_key_from(key: Ed25519PrivateKey, cert: str) -> paramiko.PKey:
    pem = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.OpenSSH,  # paramiko's Ed25519Key only parses this
        crypto_serialization.NoEncryption(),
    ).decode()
    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(pem))
    # cert is "ssh-ed25519-cert-v01@openssh.com <b64> <key_id>"
    # pkey.load_certificate(paramiko.PublicBlob.from_string(cert))
    # pkey.load_certificate(cert)  # "ssh-ed25519-cert-v01@openssh.com <b64> <key_id>"
    pkey.public_blob = paramiko.PublicBlob.from_string(cert)
    return pkey

def create_cert(pk_token: dict[str, Any], payload_b64: str, key: Ed25519PrivateKey, principals:list[str]):
    import struct
    import time

    def _string(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b

    def _u64(n: int) -> bytes:
        return struct.pack(">Q", n)

    def _u32(n: int) -> bytes:
        return struct.pack(">I", n)

    def _name_list(items: list[str]) -> bytes:
        return _string(b"".join(_string(i.encode()) for i in items))

    def _kv_list(pairs: list[tuple[str, bytes]]) -> bytes:
        # critical options / extensions: lexically sorted by name
        body = b"".join(_string(k.encode()) + _string(v) for k, v in sorted(pairs))
        return _string(body)

    CERT_TYPE = b"ssh-ed25519-cert-v01@openssh.com"
    SSH_CERT_TYPE_USER = 1

    def build_ssh_cert(
        key, pk_token_blob: bytes, principals: list[str], key_id: str, valid_before: int
    ) -> str:
        raw_pub = key.public_key().public_bytes(
            crypto_serialization.Encoding.Raw,
            crypto_serialization.PublicFormat.Raw,
        )
        ca_blob = _string(b"ssh-ed25519") + _string(raw_pub)  # self-signed: CA == upk

        tbs = (
            _string(CERT_TYPE)
            + _string(
                secrets.token_bytes(32)
            )  # nonce (anti-collision, not the OIDC nonce)
            + _string(raw_pub)  # pk
            + _u64(0)  # serial
            + _u32(SSH_CERT_TYPE_USER)  # type
            + _string(key_id.encode())  # key id
            + _name_list(principals)  # valid principals
            + _u64(int(time.time()) - 60)  # valid after (clock skew)
            + _u64(valid_before)  # valid before
            + _kv_list([])  # critical options
            + _kv_list([("openpubkey-pkt", pk_token_blob)])
            + _string(b"")  # reserved
            + _string(ca_blob)  # signature key
        )

        sig = key.sign(tbs)
        cert = tbs + _string(_string(b"ssh-ed25519") + _string(sig))
        return f"{CERT_TYPE.decode()} {base64.b64encode(cert).decode()} {key_id}"

    # CAVEATS (TODO)
    # - Whether the extension data is wrapped in another SSH string. OpenSSH's own valued extensions
    #   (force-command) use an embedded string, and ssh-keygen -O extension: does too — but some
    #   implementations store custom extension payloads raw. If your AuthorizedKeysCommand is opkssh,
    #   match whatever it expects; a one-byte-offset mismatch here is the most likely thing to break.
    # - The extension name. openpubkey-pkt has no @domain suffix, which is technically against the
    #   SSH naming convention for non-standard extensions and which ssh-keygen will reject on the
    #   signing side. It's fine when you encode the cert yourself, as above.

    payload = json.loads(b64u_decode(payload_b64))
    return build_ssh_cert(
        key,
        pk_token_blob=json.dumps(pk_token, separators=(",", ":")).encode(),
        principals=principals,
        # free form, useful for server-side auth log:
        key_id=payload.get("email", payload["sub"]),
        valid_before=int(payload["exp"]),
    )


def make_cic(key: Ed25519PrivateKey, rz: str) -> tuple[str, str]:
    """Return (protected_cic_b64, nonce)."""
    raw = key.public_key().public_bytes(
        crypto_serialization.Encoding.Raw,
        crypto_serialization.PublicFormat.Raw,
    )
    upk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw), "alg": "EdDSA"}

    cic = {"alg": "EdDSA", "upk": upk, "rz": rz, "typ": "CIC"}
    # canonical: sorted keys, no whitespace -> reproducible by the verifier
    protected = b64u(json.dumps(cic, sort_keys=True, separators=(",", ":")).encode())
    nonce = b64u(
        hashlib.sha3_256(protected.encode("ascii")).digest()
    )  # TODO check hash alg with SSH server
    return protected, nonce


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def get_idp_tokens(nonce: str) -> str:
    state = secrets.token_urlsafe()
    code_verifier, code_challenge = generate_pkce_pair()

    with httpx.Client(base_url=PROVIDER) as client:
        auth_uri = build_login_uri(client, code_challenge, state=state, nonce=nonce)

        # Start a server to handle the OAuth redirect with the auth code:
        with launch_auth_server(
            port=PORT, timeout=30, issuer=PROVIDER, state=state,path=PATH
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
            "scope": " ".join(SCOPES),
            "redirect_uri": REDIRECT_URI,
            "code_verifier": code_verifier,
        }
        response = client.post(TOKEN_URI, data=data)
        response.raise_for_status()
        j = response.json()
    assert j["token_type"] == "Bearer"
    return j


def build_login_uri(
    client: httpx.Client, code_challenge: str, state: str, nonce: str
) -> str:
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
            "nonce": nonce,
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
