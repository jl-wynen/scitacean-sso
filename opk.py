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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes
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

    ssh_key, username = ssh_login()

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(
        hostname="sftp.esss.dk",
        username=username,
        # key_filename="/home/jl/.ssh/id_opk",
        pkey=ssh_key,
        allow_agent=False,      # otherwise the agent may win before your key is tried
        look_for_keys=False,    # don't fall back to ~/.ssh/id_*
    )
    sftp = client.open_sftp()
    print(sftp.listdir("/ess/data"))

def ssh_login() -> tuple[paramiko.PKey,str]:
    key = ec.generate_private_key(ec.SECP256R1())

    rz = secrets.token_bytes(32).hex()
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

    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    user_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    try:
        key.public_key().verify(
            encode_dss_signature(
                int.from_bytes(user_sig[:32], "big"),
                int.from_bytes(user_sig[32:], "big"),
            ),
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        print("invalid\n")
    else:
        print("valid\n")

    # opkssh uses this format, not a JWS:
    pk_token = ":".join([payload_b64, op_protected_b64, op_sig_b64,
                         cic_protected_b64, b64u(user_sig)])
    print(pk_token)

    print("=== serialize ===")
    cert = create_cert(pk_token, payload_b64, key,
        principals=["opkssh-wildcard"],
        # principals=["janlukaswynen"],
        # principals=[payload["email"]],
    )
    print(cert)

    # priv = key.private_bytes(
    #     crypto_serialization.Encoding.PEM,
    #     crypto_serialization.PrivateFormat.OpenSSH,   # not PKCS8 — ssh wants this
    #     crypto_serialization.NoEncryption(),
    # )
    # d = pathlib.Path.home() / ".ssh"
    # (d / "id_opk").write_bytes(priv)
    # (d / "id_opk").chmod(0o600)
    # (d / "id_opk-cert.pub").write_text(cert + "\n")

    username = payload['preferred_username']

    return paramiko_key_from(key, cert), username

def paramiko_key_from(key: Ed25519PrivateKey, cert: str) -> paramiko.PKey:
    pem = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.OpenSSH,  # paramiko's Ed25519Key only parses this
        crypto_serialization.NoEncryption(),
    ).decode()
    pkey = paramiko.ECDSAKey.from_private_key(io.StringIO(pem))
    pkey.load_certificate(cert)
    return pkey

def create_cert(pk_token: str|dict[str, Any], payload_b64: str, key: Ed25519PrivateKey, principals:list[str]):
    import struct
    import time

    def _string(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b

    def _u64(n: int) -> bytes:
        return struct.pack(">Q", n)

    def _u32(n: int) -> bytes:
        return struct.pack(">I", n)

    def _mpint(n: int) -> bytes:
        """SSH mpint: big-endian two's complement, minimal length."""
        if n == 0:
            return _string(b"")
        b = n.to_bytes((n.bit_length() + 8) // 8, "big")  # +8 -> leading 0x00 if high bit set
        return _string(b)

    def _name_list(items: list[str]) -> bytes:
        return _string(b"".join(_string(i.encode()) for i in items))

    def _kv_list(pairs: list[tuple[str, bytes]]) -> bytes:
        # critical options / extensions: lexically sorted by name
        body = b"".join(_string(k.encode()) + _string(v) for k, v in sorted(pairs))
        return _string(body)

    # CERT_TYPE = b"ssh-ed25519-cert-v01@openssh.com"

    CERT_TYPE = b"ecdsa-sha2-nistp256-cert-v01@openssh.com"
    KEY_TYPE = b"ecdsa-sha2-nistp256"
    CURVE = b"nistp256"

    SSH_CERT_TYPE_USER = 1

    def build_ssh_cert(
        key, pk_token_blob: bytes, principals: list[str], key_id: str, valid_before: int
    ) -> str:
        point = key.public_key().public_bytes(
            crypto_serialization.Encoding.X962,
            crypto_serialization.PublicFormat.UncompressedPoint,
        )  # 0x04 || X || Y, 65 bytes
        ca_blob = _string(KEY_TYPE) + _string(CURVE) + _string(point)

        tbs = (
            _string(CERT_TYPE)
            + _string(secrets.token_bytes(32))   # nonce (anti-collision, not the OIDC nonce)
            + _string(CURVE)                     # pk: curve name ...
            + _string(point)                     # ... and point (two separate fields)
            + _u64(0)                            # serial
            + _u32(SSH_CERT_TYPE_USER)           # type
            + _string(key_id.encode())           # key id
            + _name_list(principals)             # valid principals
            + _u64(int(time.time()) - 60)        # valid after (clock skew)
            + _u64(valid_before)                 # valid before
            + _kv_list([])                       # critical options
            + _kv_list(
                [
                    ("openpubkey-pkt", _string(pk_token_blob)),  # value is string-wrapped
                    ("permit-X11-forwarding", b""),
                    ("permit-agent-forwarding", b""),
                    ("permit-port-forwarding", b""),
                    ("permit-pty", b""),
                    ("permit-user-rc", b""),
                ]
            )
            + _string(b"")                       # reserved
            + _string(ca_blob)                   # signature key (string-wrapped key blob)
        )

        der = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig_blob = _string(KEY_TYPE) + _string(_mpint(r) + _mpint(s))

        cert = tbs + _string(sig_blob)
        return f"{CERT_TYPE.decode()} {base64.b64encode(cert).decode()} {key_id}"

    payload = json.loads(b64u_decode(payload_b64))
    if isinstance(pk_token, str):
        pk_token_blob = pk_token.encode("ascii")
    else:
        pk_token_blob = json.dumps(pk_token, separators=(",", ":")).encode()
    return build_ssh_cert(
        key,
        pk_token_blob=pk_token_blob,
        principals=principals,
        # free form, useful for server-side auth log:
        key_id=payload.get("email", payload["sub"]),
        valid_before=int(payload["exp"]),
    )


def make_cic(key: Ed25519PrivateKey, rz: str) -> tuple[str, str]:
    """Return (protected_cic_b64, nonce)."""
    # 1st attempt:
#     raw = key.public_key().public_bytes(
#         crypto_serialization.Encoding.Raw,
#         crypto_serialization.PublicFormat.Raw,
#     )
#     upk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw), "alg": "EdDSA"}
#
#     cic = {"alg": "EdDSA", "upk": upk, "rz": rz, "typ": "CIC"}

    # 2nd attempt to match opkssh:
    nums = key.public_key().public_numbers()
    upk ={
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }
    cic = {"alg": "ES256", "rz": rz, "typ": "CIC", "upk": upk}
    cic_json = json.dumps(cic, sort_keys=True, separators=(",", ":")).encode()

    # canonical: sorted keys, no whitespace -> reproducible by the verifier
    protected = b64u(cic_json)
    nonce = b64u(
        hashlib.sha3_256(cic_json).digest()
    )
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
