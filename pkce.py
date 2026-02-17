import secrets
import hashlib
import base64


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
