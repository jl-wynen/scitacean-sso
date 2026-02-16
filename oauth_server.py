from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse

@contextmanager
def launch_auth_server(*,port:int, timeout:int, state:str, issuer:str)->Generator[OAuthHttpServer, None,None]:
    with OAuthHttpServer(("", port), OAuthHttpHandler, timeout=timeout, state=state, issuer=issuer) as server:
        yield server


class OAuthHttpServer(HTTPServer):
    """Server to receive the authorization code."""

    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type,*, timeout:int,state:str, issuer:str) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.timeout = timeout
        self.state = state
        self.issuer = issuer
        self.authorization_code: str | None = None

    def handle_timeout(self) -> None:
        super().handle_timeout()
        raise TimeoutError(
            "The OAuth server did not receive an authorization code after "
            f"{self.timeout} seconds. This means either that nobody logged "
            "in successfully in that time or that the identity provider did "
            "not redirect or did not redirect correctly.")


class OAuthHttpHandler(BaseHTTPRequestHandler):
    """Handler for the OAuth HTTP server."""

    def do_GET(self) -> None:
        # TODO do not show success on failure
        data = SUCCESS_HTML.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        # TODO doesn't close the window on first login but does close when login is cached
        #   In the former case, the user interacted with the window which triggered a page change
        #   and scripts are not allowed to close the window in that case.
        #   See https://developer.mozilla.org/en-US/docs/Web/API/Window/close
        self.wfile.write(data)

        server: OAuthHttpServer = self.server  # type: ignore[assignment]

        parsed = parse.urlparse(self.path)
        qs = parse.parse_qs(parsed.query)
        if qs.get("state", None) != [server.state]:
            raise ValueError("Invalid state")
        if qs.get("iss", None) != [server.issuer]:
            raise ValueError("Invalid issuer")

        server.authorization_code = qs.get("code", [None])[0]

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
