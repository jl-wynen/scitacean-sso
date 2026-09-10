from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager
from functools import cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from string import Template
from urllib import parse


@contextmanager
def launch_auth_server(
    *, port: int, timeout: int, state: str, issuer: str
) -> Generator[OAuthHttpServer, None, None]:
    with OAuthHttpServer(
        ("", port), OAuthHttpHandler, timeout=timeout, state=state, issuer=issuer
    ) as server:
        yield server


class OAuthHttpServer(HTTPServer):
    """Server to receive the authorization code."""

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type,
        *,
        timeout: int,
        state: str,
        issuer: str,
    ) -> None:
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
            "not redirect or did not redirect correctly."
        )


class OAuthHttpHandler(BaseHTTPRequestHandler):
    """Handler for the OAuth HTTP server."""

    def do_GET(self) -> None:
        server: OAuthHttpServer = self.server  # type: ignore[assignment]

        parsed = parse.urlparse(self.path)
        qs = parse.parse_qs(parsed.query)
        if qs.get("state", None) != [server.state]:
            self._send_result_page(success=False)
            raise ValueError("Invalid state")
        # Keycloak returns an issuer, ping does not
        # if qs.get("iss", None) != [server.issuer]:
        #     self._send_result_page(success=False)
        #     raise ValueError("Invalid issuer")

        server.authorization_code = qs.get("code", [None])[0]
        self._send_result_page(success=True)

    def _send_result_page(self, *, success: bool) -> None:
        if success:
            text = _success_page()
        else:
            text = _failure_page()
        data = text.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        # TODO doesn't close the window on first login but does close when login is cached
        #   In the former case, the user interacted with the window which triggered a page change
        #   and scripts are not allowed to close the window in that case.
        #   See https://developer.mozilla.org/en-US/docs/Web/API/Window/close
        self.wfile.write(data)

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


def _success_page() -> str:
    content = _html_asset("success")
    base = _base_html()
    return base.substitute(content=content, title="Authenticated")


def _failure_page() -> str:
    content = _html_asset("failure")
    base = _base_html()
    return base.substitute(content=content, title="Login failed")


def _base_html() -> Template:
    return Template(_html_asset("base"))


@cache
def _html_asset(name: str) -> str:
    with open((Path(__file__).parent / "assets" / name).with_suffix(".html"), "r") as f:
        return f.read()
