"""HTTP-01 challenge validator (RFC 8555 §8.3).

Validates by fetching
``http://{identifier}:{port}/.well-known/acme-challenge/{token}``
and comparing the response body against the computed key authorization.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import secrets
import socket
import urllib.error
import urllib.request
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from acmeeh.challenge.base import ChallengeError, ChallengeValidator
from acmeeh.core.jws import key_authorization
from acmeeh.core.types import ChallengeType

if TYPE_CHECKING:
    from acmeeh.config.settings import Http01Settings

log = logging.getLogger(__name__)


class _RebindingCheckedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that re-applies the SSRF blocklist to every hop.

    ``urllib``'s default handler follows redirects transparently, so without
    this a malicious/compromised target could return a 3xx pointing at an
    internal address and bypass the pre-request blocklist check entirely.
    """

    def __init__(self, check_url) -> None:  # type: ignore[no-untyped-def]
        self._check_url = check_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self._check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _make_pinned_connection_classes(pinned_ips: dict[str, str]) -> tuple[type, type]:
    """Build HTTPConnection/HTTPSConnection subclasses that connect to a
    pre-validated IP instead of re-resolving the hostname.

    Without this, the blocklist check and the actual TCP connection each do
    their own independent DNS lookup (the check via ``getaddrinfo`` in
    ``check_host_allowed``, the connection via ``socket.create_connection``
    inside ``http.client``). A resolver under the attacker's control can
    answer those two lookups differently (e.g. TTL 0 / alternating answers),
    passing the blocklist check and then rebinding to an internal address for
    the real request. Pinning the socket to the exact IP that was checked
    closes that TOCTOU gap.
    """

    class _PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            ip = pinned_ips.get(self.host)
            if ip is None:
                super().connect()
                return
            self.sock = socket.create_connection(  # type: ignore[attr-defined]
                (ip, self.port), self.timeout, self.source_address  # type: ignore[attr-defined]
            )
            if self._tunnel_host:  # type: ignore[attr-defined]
                self._tunnel()  # type: ignore[attr-defined]

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            ip = pinned_ips.get(self.host)
            if ip is None:
                super().connect()
                return
            sock = socket.create_connection(
                (ip, self.port), self.timeout, self.source_address  # type: ignore[attr-defined]
            )
            if self._tunnel_host:  # type: ignore[attr-defined]
                self.sock = sock  # type: ignore[attr-defined]
                self._tunnel()  # type: ignore[attr-defined]
            self.sock = self._context.wrap_socket(  # type: ignore[attr-defined]
                sock, server_hostname=self.host
            )

    return _PinnedHTTPConnection, _PinnedHTTPSConnection


class Http01Validator(ChallengeValidator):
    """HTTP-01 challenge validator (RFC 8555 §8.3).

    Connects to the identifier on the configured port, requests the
    well-known challenge path, and verifies the response body matches
    the key authorization string.
    """

    challenge_type = ChallengeType.HTTP_01
    supported_identifier_types = frozenset({"dns"})

    def __init__(self, settings: Http01Settings | None = None) -> None:
        super().__init__(settings=settings)

    def validate(
        self,
        *,
        token: str,
        jwk: dict,
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Validate an HTTP-01 challenge.

        Algorithm:
        1. Compute key_authorization(token, jwk)
        2. Build URL: http://{identifier}:{port}/.well-known/acme-challenge/{token}
        3. HTTP GET with timeout, following redirects (up to 10)
        4. Verify HTTP 200 response
        5. Compare response body (stripped) to key authorization string
        """
        if identifier_type != "dns":
            msg = f"HTTP-01 only supports 'dns' identifiers, got '{identifier_type}'"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=False,
            )

        port = getattr(self.settings, "port", 80)
        timeout = getattr(self.settings, "timeout_seconds", 10)

        # Step 1: compute expected key authorization
        expected = key_authorization(token, jwk)

        # Step 2: build well-known URL
        if port == 80:
            url = f"http://{identifier_value}/.well-known/acme-challenge/{token}"
        else:
            url = f"http://{identifier_value}:{port}/.well-known/acme-challenge/{token}"

        log.debug("HTTP-01 validation: fetching %s", url)

        # Step 2b: DNS rebinding / SSRF protection — resolve the host and
        # check resolved IPs against blocked networks before connecting.
        # Applied both to the initial request and to every redirect hop
        # (see _RebindingCheckedRedirectHandler) so a redirect can't be used
        # to reach a blocked address after the initial check passes.
        blocked_networks_raw = getattr(self.settings, "blocked_networks", ())
        blocked_nets = []
        for cidr in blocked_networks_raw:
            try:
                blocked_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("Ignoring unparseable blocked_network: %s", cidr)

        # Maps hostname -> the single IP that was validated for it, so the
        # actual connection (via the pinned connection classes below) is
        # forced onto that exact address instead of re-resolving the host.
        pinned_ips: dict[str, str] = {}

        def check_host_allowed(host: str, host_port: int) -> None:
            if not blocked_nets:
                return
            try:
                addrinfos = socket.getaddrinfo(
                    host,
                    host_port,
                    proto=socket.IPPROTO_TCP,
                )
            except socket.gaierror as exc:
                msg = f"HTTP-01 validation failed: could not resolve {host}: {exc}"
                log.warning(msg)
                raise ChallengeError(
                    msg,
                    retryable=True,
                ) from exc

            resolved_ips = {info[4][0] for info in addrinfos}
            allowed_ips = set()
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                if not any(ip in net for net in blocked_nets):
                    allowed_ips.add(ip_str)

            if not allowed_ips:
                msg = (
                    f"HTTP-01 validation failed: all resolved IPs for "
                    f"{host} are in blocked networks "
                    f"(resolved: {sorted(resolved_ips)})"
                )
                log.warning(msg)
                raise ChallengeError(
                    msg,
                    retryable=False,
                )
            log.debug(
                "HTTP-01 rebinding check passed for %s (allowed: %s)",
                host,
                sorted(allowed_ips),
            )
            # Pin to one specific validated IP so the connection that is
            # actually made can't be routed to a different (possibly
            # blocked) address by a resolver that answers differently on
            # the next lookup.
            pinned_ips[host] = str(sorted(allowed_ips)[0])

        def check_redirect_url(redirect_url: str) -> None:
            parts = urlsplit(redirect_url)
            if parts.scheme not in ("http", "https"):
                msg = (
                    f"HTTP-01 validation failed: redirect to unsupported "
                    f"scheme '{parts.scheme}' ({redirect_url})"
                )
                log.warning(msg)
                raise ChallengeError(msg, retryable=False)
            if not parts.hostname:
                msg = f"HTTP-01 validation failed: redirect has no host ({redirect_url})"
                log.warning(msg)
                raise ChallengeError(msg, retryable=False)
            redirect_port = parts.port or (443 if parts.scheme == "https" else 80)
            check_host_allowed(parts.hostname, redirect_port)

        check_host_allowed(identifier_value, port)

        # Step 3: HTTP GET, re-checking the blocklist on every redirect hop.
        # The HTTP(S) handlers use pinned connection classes so the socket
        # connects to the exact IP that was just validated, rather than
        # letting http.client re-resolve the hostname itself.
        handlers: list[urllib.request.BaseHandler] = [
            _RebindingCheckedRedirectHandler(check_redirect_url)
        ]
        if blocked_nets:
            pinned_http_cls, pinned_https_cls = _make_pinned_connection_classes(pinned_ips)

            class _PinnedHTTPHandler(urllib.request.HTTPHandler):
                def http_open(self, req):  # type: ignore[no-untyped-def]
                    return self.do_open(pinned_http_cls, req)  # type: ignore[arg-type]

            class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
                def https_open(self, req):  # type: ignore[no-untyped-def]
                    return self.do_open(
                        pinned_https_cls,  # type: ignore[arg-type]
                        req,
                        context=self._context,  # type: ignore[attr-defined]
                    )

            handlers.append(_PinnedHTTPHandler())
            handlers.append(_PinnedHTTPSHandler())
        opener = urllib.request.build_opener(*handlers)
        try:
            req = urllib.request.Request(url, method="GET")
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            msg = f"HTTP-01 validation failed: server returned HTTP {exc.code} for {url}"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            msg = (
                f"HTTP-01 validation failed: could not connect to {identifier_value}:{port}: {exc}"
            )
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc

        # Step 4: verify HTTP 200
        if resp.status != 200:
            msg = f"HTTP-01 validation failed: expected HTTP 200, got {resp.status}"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            )

        # Step 5: read body (size-limited) and compare
        try:
            _max_bytes = getattr(self.settings, "max_response_bytes", 1048576)
            body = resp.read(_max_bytes)
        except OSError as exc:
            msg = f"HTTP-01 validation failed: error reading response body: {exc}"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc

        try:
            body_text = body.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            msg = f"HTTP-01 validation failed: response body is not valid UTF-8: {exc}"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=False,
            ) from exc

        if not secrets.compare_digest(body_text.encode(), expected.encode()):
            msg = "HTTP-01 validation failed: response body does not match key authorization"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=False,
            )

        log.info(
            "HTTP-01 validation succeeded for %s (port %s)",
            identifier_value,
            port,
        )
