"""HTTP-01 challenge validator (RFC 8555 §8.3).

Validates by fetching
``http://{identifier}:{port}/.well-known/acme-challenge/{token}``
and comparing the response body against the computed key authorization.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

from acmeeh.challenge.base import ChallengeError, ChallengeValidator
from acmeeh.core.jws import key_authorization
from acmeeh.core.types import ChallengeType

if TYPE_CHECKING:
    from acmeeh.config.settings import Http01Settings

log = logging.getLogger(__name__)


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

        # Step 2b: DNS rebinding protection — resolve domain and check
        # resolved IPs against blocked networks before connecting.
        blocked_networks_raw = getattr(self.settings, "blocked_networks", ())
        if blocked_networks_raw:
            blocked_nets = []
            for cidr in blocked_networks_raw:
                try:
                    blocked_nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    log.warning("Ignoring unparseable blocked_network: %s", cidr)

            if blocked_nets:
                try:
                    addrinfos = socket.getaddrinfo(
                        identifier_value,
                        port,
                        proto=socket.IPPROTO_TCP,
                    )
                except socket.gaierror as exc:
                    msg = f"HTTP-01 validation failed: could not resolve {identifier_value}: {exc}"
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
                        f"{identifier_value} are in blocked networks "
                        f"(resolved: {sorted(resolved_ips)})"
                    )
                    log.warning(msg)
                    raise ChallengeError(
                        msg,
                        retryable=False,
                    )
                log.debug(
                    "HTTP-01 rebinding check passed for %s (allowed: %s)",
                    identifier_value,
                    sorted(allowed_ips),
                )

        # Step 3: HTTP GET
        try:
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, timeout=timeout)
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
