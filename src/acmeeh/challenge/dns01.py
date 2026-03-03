"""DNS-01 challenge validator (RFC 8555 §8.4).

Validates by querying ``_acme-challenge.{domain}`` for a TXT record
containing the base64url-encoded SHA-256 digest of the key authorization.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import TYPE_CHECKING

import dns.exception
import dns.flags
import dns.name
import dns.rdatatype
import dns.resolver

from acmeeh.challenge.base import ChallengeError, ChallengeValidator
from acmeeh.core.jws import key_authorization
from acmeeh.core.types import ChallengeType

if TYPE_CHECKING:
    from acmeeh.config.settings import Dns01Settings

log = logging.getLogger(__name__)


class Dns01Validator(ChallengeValidator):
    """DNS-01 challenge validator (RFC 8555 §8.4).

    Queries ``_acme-challenge.{domain}`` for a TXT record whose value
    matches the base64url-encoded SHA-256 digest of the key authorization.
    Supports wildcard identifiers by stripping the ``*.`` prefix.
    """

    challenge_type = ChallengeType.DNS_01
    supported_identifier_types = frozenset({"dns"})

    def __init__(self, settings: Dns01Settings | None = None) -> None:
        super().__init__(settings=settings)

    def validate(  # noqa: C901, PLR0912, PLR0915
        self,
        *,
        token: str,
        jwk: dict,
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Validate a DNS-01 challenge.

        Algorithm:
        1. Compute key_authorization and its SHA-256 digest
        2. base64url-encode the digest (expected TXT value)
        3. Strip wildcard prefix if present
        4. Query ``_acme-challenge.{domain}`` for TXT records
        5. One of the TXT record values must exactly match
        """
        if identifier_type != "dns":
            msg = f"DNS-01 only supports 'dns' identifiers, got '{identifier_type}'"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=False,
            )

        timeout = getattr(self.settings, "timeout_seconds", 30)
        resolvers = getattr(self.settings, "resolvers", ())

        # Step 1-2: compute expected TXT value
        key_authz = key_authorization(token, jwk)
        digest = hashlib.sha256(key_authz.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        # Step 3: strip wildcard prefix
        domain = identifier_value
        domain = domain.removeprefix("*.")

        # Step 4: build query name
        query_name = f"_acme-challenge.{domain}"
        log.debug(
            "DNS-01 validation: querying TXT for %s (expected %s)",
            query_name,
            expected,
        )

        # Configure resolver
        require_dnssec = getattr(self.settings, "require_dnssec", False)
        require_authoritative = getattr(self.settings, "require_authoritative", False)
        resolver = dns.resolver.Resolver()
        if resolvers:
            resolver.nameservers = list(resolvers)
        resolver.lifetime = timeout
        if require_dnssec:
            resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        # Step 4b: authoritative NS resolution (when enabled)
        if require_authoritative:
            try:
                zone = dns.resolver.zone_for_name(domain)
                ns_answer = dns.resolver.resolve(zone, "NS")
                ns_ips = []
                for rdata in ns_answer:
                    ns_name = rdata.target.to_text()
                    try:
                        a_answer = dns.resolver.resolve(ns_name, "A")
                        for a_rdata in a_answer:
                            ns_ips.append(a_rdata.address)
                    except dns.exception.DNSException:
                        pass
                    try:
                        aaaa_answer = dns.resolver.resolve(ns_name, "AAAA")
                        for aaaa_rdata in aaaa_answer:
                            ns_ips.append(aaaa_rdata.address)
                    except dns.exception.DNSException:
                        pass

                if ns_ips:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = ns_ips
                    resolver.lifetime = timeout
                    if require_dnssec:
                        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)
                    log.debug(
                        "DNS-01 using authoritative NS for %s: %s",
                        domain,
                        ns_ips,
                    )
                else:
                    log.warning(
                        "DNS-01 authoritative NS lookup for %s yielded "
                        "no IPs — falling back to standard resolution",
                        domain,
                    )
            except dns.exception.DNSException as exc:
                log.warning(
                    "DNS-01 authoritative NS lookup failed for %s: %s "
                    "— falling back to standard resolution",
                    domain,
                    exc,
                )

        # Step 5: query and compare
        try:
            answer = resolver.resolve(query_name, "TXT")

            # DNSSEC validation
            if require_dnssec:
                if not (answer.response.flags & dns.flags.AD):
                    msg = (
                        f"DNS-01 validation failed: DNSSEC validation failed "
                        f"for {query_name} — response not authenticated "
                        f"(AD flag not set)"
                    )
                    log.warning(msg)
                    raise ChallengeError(
                        msg,
                        retryable=True,
                    )

        except dns.resolver.NXDOMAIN as exc:
            msg = (
                f"DNS-01 validation failed: {query_name} does not exist "
                f"(NXDOMAIN) — record may not have propagated yet"
            )
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc
        except dns.resolver.NoAnswer as exc:
            msg = (
                f"DNS-01 validation failed: {query_name} exists but has "
                f"no TXT records — record may not have propagated yet"
            )
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc
        except dns.resolver.NoNameservers as exc:
            msg = (
                f"DNS-01 validation failed: no nameservers available "
                f"for {query_name} (SERVFAIL or all refused)"
            )
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc
        except dns.exception.Timeout as exc:
            msg = f"DNS-01 validation failed: DNS query for {query_name} timed out after {timeout}s"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc
        except dns.exception.DNSException as exc:
            msg = f"DNS-01 validation failed: DNS error querying {query_name}: {exc}"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc

        # Extract and compare TXT record values
        found_values = []
        for rdata in answer:
            # TXT rdata has .strings — a tuple of bytes segments.
            # Concatenate them (per RFC 7208 §3.3) and decode.
            txt_value = b"".join(rdata.strings).decode("ascii", errors="replace")
            found_values.append(txt_value)
            if txt_value == expected:
                log.info(
                    "DNS-01 validation succeeded for %s (query %s)",
                    identifier_value,
                    query_name,
                )
                return

        msg = (
            f"DNS-01 validation failed: no TXT record at {query_name} "
            f"matches the expected digest. Found {len(found_values)} "
            f"record(s) but none matched"
        )
        log.warning(msg)
        raise ChallengeError(
            msg,
            retryable=True,
        )
