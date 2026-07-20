"""CAA record validation (RFC 8659).

Checks CAA DNS records to verify that the ACME server is authorized
to issue certificates for the requested domain.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from acmeeh.app.errors import CAA, DNS, AcmeProblem

if TYPE_CHECKING:
    from acmeeh.config.settings import DnsSettings

log = logging.getLogger(__name__)


class CAAValidator:
    """Validates CAA records per RFC 8659.

    Includes a thread-safe TTL cache for negative results (no CAA records
    found) to avoid redundant DNS queries for multi-level subdomains.
    """

    def __init__(
        self,
        caa_identities: tuple[str, ...],
        dns_settings: DnsSettings,
        negative_cache_ttl: int = 3600,
    ) -> None:
        self._identities = caa_identities
        self._dns = dns_settings
        self._negative_cache_ttl = negative_cache_ttl
        # Cache: domain -> expiry timestamp (monotonic)
        self._negative_cache: dict[str, float] = {}
        self._cache_lock = threading.Lock()

    def check(self, domain: str, *, is_wildcard: bool = False) -> None:
        """Check CAA records for *domain*.

        Walks up the domain tree if no CAA records are found at the
        queried name.  If CAA records exist but none authorize this
        server, raises an ``AcmeProblem``.

        Per RFC 8659 §4.2:
        - For wildcard domains (``is_wildcard=True``): check ``issuewild``
          tags first; fall back to ``issue`` if no ``issuewild`` present.
        - For non-wildcard domains: check only ``issue`` tags.

        Skips validation if no ``caa_identities`` are configured.
        """
        if not self._identities:
            return

        # Strip wildcard prefix for DNS lookup
        lookup_domain = domain
        if is_wildcard and lookup_domain.startswith("*."):
            lookup_domain = lookup_domain[2:]

        # Check negative cache — if we recently confirmed no CAA records
        # exist for this domain, skip the DNS lookup.
        if self._check_negative_cache(lookup_domain):
            log.debug(
                "CAA check skipped for %s — negative cache hit",
                domain,
            )
            return

        resolver = dns.resolver.Resolver()
        if self._dns.resolvers:
            resolver.nameservers = list(self._dns.resolvers)
        resolver.lifetime = self._dns.timeout_seconds

        # Walk up the domain tree
        labels = lookup_domain.rstrip(".").split(".")
        for i in range(len(labels)):
            name = ".".join(labels[i:])
            try:
                answer = resolver.resolve(name, "CAA")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.exception.DNSException as exc:
                log.warning("CAA lookup failed for %s: %s", name, exc)
                # Fail closed: an unresolvable CAA lookup must not be treated
                # as "no CAA records found". RFC 8659 §4.1 requires issuance
                # to be refused if CAA records cannot be retrieved due to an
                # error, to avoid an attacker using DNS failures to bypass
                # CAA restrictions.
                raise AcmeProblem(
                    DNS,
                    f"CAA lookup for {name} failed: {exc}",
                    status=500,
                ) from exc

            # CAA records found — collect tags
            issue_values = []
            issuewild_values = []
            for rdata in answer:
                caa_tag = rdata.tag.decode("ascii", errors="replace").lower()
                caa_value = rdata.value.decode("ascii", errors="replace").strip('"')
                if caa_tag == "issue":
                    issue_values.append(caa_value)
                elif caa_tag == "issuewild":
                    issuewild_values.append(caa_value)

            if is_wildcard:
                # RFC 8659 §4.2: use issuewild if present, else fall back to issue
                check_values = issuewild_values or issue_values
            else:
                check_values = issue_values

            for val in check_values:
                if val in self._identities:
                    log.debug(
                        "CAA check passed for %s (matched %s at %s)",
                        domain,
                        val,
                        name,
                    )
                    return

            # CAA records exist but none authorize us
            raise AcmeProblem(
                CAA,
                f"CAA records at {name} do not authorize this server "
                f"to issue certificates for {domain}. "
                f"Expected one of: {list(self._identities)}",
                status=403,
            )

        # No CAA records found anywhere — issuance is permitted
        # Cache this negative result to avoid repeated DNS walks
        self._set_negative_cache(lookup_domain)
        log.debug("No CAA records found for %s — issuance permitted", domain)

    def _check_negative_cache(self, domain: str) -> bool:
        """Return True if domain is in the negative cache and not expired."""
        with self._cache_lock:
            expiry = self._negative_cache.get(domain)
            if expiry is None:
                return False
            if time.monotonic() > expiry:
                del self._negative_cache[domain]
                return False
            return True

    def _set_negative_cache(self, domain: str) -> None:
        """Store a negative result in the cache."""
        with self._cache_lock:
            self._negative_cache[domain] = time.monotonic() + self._negative_cache_ttl

    def clear_cache(self) -> None:
        """Clear the negative result cache (useful for testing)."""
        with self._cache_lock:
            self._negative_cache.clear()
