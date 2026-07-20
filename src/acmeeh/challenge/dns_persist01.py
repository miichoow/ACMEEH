"""DNS-PERSIST-01 challenge validator (draft-ietf-acme-dns-persist).

Unlike DNS-01, this method has no per-challenge token and no key
authorization.  The subscriber publishes a long-lived TXT record at
``_validation-persist.{domain}`` whose value follows the ``issue-value``
syntax of RFC 8659 (the CAA record format) and binds an Issuer Domain Name
to the ACME account permitted to request issuance::

    _validation-persist.example.com. IN TXT "ca.example; accounturi=https://ca.example/acct/1"

Because the record authorizes *future* issuance, it is meant to stay
published; nothing here removes it.

The CA side of the draft is:

1. Query TXT at the Validation Domain Name.
2. Discard records whose Issuer Domain Name is not one of ours.
3. For each surviving record, check ``accounturi`` against the requesting
   account and ``persistUntil`` against the clock.
4. Succeed if any record passes; otherwise fail.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

import dns.exception
import dns.flags
import dns.name
import dns.nameserver
import dns.rdatatype
import dns.resolver

from acmeeh.challenge.base import ChallengeError, ChallengeValidator
from acmeeh.core.types import ChallengeType

if TYPE_CHECKING:
    from acmeeh.challenge.base import ChallengeContext
    from acmeeh.config.settings import DnsPersist01Settings

log = logging.getLogger(__name__)

PERSIST_LABEL = "_validation-persist"
"""Underscored node name prepended to form the Validation Domain Name."""

WILDCARD_POLICY = "wildcard"
"""``policy`` value authorizing wildcards and subdomains."""

# RFC 8659 §4.2: a parameter tag is one or more alphanumerics.
_TAG_RE = re.compile(r"^[A-Za-z0-9]+$")

# RFC 8659 §4.2: a parameter value is printable US-ASCII excluding ";" (%x3B),
# which terminates the parameter.  Whitespace is excluded so that a value
# cannot silently swallow the separator between two parameters.
_VALUE_RE = re.compile(r"^[\x21-\x3A\x3C-\x7E]+$")

# An Issuer Domain Name is a DNS name; the usual LDH label set applies.  An
# empty issuer is rejected: in CAA a bare ";" means "no issuer permitted",
# which is never a valid dns-persist-01 record.
_ISSUER_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


class PersistRecordError(ValueError):
    """Raised when a DNS-PERSIST-01 TXT record value is malformed."""


@dataclass(frozen=True)
class PersistRecord:
    """A parsed DNS-PERSIST-01 TXT record value.

    Parameters
    ----------
    issuer_domain_name:
        The Issuer Domain Name authorized by this record, normalized to
        lowercase without a trailing dot.
    accounturi:
        URI of the ACME account permitted to request issuance.
    policy:
        The ``policy`` parameter, if present.
    persist_until:
        The ``persistUntil`` parameter as a UNIX timestamp, if present.
    parameters:
        Any further parameters, in encounter order.

    """

    issuer_domain_name: str
    accounturi: str
    policy: str | None = None
    persist_until: int | None = None
    parameters: tuple[tuple[str, str], ...] = field(default=())

    @property
    def allows_wildcard(self) -> bool:
        """Whether the record carries ``policy=wildcard``.

        The draft treats the ``policy`` tag and its defined values as
        case-insensitive, and says any other value must be handled as if
        the parameter were absent.
        """
        return self.policy is not None and self.policy.lower() == WILDCARD_POLICY

    def is_expired(self, now: datetime | None = None) -> bool:
        """Whether ``persistUntil`` has passed.

        Records without ``persistUntil`` never expire.
        """
        if self.persist_until is None:
            return False
        moment = now or datetime.now(UTC)
        return moment.timestamp() > self.persist_until


def validation_domain_name(domain: str) -> str:
    """Build the Validation Domain Name for *domain*.

    A wildcard identifier is validated through the record for its base
    domain — the wildcard itself is authorized by ``policy=wildcard`` in the
    record value, not by a distinct record name.

    Examples
    --------
    >>> validation_domain_name("example.com")
    '_validation-persist.example.com'
    >>> validation_domain_name("*.example.com")
    '_validation-persist.example.com'

    """
    base = domain.removeprefix("*.").rstrip(".")
    return f"{PERSIST_LABEL}.{base}"


def parse_nameserver(spec: str) -> str | dns.nameserver.Do53Nameserver:
    """Parse a configured resolver into something dnspython accepts.

    A plain address is returned unchanged. An ``address:port`` form — needed
    for split-horizon resolvers that do not listen on 53 — becomes a
    :class:`dns.nameserver.Do53Nameserver`, since ``Resolver.nameservers``
    itself carries no port. IPv6 addresses use the bracketed ``[::1]:5353``
    form, because a bare IPv6 address is full of colons.

    Examples
    --------
    >>> parse_nameserver("192.0.2.53")
    '192.0.2.53'
    >>> parse_nameserver("192.0.2.53:5353").port
    5353

    """
    spec = spec.strip()

    if spec.startswith("["):
        address, _, port = spec.partition("]")
        address = address[1:]
        port = port.lstrip(":")
        if not port:
            return address
        return dns.nameserver.Do53Nameserver(address, int(port))

    # A bare IPv6 address has several colons; only a single one can be a
    # port separator.
    if spec.count(":") == 1:
        address, _, port = spec.partition(":")
        return dns.nameserver.Do53Nameserver(address, int(port))

    return spec


def ancestors(domain: str, *, min_labels: int = 2) -> list[str]:
    """Return the ancestor domains of *domain*, closest first.

    Used for the draft's subdomain semantics: a ``policy=wildcard`` record on
    an ancestor authorizes issuance for names below it.  The walk stops at
    *min_labels* so a lookup never reaches a TLD, where no subscriber can
    publish a record and every query is wasted.

    Examples
    --------
    >>> ancestors("a.b.example.com")
    ['b.example.com', 'example.com']
    >>> ancestors("example.com")
    []

    """
    labels = domain.removeprefix("*.").rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(1, max(len(labels) - min_labels + 1, 1))]


def parse_record(value: str) -> PersistRecord:
    """Parse a DNS-PERSIST-01 TXT record value.

    Raises
    ------
    PersistRecordError
        If the value is not well-formed ``issue-value`` syntax, repeats a
        parameter, or omits the mandatory ``accounturi``.

    """
    segments = value.split(";")
    issuer = segments[0].strip()

    if not _ISSUER_RE.match(issuer):
        msg = f"invalid issuer-domain-name {issuer!r}"
        raise PersistRecordError(msg)

    accounturi: str | None = None
    policy: str | None = None
    persist_until: int | None = None
    extra: list[tuple[str, str]] = []
    seen: set[str] = set()

    for raw_segment in segments[1:]:
        segment = raw_segment.strip()
        if not segment:
            # RFC 8659 tolerates empty/trailing separators.
            continue

        tag, sep, raw_value = segment.partition("=")
        if not sep:
            msg = f"parameter is not a tag=value pair: {segment!r}"
            raise PersistRecordError(msg)

        tag = tag.strip()
        raw_value = raw_value.strip()
        if not _TAG_RE.match(tag):
            msg = f"invalid parameter tag {tag!r}"
            raise PersistRecordError(msg)

        # RFC 8659 §4.2 matches parameter tags case-insensitively, so
        # "persistUntil", "persistuntil" and "PERSISTUNTIL" are one tag.
        # Comparing the raw spelling would let a record expire silently.
        canonical = tag.lower()

        # The draft calls a duplicate parameter a malformed record rather
        # than letting last-wins silently pick one of two meanings.
        if canonical in seen:
            msg = f"duplicate parameter {tag!r}"
            raise PersistRecordError(msg)
        seen.add(canonical)

        if canonical == "accounturi":
            if not raw_value:
                msg = "empty value for mandatory accounturi parameter"
                raise PersistRecordError(msg)
            accounturi = _check_value(tag, raw_value)
        elif canonical == "policy":
            # An empty or unrecognized policy is treated as absent rather
            # than as an error, per the draft.
            policy = _check_value(tag, raw_value) if raw_value else None
        elif canonical == "persistuntil":
            persist_until = _parse_persist_until(raw_value)
        elif raw_value:
            extra.append((canonical, _check_value(tag, raw_value)))
        else:
            extra.append((canonical, ""))

    if accounturi is None:
        msg = "record is missing the mandatory accounturi parameter"
        raise PersistRecordError(msg)

    return PersistRecord(
        issuer_domain_name=issuer.rstrip(".").lower(),
        accounturi=accounturi,
        policy=policy,
        persist_until=persist_until,
        parameters=tuple(extra),
    )


def _check_value(tag: str, value: str) -> str:
    """Validate a parameter value against RFC 8659 issue-value syntax."""
    if not _VALUE_RE.match(value):
        msg = (
            f"invalid value for parameter {tag!r}: {value!r} "
            "(must be printable US-ASCII without ';' or whitespace)"
        )
        raise PersistRecordError(msg)
    return value


def _parse_persist_until(raw: str) -> int:
    """Parse a ``persistUntil`` value as a base-10 UNIX timestamp."""
    # int() would accept "+10", "_" separators and surrounding whitespace;
    # the draft asks for a plain base-10 integer.
    if not raw.isdigit():
        msg = f"persistUntil is not a base-10 timestamp: {raw!r}"
        raise PersistRecordError(msg)
    return int(raw)


class DnsPersist01Validator(ChallengeValidator):
    """DNS-PERSIST-01 challenge validator (draft-ietf-acme-dns-persist).

    Queries ``_validation-persist.{domain}`` for TXT records, keeps those
    naming one of the CA's configured Issuer Domain Names, and accepts the
    challenge if any of them authorizes the requesting account for the
    identifier being validated.
    """

    challenge_type: ClassVar[ChallengeType] = ChallengeType.DNS_PERSIST_01
    supported_identifier_types: ClassVar[frozenset[str]] = frozenset({"dns"})
    requires_context: ClassVar[bool] = True
    uses_token: ClassVar[bool] = False

    def __init__(self, settings: DnsPersist01Settings | None = None) -> None:
        super().__init__(settings=settings)

    @property
    def issuer_domain_names(self) -> tuple[str, ...]:
        """The Issuer Domain Names this CA accepts and advertises."""
        return tuple(getattr(self.settings, "issuer_domain_names", ()) or ())

    def validate(
        self,
        *,
        token: str,
        jwk: dict,
        identifier_type: str,
        identifier_value: str,
        context: ChallengeContext | None = None,
    ) -> None:
        """Validate a DNS-PERSIST-01 challenge.

        ``token`` and ``jwk`` are accepted to satisfy the validator
        interface but are unused: this method has neither a token nor a key
        authorization.
        """
        del token, jwk

        if identifier_type != "dns":
            msg = f"DNS-PERSIST-01 only supports 'dns' identifiers, got '{identifier_type}'"
            log.warning(msg)
            raise ChallengeError(msg, retryable=False)

        issuers = self.issuer_domain_names
        if not issuers:
            # Without configured issuer names nothing can ever match, and
            # treating that as a client failure would be misleading.
            msg = (
                "DNS-PERSIST-01 is enabled but no issuer_domain_names are "
                "configured — the server cannot validate this challenge type"
            )
            log.error(msg)
            raise ChallengeError(msg, retryable=False)

        account_uri = context.account_uri if context else None
        if not account_uri:
            msg = "DNS-PERSIST-01 validation failed: the requesting account has no account URI"
            log.error(msg)
            raise ChallengeError(msg, retryable=False)

        is_wildcard = bool(context and context.is_wildcard)
        domain = identifier_value.removeprefix("*.")

        # The exact name authorizes the FQDN itself; ancestors can only
        # authorize it through policy=wildcard, which the draft defines as
        # covering subdomains for which the validated name is a proper suffix.
        candidates: list[tuple[str, bool]] = [(domain, is_wildcard)]
        if getattr(self.settings, "allow_subdomain_policy", True):
            candidates += [(ancestor, True) for ancestor in ancestors(domain)]

        errors: list[ChallengeError] = []
        for candidate_domain, require_wildcard in candidates:
            query_name = validation_domain_name(candidate_domain)
            log.debug(
                "DNS-PERSIST-01 validation: querying TXT for %s "
                "(account %s, requires policy=wildcard: %s)",
                query_name,
                account_uri,
                require_wildcard,
            )
            try:
                answer = self._query(query_name, candidate_domain)
                self._match(
                    answer=answer,
                    query_name=query_name,
                    issuers=issuers,
                    account_uri=account_uri,
                    require_wildcard=require_wildcard,
                    identifier_value=identifier_value,
                )
            except ChallengeError as exc:
                errors.append(exc)
                continue
            return

        # Every candidate failed. Surface the failure for the exact name --
        # it is the one the subscriber most likely intended -- but keep the
        # attempt retryable only if some candidate could still succeed later.
        primary = errors[0]
        raise ChallengeError(primary.detail, retryable=any(e.retryable for e in errors))

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    def _build_resolver(self, domain: str) -> dns.resolver.Resolver:
        """Build a resolver, optionally pinned to the zone's authoritative NS."""
        timeout = getattr(self.settings, "timeout_seconds", 30)
        resolvers = getattr(self.settings, "resolvers", ())
        require_dnssec = getattr(self.settings, "require_dnssec", False)
        require_authoritative = getattr(self.settings, "require_authoritative", False)

        resolver = dns.resolver.Resolver()
        if resolvers:
            resolver.nameservers = [parse_nameserver(r) for r in resolvers]
        resolver.lifetime = timeout
        if require_dnssec:
            resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        if not require_authoritative:
            return resolver

        ns_ips = self._authoritative_nameservers(domain)
        if not ns_ips:
            log.warning(
                "DNS-PERSIST-01 authoritative NS lookup for %s yielded no IPs "
                "— falling back to standard resolution",
                domain,
            )
            return resolver

        authoritative = dns.resolver.Resolver(configure=False)
        authoritative.nameservers = ns_ips
        authoritative.lifetime = timeout
        if require_dnssec:
            authoritative.use_edns(edns=0, ednsflags=dns.flags.DO)
        log.debug("DNS-PERSIST-01 using authoritative NS for %s: %s", domain, ns_ips)
        return authoritative

    @staticmethod
    def _authoritative_nameservers(domain: str) -> list[str]:
        """Resolve the IPs of the authoritative nameservers for *domain*."""
        ns_ips: list[str] = []
        try:
            zone = dns.resolver.zone_for_name(domain)
            ns_answer = dns.resolver.resolve(zone, "NS")
        except dns.exception.DNSException as exc:
            log.warning(
                "DNS-PERSIST-01 authoritative NS lookup failed for %s: %s "
                "— falling back to standard resolution",
                domain,
                exc,
            )
            return []

        for rdata in ns_answer:
            ns_name = rdata.target.to_text()
            for rrtype in ("A", "AAAA"):
                try:
                    for addr in dns.resolver.resolve(ns_name, rrtype):
                        ns_ips.append(addr.address)
                except dns.exception.DNSException:  # noqa: PERF203
                    continue
        return ns_ips

    def _query(self, query_name: str, domain: str) -> dns.resolver.Answer:
        """Query TXT records at the Validation Domain Name.

        Every DNS-level failure is retryable: the record is long-lived, so a
        lookup failure is far more likely to be transient than to mean the
        subscriber never published it.
        """
        timeout = getattr(self.settings, "timeout_seconds", 30)
        require_dnssec = getattr(self.settings, "require_dnssec", False)
        resolver = self._build_resolver(domain)

        try:
            answer = resolver.resolve(query_name, "TXT")
        except dns.resolver.NXDOMAIN as exc:
            msg = (
                f"DNS-PERSIST-01 validation failed: {query_name} does not "
                f"exist (NXDOMAIN) — the persistent record may not be published yet"
            )
            log.warning(msg)
            raise ChallengeError(msg, retryable=True) from exc
        except dns.resolver.NoAnswer as exc:
            msg = f"DNS-PERSIST-01 validation failed: {query_name} exists but has no TXT records"
            log.warning(msg)
            raise ChallengeError(msg, retryable=True) from exc
        except dns.resolver.NoNameservers as exc:
            msg = (
                f"DNS-PERSIST-01 validation failed: no nameservers available "
                f"for {query_name} (SERVFAIL or all refused)"
            )
            log.warning(msg)
            raise ChallengeError(msg, retryable=True) from exc
        except dns.exception.Timeout as exc:
            msg = (
                f"DNS-PERSIST-01 validation failed: DNS query for "
                f"{query_name} timed out after {timeout}s"
            )
            log.warning(msg)
            raise ChallengeError(msg, retryable=True) from exc
        except dns.exception.DNSException as exc:
            msg = f"DNS-PERSIST-01 validation failed: DNS error querying {query_name}: {exc}"
            log.warning(msg)
            raise ChallengeError(msg, retryable=True) from exc

        if require_dnssec and not (answer.response.flags & dns.flags.AD):
            msg = (
                f"DNS-PERSIST-01 validation failed: DNSSEC validation failed "
                f"for {query_name} — response not authenticated (AD flag not set)"
            )
            log.warning(msg)
            raise ChallengeError(msg, retryable=True)

        return answer

    # ------------------------------------------------------------------
    # Record matching
    # ------------------------------------------------------------------

    def _match(  # noqa: PLR0913
        self,
        *,
        answer: dns.resolver.Answer,
        query_name: str,
        issuers: tuple[str, ...],
        account_uri: str,
        require_wildcard: bool,
        identifier_value: str,
    ) -> None:
        """Find a record authorizing *account_uri* for the identifier.

        Raises :class:`ChallengeError` when no record qualifies, quoting the
        per-record reasons so operators can see *why* a published record was
        rejected rather than only that none matched.
        """
        allow_wildcard = getattr(self.settings, "allow_wildcard_policy", True)
        reasons: list[str] = []
        considered = 0

        for rdata in answer:
            # TXT rdata is a tuple of byte segments; join per RFC 7208 §3.3.
            raw = b"".join(rdata.strings).decode("ascii", errors="replace")

            try:
                record = parse_record(raw)
            except PersistRecordError as exc:
                # A malformed record is skipped, not fatal: an unrelated TXT
                # record at the same name must not block a valid one.
                log.debug("DNS-PERSIST-01 skipping unparseable record %r: %s", raw, exc)
                reasons.append(f"malformed record ({exc})")
                continue

            # Step 2: ignore records naming a different issuer entirely.
            if record.issuer_domain_name not in issuers:
                log.debug(
                    "DNS-PERSIST-01 ignoring record for issuer %r (not ours)",
                    record.issuer_domain_name,
                )
                continue

            considered += 1

            # Step 3: account binding, via Simple String Comparison.
            if record.accounturi != account_uri:
                reasons.append(
                    f"accounturi {record.accounturi!r} does not match "
                    f"the requesting account {account_uri!r}"
                )
                continue

            if record.is_expired():
                reasons.append(f"persistUntil={record.persist_until} has passed")
                continue

            if require_wildcard:
                if not record.allows_wildcard:
                    reasons.append(
                        "the request needs policy=wildcard but the record does not set it"
                    )
                    continue
                if not allow_wildcard:
                    reasons.append(
                        "record sets policy=wildcard but this server does not "
                        "honour the wildcard policy"
                    )
                    continue

            log.info(
                "DNS-PERSIST-01 validation succeeded for %s (query %s, issuer %s)",
                identifier_value,
                query_name,
                record.issuer_domain_name,
            )
            return

        if considered == 0:
            msg = (
                f"DNS-PERSIST-01 validation failed: no TXT record at "
                f"{query_name} names an Issuer Domain Name served by this CA "
                f"({', '.join(issuers)})"
            )
            log.warning(msg)
            raise ChallengeError(msg, retryable=True)

        msg = (
            f"DNS-PERSIST-01 validation failed: {considered} record(s) at "
            f"{query_name} named this CA but none authorized the request: "
            f"{'; '.join(reasons)}"
        )
        log.warning(msg)
        # Not retryable — the record is present and says something definite,
        # so retrying the same query would reach the same conclusion.
        raise ChallengeError(msg, retryable=False)
