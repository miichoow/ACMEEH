"""Response serialization for ACME resources (RFC 8555).

Each function takes a model entity plus :class:`AcmeUrls` and produces
a dictionary suitable for ``flask.jsonify``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from acmeeh.core.types import ChallengeType

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from acmeeh.config.settings import AcmeehSettings
    from acmeeh.core.urls import AcmeUrls
    from acmeeh.models.account import Account, AccountContact
    from acmeeh.models.authorization import Authorization
    from acmeeh.models.challenge import Challenge
    from acmeeh.models.order import Order

MAX_ISSUER_DOMAIN_NAMES = 10
"""Upper bound on ``issuer-domain-names`` (draft-ietf-acme-dns-persist §4.3.1)."""


def serialize_directory(
    urls: AcmeUrls,
    settings: AcmeehSettings,
) -> dict:
    """Serialize the ACME directory resource (RFC 8555 §7.1.1)."""
    result: dict[str, Any] = {
        "newNonce": urls.new_nonce,
        "newAccount": urls.new_account,
        "newOrder": urls.new_order,
        "newAuthz": urls.new_authz,
        "revokeCert": urls.revoke_cert,
        "keyChange": urls.key_change,
    }

    # ARI (if enabled)
    if urls.renewal_info:
        result["renewalInfo"] = urls.renewal_info

    # Meta object
    meta: dict = {}
    if settings.tos.url:
        meta["termsOfService"] = settings.tos.url
    if settings.acme.website_url:
        meta["website"] = settings.acme.website_url
    if settings.acme.caa_identities:
        meta["caaIdentities"] = list(settings.acme.caa_identities)
    if settings.acme.eab_required:
        meta["externalAccountRequired"] = True

    # Pre-authorization lifetime (non-standard but useful for clients)
    if settings.order.pre_authorization_lifetime_days > 0:
        meta["authorizationLifetimeDays"] = settings.order.pre_authorization_lifetime_days

    # Profiles extension (RFC 9727 §4: object mapping name → description URL)
    if settings.ca.profiles:
        profile_names = sorted(settings.ca.profiles.keys())
        if profile_names and profile_names != ["default"]:
            meta["profiles"] = dict.fromkeys(profile_names, "")

    if meta:
        result["meta"] = meta

    return result


def serialize_account(
    account: Account,
    contacts: list[AccountContact],
    urls: AcmeUrls,
) -> dict:
    """Serialize an ACME account resource (RFC 8555 §7.1.2)."""
    result: dict = {
        "status": account.status.value,
        "orders": urls.orders_url(account.id),
    }

    if contacts:
        result["contact"] = [c.contact_uri for c in contacts]

    if account.tos_agreed:
        result["termsOfServiceAgreed"] = True

    return result


def serialize_order(
    order: Order,
    authz_ids: list[UUID],
    urls: AcmeUrls,
) -> dict:
    """Serialize an ACME order resource (RFC 8555 §7.1.3)."""
    result: dict = {
        "status": order.status.value,
        "identifiers": [{"type": i.type.value, "value": i.value} for i in order.identifiers],
        "authorizations": [urls.authorization_url(aid) for aid in authz_ids],
        "finalize": urls.finalize_url(order.id),
    }

    if order.expires:
        result["expires"] = order.expires.isoformat()
    if order.not_before:
        result["notBefore"] = order.not_before.isoformat()
    if order.not_after:
        result["notAfter"] = order.not_after.isoformat()
    if order.certificate_id:
        result["certificate"] = urls.certificate_url(order.certificate_id)
    if order.error:
        result["error"] = order.error

    return result


def serialize_authorization(
    authz: Authorization,
    challenges: list[Challenge],
    urls: AcmeUrls,
    issuer_domain_names: Sequence[str] = (),
) -> dict:
    """Serialize an ACME authorization resource (RFC 8555 §7.1.4).

    ``issuer_domain_names`` is forwarded to DNS-PERSIST-01 challenges; see
    :func:`serialize_challenge`.
    """
    account_uri = urls.account_url(authz.account_id)
    result: dict = {
        "status": authz.status.value,
        "identifier": {
            "type": authz.identifier_type.value,
            "value": authz.identifier_value,
        },
        "challenges": [
            serialize_challenge(
                c,
                urls,
                account_uri=account_uri,
                issuer_domain_names=issuer_domain_names,
            )
            for c in challenges
        ],
    }

    if authz.expires:
        result["expires"] = authz.expires.isoformat()
    if authz.wildcard:
        result["wildcard"] = True

    return result


def serialize_challenge(
    challenge: Challenge,
    urls: AcmeUrls,
    account_uri: str | None = None,
    issuer_domain_names: Sequence[str] = (),
) -> dict:
    """Serialize an ACME challenge resource (RFC 8555 §7.1.5).

    DNS-PERSIST-01 (draft-ietf-acme-dns-persist §4.3.1) has no token and no
    key authorization; its object instead carries ``accounturi`` and
    ``issuer-domain-names``, which together tell the client exactly what to
    publish.  ``token`` is omitted for that type so clients cannot mistake
    it for a DNS-01-style challenge.
    """
    result: dict = {
        "type": challenge.type.value,
        "url": urls.challenge_url(challenge.id),
        "status": challenge.status.value,
    }

    if challenge.type is ChallengeType.DNS_PERSIST_01:
        if account_uri is not None:
            result["accounturi"] = account_uri
        # The draft caps the list at 10 and requires normalized names;
        # normalization happens once at config load.
        result["issuer-domain-names"] = list(issuer_domain_names)[:MAX_ISSUER_DOMAIN_NAMES]
    else:
        result["token"] = challenge.token

    if challenge.validated_at:
        result["validated"] = challenge.validated_at.isoformat()
    if challenge.error:
        result["error"] = challenge.error

    return result
