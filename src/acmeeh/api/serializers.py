"""Response serialization for ACME resources (RFC 8555).

Each function takes a model entity plus :class:`AcmeUrls` and produces
a dictionary suitable for ``flask.jsonify``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.config.settings import AcmeehSettings
    from acmeeh.core.urls import AcmeUrls
    from acmeeh.models.account import Account, AccountContact
    from acmeeh.models.authorization import Authorization
    from acmeeh.models.challenge import Challenge
    from acmeeh.models.order import Order


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
) -> dict:
    """Serialize an ACME authorization resource (RFC 8555 §7.1.4)."""
    result: dict = {
        "status": authz.status.value,
        "identifier": {
            "type": authz.identifier_type.value,
            "value": authz.identifier_value,
        },
        "challenges": [serialize_challenge(c, urls) for c in challenges],
    }

    if authz.expires:
        result["expires"] = authz.expires.isoformat()
    if authz.wildcard:
        result["wildcard"] = True

    return result


def serialize_challenge(
    challenge: Challenge,
    urls: AcmeUrls,
) -> dict:
    """Serialize an ACME challenge resource (RFC 8555 §7.1.5)."""
    result: dict = {
        "type": challenge.type.value,
        "url": urls.challenge_url(challenge.id),
        "token": challenge.token,
        "status": challenge.status.value,
    }

    if challenge.validated_at:
        result["validated"] = challenge.validated_at.isoformat()
    if challenge.error:
        result["error"] = challenge.error

    return result
