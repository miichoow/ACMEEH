"""Challenge service — orchestrates ACME challenge validation.

Coordinates between the challenge repository, authorization
repository, order repository, and challenge validators to process
challenge responses and cascade state changes.

Production features:
- Retry logic with configurable max_retries per challenge type
- auto_validate (synchronous) vs deferred (background worker) modes
- Expiration handling for challenges whose authorizations have expired
- Full lifecycle hook dispatch (before_validate, after_validate,
  on_failure, on_retry)
- No raw Database calls — all DB access through repositories
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from acmeeh.app.errors import MALFORMED, UNAUTHORIZED, AcmeProblem
from acmeeh.challenge.base import ChallengeError
from acmeeh.core.state import log_transition
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    NotificationType,
    OrderStatus,
)
from acmeeh.logging import security_events

if TYPE_CHECKING:
    from acmeeh.challenge.registry import ChallengeRegistry
    from acmeeh.hooks.registry import HookRegistry
    from acmeeh.models.authorization import Authorization
    from acmeeh.models.challenge import Challenge
    from acmeeh.repositories.authorization import AuthorizationRepository
    from acmeeh.repositories.challenge import ChallengeRepository
    from acmeeh.repositories.order import OrderRepository

log = logging.getLogger(__name__)


class ChallengeService:
    """Orchestrates ACME challenge validation and state cascading."""

    def __init__(
        self,
        challenge_repo: ChallengeRepository,
        authz_repo: AuthorizationRepository,
        order_repo: OrderRepository,
        registry: ChallengeRegistry,
        hook_registry: HookRegistry | None = None,
        metrics=None,
        rate_limiter=None,
        challenge_settings=None,
        notifier=None,
    ) -> None:
        self._challenges = challenge_repo
        self._authz = authz_repo
        self._orders = order_repo
        self._registry = registry
        self._hooks = hook_registry
        self._metrics = metrics
        self._rate_limiter = rate_limiter
        self._challenge_settings = challenge_settings
        self._notifier = notifier

    def initiate_validation(
        self,
        challenge_id: UUID,
        account_id: UUID,
        jwk: dict,
    ) -> Challenge:
        """Initiate validation for a challenge.

        1. Verify ownership (challenge -> authz -> account)
        2. If already terminal, return as-is
        3. Check auto_validate:
           - True: claim → validate synchronously → complete/retry → cascade
           - False: claim for processing only (status → processing),
             return immediately for background worker
        4. Dispatch lifecycle hooks around validation

        Parameters
        ----------
        challenge_id:
            The challenge to validate.
        account_id:
            The requesting account's ID.
        jwk:
            The account's JWK dictionary.

        Returns
        -------
        Challenge
            The updated challenge.

        """
        challenge, authz = self._lookup_and_verify(challenge_id, account_id)

        # If already terminal, return as-is
        if challenge.status in (ChallengeStatus.VALID, ChallengeStatus.INVALID):
            return challenge

        # Per-account rate limit on validation attempts
        if self._rate_limiter is not None:
            self._rate_limiter.check(
                str(account_id),
                "challenge_validation",
            )

        # Claim for processing
        worker_id = uuid4().hex
        claimed = self._challenges.claim_for_processing(challenge_id, worker_id)
        if claimed is None:
            # Already being processed or no longer pending
            updated = self._challenges.find_by_id(challenge_id)
            return updated if updated is not None else challenge

        # Get validator
        validator = self._registry.get_validator_or_none(challenge.type)
        if validator is None:
            error_detail = {
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": f"No validator for challenge type '{challenge.type.value}'",
            }
            result = self._challenges.complete_validation(
                challenge_id,
                worker_id,
                success=False,
                error=error_detail,
            )
            self._cascade_authz_invalid(challenge.authorization_id)
            return result or challenge

        # Check auto_validate — if False, leave in processing state
        # for background worker to pick up later
        if not validator.auto_validate:
            return claimed

        # Synchronous validation
        return self._run_validation(
            challenge,
            claimed,
            worker_id,
            validator,
            jwk,
            authz.identifier_type.value,
            authz.identifier_value,
        )

    def process_pending(
        self,
        challenge_id: UUID,
        worker_id: str,
        jwk: dict,
    ) -> Challenge:
        """Process a deferred challenge (auto_validate=False).

        Called by background workers to pick up challenges left in
        ``processing`` state by :meth:`initiate_validation`.

        Parameters
        ----------
        challenge_id:
            The challenge to process.
        worker_id:
            The background worker's identifier.
        jwk:
            The account's JWK dictionary.

        Returns
        -------
        Challenge
            The updated challenge.

        """
        challenge = self._challenges.find_by_id(challenge_id)
        if challenge is None:
            raise AcmeProblem(MALFORMED, "Challenge not found", status=404)

        authz = self._authz.find_by_id(challenge.authorization_id)
        if authz is None:
            raise AcmeProblem(
                MALFORMED,
                "Associated authorization not found",
                status=404,
            )

        # If already terminal, return as-is
        if challenge.status in (ChallengeStatus.VALID, ChallengeStatus.INVALID):
            return challenge

        validator = self._registry.get_validator_or_none(challenge.type)
        if validator is None:
            error_detail = {
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": f"No validator for challenge type '{challenge.type.value}'",
            }
            result = self._challenges.complete_validation(
                challenge_id,
                worker_id,
                success=False,
                error=error_detail,
            )
            self._cascade_authz_invalid(challenge.authorization_id)
            return result or challenge

        return self._run_validation(
            challenge,
            challenge,
            worker_id,
            validator,
            jwk,
            authz.identifier_type.value,
            authz.identifier_value,
        )

    def expire_challenges(self) -> int:
        """Expire pending challenges whose authorization has expired.

        Finds pending authorizations that are past expiry, transitions
        their challenges to invalid, and cascades authz/orders to
        invalid.

        Returns
        -------
        int
            Number of challenges expired.

        """
        expired_authzs = self._authz.find_expired_pending()
        count = 0

        for authz in expired_authzs:
            challenges = self._challenges.find_by_authorization(authz.id)
            for challenge in challenges:
                if challenge.status in (
                    ChallengeStatus.PENDING,
                    ChallengeStatus.PROCESSING,
                ):
                    # Claim and immediately invalidate
                    worker_id = f"expiry-{uuid4().hex[:8]}"
                    claimed = self._challenges.claim_for_processing(
                        challenge.id,
                        worker_id,
                    )
                    if claimed is not None:
                        error_detail = {
                            "type": "urn:ietf:params:acme:error:unauthorized",
                            "detail": "Authorization expired before challenge validation completed",
                        }
                        self._challenges.complete_validation(
                            challenge.id,
                            worker_id,
                            success=False,
                            error=error_detail,
                        )
                        count += 1
                        if self._metrics:
                            self._metrics.increment("acmeeh_challenges_expired_total")

            # Cascade authz → invalid
            self._authz.transition_status(
                authz.id,
                AuthorizationStatus.PENDING,
                AuthorizationStatus.EXPIRED,
            )

            # Cascade orders → invalid
            self._invalidate_orders_for_authz(authz.id)

        return count

    # ------------------------------------------------------------------
    # Internal validation logic
    # ------------------------------------------------------------------

    def _lookup_and_verify(
        self,
        challenge_id: UUID,
        account_id: UUID,
    ) -> tuple[Challenge, Authorization]:
        """Look up challenge and verify ownership.

        Returns (challenge, authorization).
        """
        challenge = self._challenges.find_by_id(challenge_id)
        if challenge is None:
            raise AcmeProblem(MALFORMED, "Challenge not found", status=404)

        authz = self._authz.find_by_id(challenge.authorization_id)
        if authz is None:
            raise AcmeProblem(
                MALFORMED,
                "Associated authorization not found",
                status=404,
            )
        if authz.account_id != account_id:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Challenge does not belong to this account",
                status=403,
            )

        return challenge, authz

    def _run_validation(
        self,
        challenge: Challenge,
        claimed: Challenge,
        worker_id: str,
        validator,
        jwk: dict,
        identifier_type: str,
        identifier_value: str,
    ) -> Challenge:
        """Execute validation with retry/hook logic.

        Parameters
        ----------
        challenge:
            The original challenge entity.
        claimed:
            The claimed (processing) challenge entity.
        worker_id:
            The worker lock identifier.
        validator:
            The challenge validator instance.
        jwk:
            The account's JWK dictionary.
        identifier_type:
            The identifier type string (e.g. ``"dns"``).
        identifier_value:
            The identifier value (e.g. ``"example.com"``).

        Returns
        -------
        Challenge
            The updated challenge after validation.

        """
        ctx = {
            "challenge_type": challenge.type.value,
            "token": challenge.token,
            "identifier_type": identifier_type,
            "identifier_value": identifier_value,
        }

        # Dispatch before_validate hook
        if self._hooks:
            self._hooks.dispatch("challenge.before_validate", ctx)

        try:
            validator.validate(
                token=challenge.token,
                jwk=jwk,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
            )

            # Success
            result = self._challenges.complete_validation(
                challenge.id,
                worker_id,
                success=True,
            )
            if self._metrics:
                self._metrics.increment(
                    "acmeeh_challenges_validated_total",
                    labels={"result": "success"},
                )
            if self._hooks:
                self._hooks.dispatch(
                    "challenge.after_validate",
                    {
                        **ctx,
                        "result": "success",
                    },
                )
            self._cascade_authz_valid(challenge.authorization_id)
            return result or challenge

        except ChallengeError as exc:
            return self._handle_challenge_error(
                exc,
                challenge,
                worker_id,
                validator,
                ctx,
            )

        except Exception as exc:
            # Unexpected error — treat as non-retryable failure
            log.exception(
                "Unexpected error during challenge validation for %s",
                challenge.id,
            )
            error_detail = {
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": str(exc),
            }
            result = self._challenges.complete_validation(
                challenge.id,
                worker_id,
                success=False,
                error=error_detail,
            )
            if self._hooks:
                self._hooks.dispatch(
                    "challenge.on_failure",
                    {
                        **ctx,
                        "error": str(exc),
                    },
                )
            self._cascade_authz_invalid(challenge.authorization_id)
            if self._notifier:
                try:
                    authz = self._authz.find_by_id(challenge.authorization_id)
                    self._notifier.notify(
                        NotificationType.CHALLENGE_FAILED,
                        authz.account_id if authz else None,
                        {
                            "identifier": identifier_value,
                            "challenge_type": challenge.type.value,
                            "error_detail": str(exc),
                        },
                    )
                except Exception:  # noqa: BLE001
                    log.exception("Failed to send CHALLENGE_FAILED notification")
            return result or challenge

        finally:
            try:
                validator.cleanup(
                    token=challenge.token,
                    identifier_type=identifier_type,
                    identifier_value=identifier_value,
                )
            except Exception:
                log.exception(
                    "Challenge cleanup failed for %s",
                    challenge.id,
                )

    def _handle_challenge_error(
        self,
        exc: ChallengeError,
        challenge: Challenge,
        worker_id: str,
        validator,
        ctx: dict,
    ) -> Challenge:
        """Handle a ChallengeError with retry logic.

        If the error is retryable and retry_count < max_retries,
        the challenge goes back to pending.  Otherwise it's marked
        invalid.
        """
        if exc.retryable and challenge.retry_count < validator.max_retries:
            # Exponential backoff: base * 2^retry_count, capped at max
            _base = getattr(self._challenge_settings, "backoff_base_seconds", 5)
            _cap = getattr(self._challenge_settings, "backoff_max_seconds", 300)
            backoff = min(
                _base * (2**challenge.retry_count),
                _cap,
            )
            result = self._challenges.retry_challenge(
                challenge.id,
                worker_id,
                backoff_seconds=backoff,
            )
            if self._metrics:
                self._metrics.increment(
                    "acmeeh_challenges_validated_total",
                    labels={"result": "retry"},
                )
            if self._hooks:
                self._hooks.dispatch(
                    "challenge.on_retry",
                    {
                        **ctx,
                        "error": exc.detail,
                        "retry_count": challenge.retry_count + 1,
                        "backoff_seconds": backoff,
                    },
                )
            log.info(
                "Challenge %s retrying (attempt %d/%d, backoff %ds): %s",
                challenge.id,
                challenge.retry_count + 1,
                validator.max_retries,
                backoff,
                exc.detail,
            )
            return result or challenge

        # Terminal failure
        error_detail = {
            "type": "urn:ietf:params:acme:error:incorrectResponse",
            "detail": exc.detail,
        }
        result = self._challenges.complete_validation(
            challenge.id,
            worker_id,
            success=False,
            error=error_detail,
        )
        security_events.challenge_validation_failed(
            challenge.id,
            ctx.get("identifier_value", ""),
            ctx.get("challenge_type", ""),
            exc.detail,
        )
        if self._metrics:
            self._metrics.increment(
                "acmeeh_challenges_validated_total",
                labels={"result": "failure"},
            )
        if self._hooks:
            self._hooks.dispatch(
                "challenge.on_failure",
                {
                    **ctx,
                    "error": exc.detail,
                },
            )
        self._cascade_authz_invalid(challenge.authorization_id)
        if self._notifier:
            try:
                authz = self._authz.find_by_id(challenge.authorization_id)
                self._notifier.notify(
                    NotificationType.CHALLENGE_FAILED,
                    authz.account_id if authz else None,
                    {
                        "identifier": ctx.get("identifier_value", ""),
                        "challenge_type": ctx.get("challenge_type", ""),
                        "error_detail": exc.detail,
                    },
                )
            except Exception:  # noqa: BLE001
                log.exception("Failed to send CHALLENGE_FAILED notification")
        return result or challenge

    # ------------------------------------------------------------------
    # State cascading
    # ------------------------------------------------------------------

    def _cascade_authz_valid(self, authz_id: UUID) -> None:
        """Cascade authorization to valid and check linked orders.

        Transitions authz pending -> valid, then checks all orders
        linked to this authz.  If all authzs for an order are valid,
        transitions the order pending -> ready.
        """
        result = self._authz.transition_status(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.VALID,
        )
        if result is not None:
            log_transition(
                "authorization", authz_id, AuthorizationStatus.PENDING, AuthorizationStatus.VALID
            )
        self._check_orders_for_authz(authz_id)

    def _cascade_authz_invalid(self, authz_id: UUID) -> None:
        """Cascade authorization to invalid and invalidate linked orders.

        Transitions authz pending -> invalid, then transitions all
        linked pending orders to invalid with subproblem details.
        """
        authz = self._authz.find_by_id(authz_id)
        result = self._authz.transition_status(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.INVALID,
        )
        if result is not None:
            log_transition(
                "authorization",
                authz_id,
                AuthorizationStatus.PENDING,
                AuthorizationStatus.INVALID,
                reason="challenge validation failed",
            )
        self._invalidate_orders_for_authz(authz_id, authz=authz)

    def _check_orders_for_authz(self, authz_id: UUID) -> None:
        """Check if any orders are now ready after authz validation."""
        orders = self._orders.find_orders_by_authorization(authz_id)

        for order in orders:
            if order.status != OrderStatus.PENDING:
                continue

            # Check if all authzs for this order are valid
            authzs = self._authz.find_by_order(order.id)
            if all(a.status == AuthorizationStatus.VALID for a in authzs):
                result = self._orders.transition_status(
                    order.id,
                    OrderStatus.PENDING,
                    OrderStatus.READY,
                )
                if result is not None:
                    log_transition(
                        "order",
                        order.id,
                        OrderStatus.PENDING,
                        OrderStatus.READY,
                        reason="all authorizations valid",
                    )
                log.info("Order %s is now ready", order.id)

    def _invalidate_orders_for_authz(self, authz_id: UUID, authz=None) -> None:
        """Invalidate all pending orders linked to a failed authorization."""
        orders = self._orders.find_orders_by_authorization(authz_id)

        # Build subproblem from the failed authorization
        subproblems = None
        if authz is not None:
            subproblems = [
                {
                    "type": "urn:ietf:params:acme:error:unauthorized",
                    "detail": "Challenge validation failed for identifier",
                    "identifier": {
                        "type": authz.identifier_type.value,
                        "value": authz.identifier_value,
                    },
                }
            ]

        error: dict[str, object] = {
            "type": "urn:ietf:params:acme:error:unauthorized",
            "detail": "Authorization failed for one or more identifiers",
        }
        if subproblems:
            error["subproblems"] = subproblems

        for order in orders:
            if order.status != OrderStatus.PENDING:
                continue

            result = self._orders.transition_status(
                order.id,
                OrderStatus.PENDING,
                OrderStatus.INVALID,
                error=error,
            )
            if result is not None:
                log_transition(
                    "order",
                    order.id,
                    OrderStatus.PENDING,
                    OrderStatus.INVALID,
                    reason=f"authorization {authz_id} failed",
                )
                log.info(
                    "Order %s invalidated due to authz %s failure",
                    order.id,
                    authz_id,
                )
