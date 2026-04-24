=============
Extensibility
=============

*Writing custom challenge validators, hooks, upstream handlers, CA backends, and notification templates*

ACMEEH provides five extensibility points that require writing Python code or creating files.
All plugin classes are loaded dynamically at startup and validated before the application starts
serving requests --- a broken plugin prevents startup, it does not fail silently at runtime.

.. list-table::
   :header-rows: 1
   :widths: 25 25 25 25

   * - Extension Point
     - Base Class
     - Config Key
     - Prefix
   * - :ref:`ext-challenge-validators`
     - ``ChallengeValidator``
     - ``challenges.enabled[]``
     - ``ext:``
   * - :ref:`ext-hooks`
     - ``Hook``
     - ``hooks.registered[].class``
     - Fully qualified
   * - :ref:`ext-upstream-handlers`
     - ``UpstreamHandlerFactory``
     - ``ca.acme_proxy.challenge_handler``
     - ``ext:``
   * - :ref:`ext-ca-backends`
     - ``CABackend``
     - ``ca.backend``
     - ``ext:``
   * - :ref:`ext-notification-templates`
     - Jinja2 files
     - ``smtp.templates_path``
     - File path

.. _ext-challenge-validators:

Custom Challenge Validators
---------------------------

Challenge validators implement the server-side verification logic for ACME challenges.
The three built-in validators (``http-01``, ``dns-01``, ``tls-alpn-01``) cover the
standard RFC 8555 challenge types, but you can replace or supplement them with custom
implementations.

Use cases:

- Internal DNS validation via a private API instead of public DNS queries
- HTTP validation through a service mesh sidecar
- Custom token distribution for air-gapped environments

ChallengeValidator Interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All validators extend ``ChallengeValidator`` from ``acmeeh.challenge.base``:

.. code-block:: python

   from acmeeh.challenge.base import ChallengeValidator, ChallengeError
   from acmeeh.core.types import ChallengeType

   class MyDnsValidator(ChallengeValidator):
       # --- Required class attributes ---
       challenge_type = ChallengeType.DNS_01
       supported_identifier_types = frozenset({"dns"})

       def __init__(self, settings=None):
           super().__init__(settings=settings)
           # settings is the per-type config object (e.g., Dns01Settings)
           # or None for external validators

       # --- Required: implement validation logic ---
       def validate(
           self,
           *,
           token: str,
           jwk: dict,
           identifier_type: str,
           identifier_value: str,
       ) -> None:
           """Validate the challenge.

           Return normally on success.
           Raise ChallengeError on failure.
           """
           key_authz = self._compute_key_authorization(token, jwk)
           if not self._check_dns_record(identifier_value, key_authz):
               raise ChallengeError(
                   "TXT record not found",
                   retryable=True,  # will be retried
               )

       # --- Optional: cleanup after validation ---
       def cleanup(
           self,
           *,
           token: str,
           identifier_type: str,
           identifier_value: str,
       ) -> None:
           """Called after validation (success or failure). Default: no-op."""

Required Class Attributes
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Attribute
     - Type
     - Description
   * - ``challenge_type``
     - ``ChallengeType``
     - Must be a ``ChallengeType`` enum value (not a string). Determines which ACME challenge type this validator handles.
   * - ``supported_identifier_types``
     - ``frozenset[str]``
     - Set of identifier types this validator supports: ``"dns"``, ``"ip"``, or both.

Properties (auto-populated from settings)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Property
     - Default
     - Description
   * - ``auto_validate``
     - ``True``
     - If ``True``, validation runs synchronously when the client triggers the challenge. If ``False``, validation is deferred to the background worker (useful for DNS propagation delays).
   * - ``max_retries``
     - ``0``
     - Maximum retry attempts before marking the challenge as terminally invalid.

ChallengeError
^^^^^^^^^^^^^^

Raise ``ChallengeError`` from ``validate()`` to signal failure:

.. code-block:: python

   from acmeeh.challenge.base import ChallengeError

   # Transient failure --- will be retried if max_retries > 0
   raise ChallengeError("DNS timeout", retryable=True)

   # Permanent failure --- immediately marks challenge invalid
   raise ChallengeError("Wrong key authorization", retryable=False)

Configuration
^^^^^^^^^^^^^

Register external validators in ``challenges.enabled`` using the ``ext:`` prefix:

.. code-block:: yaml

   challenges:
     enabled:
       - "ext:mycompany.validators.InternalDnsValidator"
       - http-01
     retry_after_seconds: 5
     backoff_base_seconds: 2

The fully qualified class name must be importable from the Python path. The class is
imported, validated (must subclass ``ChallengeValidator``, must have a ``challenge_type``
attribute of type ``ChallengeType``), and instantiated with ``settings=None``.

.. note::

   **Settings for external validators**

   External validators are instantiated with ``settings=None``. If your validator
   needs configuration, read it from environment variables or a separate config file
   in ``__init__``. Built-in validators receive their per-type settings objects
   (``Http01Settings``, ``Dns01Settings``, ``TlsAlpn01Settings``) automatically.

Complete Example
^^^^^^^^^^^^^^^^

A validator that checks DNS TXT records via an internal API:

.. code-block:: python

   """Internal DNS challenge validator for ACMEEH."""

   from __future__ import annotations

   import hashlib
   import base64
   import json
   import logging
   import os
   import urllib.request

   from acmeeh.challenge.base import ChallengeValidator, ChallengeError
   from acmeeh.core.types import ChallengeType

   log = logging.getLogger(__name__)


   class InternalDnsValidator(ChallengeValidator):
       """Validate DNS-01 challenges via an internal DNS API."""

       challenge_type = ChallengeType.DNS_01
       supported_identifier_types = frozenset({"dns"})

       def __init__(self, settings=None):
           super().__init__(settings=settings)
           self._api_url = os.environ.get(
               "DNS_API_URL", "https://dns.internal/api/v1"
           )
           self._api_token = os.environ["DNS_API_TOKEN"]
           # Override defaults for deferred validation
           self._auto_validate = False
           self._max_retries = 5

       def validate(
           self,
           *,
           token: str,
           jwk: dict,
           identifier_type: str,
           identifier_value: str,
       ) -> None:
           # Compute expected value: base64url(sha256(key_authorization))
           thumbprint = self._jwk_thumbprint(jwk)
           key_authz = f"{token}.{thumbprint}"
           expected = base64.urlsafe_b64encode(
               hashlib.sha256(key_authz.encode()).digest()
           ).rstrip(b"=").decode()

           # Query internal DNS API
           domain = identifier_value.lstrip("*.")
           record_name = f"_acme-challenge.{domain}"
           try:
               txt_values = self._query_txt(record_name)
           except Exception as exc:
               raise ChallengeError(
                   f"DNS API query failed: {exc}",
                   retryable=True,
               ) from exc

           if expected not in txt_values:
               raise ChallengeError(
                   f"Expected TXT value not found in {record_name}",
                   retryable=True,
               )

           log.info("DNS-01 validated for %s via internal API", domain)

       def cleanup(
           self,
           *,
           token: str,
           identifier_type: str,
           identifier_value: str,
       ) -> None:
           domain = identifier_value.lstrip("*.")
           record_name = f"_acme-challenge.{domain}"
           try:
               self._delete_txt(record_name)
           except Exception:
               log.warning("Failed to clean up %s", record_name)

       def _jwk_thumbprint(self, jwk: dict) -> str:
           """Compute RFC 7638 JWK Thumbprint."""
           if jwk.get("kty") == "RSA":
               canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
           else:
               canonical = {
                   "crv": jwk["crv"], "kty": "EC",
                   "x": jwk["x"], "y": jwk["y"],
               }
           digest = hashlib.sha256(
               json.dumps(canonical, separators=(",", ":"),
                          sort_keys=True).encode()
           ).digest()
           return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

       def _query_txt(self, record_name: str) -> list[str]:
           req = urllib.request.Request(
               f"{self._api_url}/txt/{record_name}",
               headers={"Authorization": f"Bearer {self._api_token}"},
           )
           with urllib.request.urlopen(req, timeout=10) as resp:
               data = json.loads(resp.read())
           return data.get("values", [])

       def _delete_txt(self, record_name: str) -> None:
           req = urllib.request.Request(
               f"{self._api_url}/txt/{record_name}",
               method="DELETE",
               headers={"Authorization": f"Bearer {self._api_token}"},
           )
           urllib.request.urlopen(req, timeout=10)

Testing
^^^^^^^

.. code-block:: python

   from acmeeh.challenge.base import ChallengeValidator, ChallengeError
   from acmeeh.core.types import ChallengeType


   class FakeValidator(ChallengeValidator):
       """Minimal validator for testing."""

       challenge_type = ChallengeType.DNS_01
       supported_identifier_types = frozenset({"dns"})

       def validate(self, *, token, jwk, identifier_type, identifier_value):
           pass  # Always succeeds


   def test_registry_loads_external(monkeypatch):
       """Verify external validator is loaded and registered."""
       import importlib
       from types import SimpleNamespace
       from unittest.mock import MagicMock

       mock_module = MagicMock()
       mock_module.FakeValidator = FakeValidator
       monkeypatch.setattr(importlib, "import_module",
                           lambda m: mock_module)

       from acmeeh.challenge.registry import ChallengeRegistry

       settings = SimpleNamespace(
           enabled=["ext:mypackage.FakeValidator"],
           http01=None, dns01=None, tlsalpn01=None,
       )
       registry = ChallengeRegistry(settings)
       assert registry.is_enabled(ChallengeType.DNS_01)

.. _ext-hooks:

Custom Hooks
------------

Hooks are fire-and-forget event handlers that run asynchronously in a thread pool.
They receive a context dictionary and can perform any side effect: send notifications,
write to external systems, trigger automation, etc. Hook failures are logged but never
propagated to the ACME client.

Use cases:

- Send Slack/Teams notifications on certificate issuance
- Stream audit events to a SIEM
- Trigger deployment pipelines when certificates are renewed
- Log challenge failures to an alerting system
- Submit certificates to Certificate Transparency logs

Hook Interface
^^^^^^^^^^^^^^

All hooks extend ``Hook`` from ``acmeeh.hooks.base``. Every event method is optional ---
only override the ones you need. Unimplemented methods are no-ops.

.. code-block:: python

   from acmeeh.hooks.base import Hook


   class MyHook(Hook):
       @classmethod
       def validate_config(cls, config: dict) -> None:
           """Called at load time. Raise ValueError if config is invalid."""
           if "webhook_url" not in config:
               raise ValueError("webhook_url is required")

       def __init__(self, config: dict | None = None):
           super().__init__(config)
           self.url = self.config["webhook_url"]

       def on_certificate_issuance(self, ctx: dict) -> None:
           # ctx: certificate_id, order_id, account_id,
           #      serial_number, domains, not_after, pem_chain
           ...

       def on_certificate_revocation(self, ctx: dict) -> None:
           # ctx: certificate_id, account_id, serial_number, reason
           ...

Available Events
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Event
     - Method
     - Context Keys
   * - ``account.registration``
     - ``on_account_registration``
     - ``account_id``, ``contacts``, ``jwk_thumbprint``, ``tos_agreed``
   * - ``order.creation``
     - ``on_order_creation``
     - ``order_id``, ``account_id``, ``identifiers``, ``authz_ids``
   * - ``challenge.before_validate``
     - ``on_challenge_before_validate``
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``
   * - ``challenge.after_validate``
     - ``on_challenge_after_validate``
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``, ``result``
   * - ``challenge.on_failure``
     - ``on_challenge_failure``
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``, ``error``
   * - ``challenge.on_retry``
     - ``on_challenge_retry``
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``, ``error``, ``retry_count``
   * - ``certificate.issuance``
     - ``on_certificate_issuance``
     - ``certificate_id``, ``order_id``, ``account_id``, ``serial_number``, ``domains``, ``not_after``, ``pem_chain``
   * - ``certificate.revocation``
     - ``on_certificate_revocation``
     - ``certificate_id``, ``account_id``, ``serial_number``, ``reason``
   * - ``certificate.delivery``
     - ``on_certificate_delivery``
     - ``certificate_id``, ``account_id``, ``serial_number``
   * - ``ct.submission``
     - ``on_ct_submission``
     - ``certificate_id``, ``serial_number``, ``ct_log_url``, ``sct``

Configuration
^^^^^^^^^^^^^

Register hooks in ``hooks.registered``. Each entry specifies the fully qualified class path,
an optional event filter, optional per-hook timeout, and an arbitrary config dict passed to
the constructor:

.. code-block:: yaml

   hooks:
     timeout_seconds: 30        # Global default timeout per hook execution
     max_workers: 4             # Thread pool size
     max_retries: 1             # Retry failed hooks (exponential backoff)
     dead_letter_log: /var/log/acmeeh/hook_errors.jsonl  # Optional
     registered:
       - class: mycompany.hooks.SlackNotifier
         enabled: true
         events:                 # Subscribe to specific events (omit for all)
           - certificate.issuance
           - certificate.revocation
         timeout_seconds: 10     # Per-hook override
         config:                 # Passed to __init__ and validate_config
           webhook_url: https://hooks.slack.com/services/T00/B00/xxx

       - class: mycompany.hooks.SiemExporter
         enabled: true
         # No events list = subscribed to ALL 10 events
         config:
           endpoint: https://siem.internal/api/events

.. list-table:: Hook Entry Fields
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Default
     - Description
   * - ``class``
     - **required**
     - Fully qualified Python class path (must subclass ``Hook``)
   * - ``enabled``
     - ``true``
     - Set to ``false`` to disable without removing
   * - ``events``
     - all events
     - List of event names to subscribe to. If omitted, the hook receives all events.
   * - ``timeout_seconds``
     - global value
     - Per-hook execution timeout override
   * - ``config``
     - ``{}``
     - Arbitrary dict passed to ``validate_config()`` and ``__init__()``

Execution Model
^^^^^^^^^^^^^^^

- **Fire-and-forget**: ``dispatch()`` submits hook calls to a thread pool and returns immediately. The ACME request is never blocked by hooks.
- **Context isolation**: The context dict is deep-copied once, then shallow-copied per hook. Hooks cannot mutate each other's context.
- **Retries**: If ``max_retries > 0``, failed hooks are retried with exponential backoff (``0.5 * 2^attempt`` seconds).
- **Dead-letter log**: If ``dead_letter_log`` is set, hooks that exhaust all retries are logged to that file as JSON lines for debugging.
- **Fail-loud loading**: If a hook class cannot be imported, does not subclass ``Hook``, or fails ``validate_config()``, the application refuses to start.
- **Shutdown**: The thread pool is shut down cleanly via ``atexit``. Pending hooks are allowed to complete.

Built-in Hooks
^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Hook
     - Description
   * - ``acmeeh.hooks.ct_hook.CTSubmissionHook``
     - Submits issued certificates to Certificate Transparency logs. Configure via ``config.logs`` (list of ``{url, timeout_seconds}`` entries).
   * - ``acmeeh.hooks.audit_export_hook.AuditWebhookHook``
     - Streams audit events to an external webhook URL. Configure via ``config.webhook_url`` and ``config.timeout_seconds``.

Complete Example
^^^^^^^^^^^^^^^^

A hook that posts certificate events to Microsoft Teams:

.. code-block:: python

   """Teams notification hook for ACMEEH."""

   from __future__ import annotations

   import json
   import logging
   import urllib.request
   from typing import Any

   from acmeeh.hooks.base import Hook

   log = logging.getLogger(__name__)


   class TeamsNotifier(Hook):
       """Post certificate lifecycle events to a Teams webhook."""

       @classmethod
       def validate_config(cls, config: dict) -> None:
           if not config.get("webhook_url"):
               raise ValueError("webhook_url is required")

       def __init__(self, config: dict | None = None) -> None:
           super().__init__(config)
           self._url = self.config["webhook_url"]
           self._timeout = self.config.get("timeout_seconds", 10)

       def on_certificate_issuance(self, ctx: dict[str, Any]) -> None:
           domains = ", ".join(ctx.get("domains", []))
           serial = ctx.get("serial_number", "?")
           self._post(f"Certificate issued for {domains} (serial: {serial})")

       def on_certificate_revocation(self, ctx: dict[str, Any]) -> None:
           serial = ctx.get("serial_number", "?")
           reason = ctx.get("reason", "unspecified")
           self._post(f"Certificate revoked: {serial} (reason: {reason})")

       def on_challenge_failure(self, ctx: dict[str, Any]) -> None:
           ident = ctx.get("identifier_value", "?")
           error = ctx.get("error", "unknown")
           self._post(f"Challenge failed for {ident}: {error}")

       def _post(self, text: str) -> None:
           payload = json.dumps({"text": text}).encode()
           req = urllib.request.Request(
               self._url,
               data=payload,
               headers={"Content-Type": "application/json"},
               method="POST",
           )
           try:
               urllib.request.urlopen(req, timeout=self._timeout)
           except Exception:
               log.exception("Failed to post to Teams")

Configuration for this hook:

.. code-block:: yaml

   hooks:
     registered:
       - class: mycompany.hooks.TeamsNotifier
         events:
           - certificate.issuance
           - certificate.revocation
           - challenge.on_failure
         config:
           webhook_url: https://outlook.office.com/webhook/...
           timeout_seconds: 10

.. _ext-upstream-handlers:

Custom Upstream Challenge Handlers
----------------------------------

When using the ``acme_proxy`` CA backend, ACMEEH acts as an ACME client to an upstream CA
(e.g., Let's Encrypt). The upstream CA requires ACMEEH to prove domain control, which means
ACMEEH itself needs a *challenge handler* to create DNS records, serve HTTP tokens, etc.

This challenge handler bridges ACMEEH to your DNS provider or web server. Three built-in
handler factories are provided, and you can write your own using the ``ext:`` prefix.

.. note::

   These are **not** the same as challenge validators. Validators verify that *your clients*
   completed their challenges. Upstream handlers complete challenges that *the upstream CA*
   poses to ACMEEH.

Built-in Handler Factories
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Factory
     - Challenge
     - Description
   * - ``callback_dns``
     - DNS-01
     - Calls shell scripts to create/delete DNS TXT records
   * - ``file_http``
     - HTTP-01
     - Writes/removes token files in a webroot directory
   * - ``callback_http``
     - HTTP-01
     - Calls shell scripts to deploy/clean up HTTP tokens

callback_dns
""""""""""""

Calls external scripts to manage DNS TXT records for DNS-01 challenges:

.. code-block:: yaml

   ca:
     backend: acme_proxy
     acme_proxy:
       directory_url: https://acme-v02.api.letsencrypt.org/directory
       email: admin@example.com
       challenge_type: dns-01
       challenge_handler: callback_dns
       challenge_handler_config:
         create_script: /opt/acmeeh/dns-create.sh
         delete_script: /opt/acmeeh/dns-delete.sh
         propagation_delay: 30
         script_timeout: 60

Scripts are called as:

- Create: ``create_script <domain> <record_name> <record_value>``
- Delete: ``delete_script <domain> <record_name>``

file_http
"""""""""

Serves HTTP-01 tokens from a webroot directory:

.. code-block:: yaml

   ca:
     backend: acme_proxy
     acme_proxy:
       challenge_type: http-01
       challenge_handler: file_http
       challenge_handler_config:
         webroot: /var/www/acme-challenge

Tokens are written to ``<webroot>/.well-known/acme-challenge/<token>``.

callback_http
"""""""""""""

Calls external scripts to manage HTTP-01 tokens:

.. code-block:: yaml

   ca:
     backend: acme_proxy
     acme_proxy:
       challenge_type: http-01
       challenge_handler: callback_http
       challenge_handler_config:
         deploy_script: /opt/acmeeh/http-deploy.sh
         cleanup_script: /opt/acmeeh/http-cleanup.sh
         script_timeout: 60

Scripts are called as:

- Deploy: ``deploy_script <domain> <token> <key_authorization>``
- Cleanup: ``cleanup_script <domain> <token>``

UpstreamHandlerFactory Interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To write a custom handler factory, extend ``UpstreamHandlerFactory`` from
``acmeeh.ca.upstream_handlers``:

.. code-block:: python

   from acmeeh.ca.upstream_handlers import UpstreamHandlerFactory


   class MyHandlerFactory(UpstreamHandlerFactory):
       def create(self, config: dict) -> Any:
           """Build and return an ACMEOW ChallengeHandler.

           Parameters
           ----------
           config:
               The challenge_handler_config dict from the ACMEEH config.

           Returns
           -------
           acmeow.ChallengeHandler
               A ready-to-use handler instance.
           """
           ...

The ``create()`` method receives the ``challenge_handler_config`` dict from the YAML config
and must return an object compatible with ACMEOW's ``ChallengeHandler`` protocol.

Complete Example
^^^^^^^^^^^^^^^^

A handler factory that manages DNS records via the Cloudflare API:

.. code-block:: python

   """Cloudflare DNS handler factory for ACMEEH ACME proxy."""

   from __future__ import annotations

   import json
   import logging
   import urllib.request
   from typing import Any

   from acmeeh.ca.upstream_handlers import UpstreamHandlerFactory

   log = logging.getLogger(__name__)


   class CloudflareDnsFactory(UpstreamHandlerFactory):
       """Create an ACMEOW ChallengeHandler for Cloudflare DNS."""

       def create(self, config: dict[str, Any]) -> Any:
           api_token = config["api_token"]
           zone_id = config["zone_id"]
           propagation_delay = config.get("propagation_delay", 15)

           from acmeow.handlers import CallbackDnsHandler

           records: dict[str, str] = {}  # record_name -> record_id

           def create_record(
               domain: str,
               record_name: str,
               record_value: str,
           ) -> None:
               url = (
                   f"https://api.cloudflare.com/client/v4"
                   f"/zones/{zone_id}/dns_records"
               )
               payload = json.dumps({
                   "type": "TXT",
                   "name": record_name,
                   "content": record_value,
                   "ttl": 60,
               }).encode()
               req = urllib.request.Request(
                   url, data=payload, method="POST",
                   headers={
                       "Authorization": f"Bearer {api_token}",
                       "Content-Type": "application/json",
                   },
               )
               with urllib.request.urlopen(req, timeout=30) as resp:
                   data = json.loads(resp.read())
               records[record_name] = data["result"]["id"]
               log.info("Created TXT record %s", record_name)

           def delete_record(
               domain: str,
               record_name: str,
           ) -> None:
               record_id = records.pop(record_name, None)
               if not record_id:
                   return
               url = (
                   f"https://api.cloudflare.com/client/v4"
                   f"/zones/{zone_id}/dns_records/{record_id}"
               )
               req = urllib.request.Request(
                   url, method="DELETE",
                   headers={
                       "Authorization": f"Bearer {api_token}",
                   },
               )
               urllib.request.urlopen(req, timeout=30)
               log.info("Deleted TXT record %s", record_name)

           return CallbackDnsHandler(
               create_record=create_record,
               delete_record=delete_record,
               propagation_delay=propagation_delay,
           )

Configuration:

.. code-block:: yaml

   ca:
     backend: acme_proxy
     acme_proxy:
       directory_url: https://acme-v02.api.letsencrypt.org/directory
       email: admin@example.com
       challenge_type: dns-01
       challenge_handler: ext:mycompany.dns.CloudflareDnsFactory
       challenge_handler_config:
         api_token: ${CF_API_TOKEN}
         zone_id: abc123def456
         propagation_delay: 15

.. _ext-ca-backends:

Custom CA Backends
------------------

CA backends handle certificate signing and revocation. ACMEEH includes four built-in backends
(``internal``, ``external``, ``hsm``, ``acme_proxy``). Custom backends are loaded via the
``ext:`` prefix.

See :doc:`ca-backends` for the full ``CABackend`` interface, ``IssuedCertificate`` dataclass,
``CAError`` exception, and configuration of all built-in backends.

Quick reference:

.. code-block:: python

   from acmeeh.ca.base import CABackend, CAError, IssuedCertificate

   class MyBackend(CABackend):
       def __init__(self, ca_settings):
           # ca_settings is the CASettings object (ca section of config)
           super().__init__(ca_settings)
           ...

       def sign(self, csr, *, profile, validity_days,
                serial_number=None, ct_submitter=None):
           return IssuedCertificate(
               pem_chain="-----BEGIN CERTIFICATE-----\n...",
               not_before=datetime.utcnow(),
               not_after=datetime.utcnow() + timedelta(days=validity_days),
               serial_number="0a1b2c...",
               fingerprint="ab:cd:ef:...",
           )

       def revoke(self, *, serial_number, certificate_pem, reason=None):
           ...

       def startup_check(self):
           # Optional: verify connectivity on startup
           ...

.. code-block:: yaml

   ca:
     backend: ext:mycompany.pki.MyBackend

.. _ext-notification-templates:

Custom Notification Templates
-----------------------------

ACMEEH sends email notifications (certificate expiration warnings, issuance confirmations)
using Jinja2 templates. You can override the built-in templates by pointing
``smtp.templates_path`` to a directory containing your custom templates.

The template renderer uses a two-tier loader:

1. **Your custom directory** (checked first)
2. **Built-in package templates** (fallback)

This means you only need to provide templates you want to override. Missing templates
fall through to the built-in defaults.

Template Naming Convention
^^^^^^^^^^^^^^^^^^^^^^^^^^

Each notification type uses two template files:

- ``{notification_type}_subject.txt`` --- Email subject line (plain text, single line)
- ``{notification_type}_body.html`` --- Email body (HTML)

Available notification types:

- ``delivery_succeeded`` --- Certificate delivered to client
- ``delivery_failed`` --- Certificate delivery failed
- ``revocation_succeeded`` --- Certificate revoked successfully
- ``revocation_failed`` --- Certificate revocation failed
- ``registration_succeeded`` --- Account registration succeeded
- ``registration_failed`` --- Account registration failed
- ``admin_user_created`` --- Admin user created
- ``admin_password_reset`` --- Admin password reset
- ``expiration_warning`` --- Certificate expiration warning
- ``order_rejected`` --- Order rejected by policy
- ``order_quota_exceeded`` --- Account exceeded order quota
- ``order_stale_recovered`` --- Stale processing order recovered
- ``challenge_failed`` --- Challenge validation failed
- ``csr_validation_failed`` --- CSR validation failed against profile
- ``account_deactivated`` --- Account deactivated by holder
- ``account_revoked`` --- Account revoked by the server (e.g. bound EAB revoked)
- ``key_rollover_succeeded`` --- Account key rollover succeeded
- ``authorization_deactivated`` --- Authorization deactivated

Configuration
^^^^^^^^^^^^^

.. code-block:: yaml

   smtp:
     templates_path: /etc/acmeeh/templates

Template Variables
^^^^^^^^^^^^^^^^^^

All templates receive the common variables ``server_url`` and ``timestamp`` (ISO 8601).
Additional variables depend on the notification type. For example,
the ``expiration_warning`` templates receive:

- ``certificate_id`` --- Certificate UUID
- ``serial_number`` --- Hex-encoded serial number
- ``not_after`` --- Certificate expiration time (string)
- ``warning_days`` --- Days until expiration (integer)

The ``delivery_succeeded`` templates receive:

- ``domains`` --- List of domain names on the certificate
- ``serial_number`` --- Hex-encoded serial number
- ``not_after`` --- Certificate expiration time
- ``order_id`` --- Order UUID
- ``certificate_id`` --- Certificate UUID

Example custom subject template (``expiration_warning_subject.txt``):

.. code-block:: text

   [ACMEEH] Certificate {{ serial_number }} expires in {{ warning_days }} days

Example custom body template (``expiration_warning_body.html``):

.. code-block:: html

   <h2>Certificate Expiration Warning</h2>
   <p>Certificate <strong>{{ serial_number }}</strong> expires on {{ not_after }}.</p>
   <p>{{ warning_days }} days remaining. Please renew.</p>
   <p><small>Sent by {{ server_url }} at {{ timestamp }}</small></p>

Packaging and Distribution
--------------------------

All plugin classes must be importable from the Python path at startup. Common approaches:

**1. Local package in the same virtualenv:**

.. code-block:: bash

   # Install your package into the ACMEEH virtualenv
   .venv/bin/pip install /path/to/mycompany-acmeeh-plugins/

   # Or install in editable/development mode
   .venv/bin/pip install -e /path/to/mycompany-acmeeh-plugins/

**2. PYTHONPATH extension:**

.. code-block:: bash

   PYTHONPATH=src:/opt/mycompany/plugins python -m acmeeh -c config.yaml

**3. Single module file:**

For simple plugins, place a ``.py`` file anywhere on the Python path:

.. code-block:: bash

   # Place in src/ alongside acmeeh
   cp my_hooks.py src/

   # Reference as top-level module
   # hooks.registered[].class: my_hooks.TeamsNotifier

Troubleshooting
^^^^^^^^^^^^^^^

- **App won't start**: Check that the class path is fully qualified (``package.module.Class``, not just ``Class``) and that the module is importable. Run ``python -c "from mypackage.module import MyClass"`` to verify.
- **Hook not firing**: Verify the hook entry has ``enabled: true`` and the ``events`` list includes the event you expect. If ``events`` is omitted, the hook subscribes to all events.
- **Challenge validator ignored**: Ensure the ``ext:`` entry is in the ``challenges.enabled`` list and the class has ``challenge_type`` set as a ``ChallengeType`` enum value (not a string).
- **Upstream handler error**: The factory's ``create()`` must return an ACMEOW-compatible ``ChallengeHandler``. Ensure ACMEOW is installed (``pip install acmeow``).
