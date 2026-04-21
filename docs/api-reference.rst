==================
ACME API Reference
==================

*RFC 8555 endpoints, JWS authentication, and error handling*

ACMEEH implements the full `RFC 8555 <https://www.rfc-editor.org/rfc/rfc8555>`_ protocol.
All requests (except directory and nonce) must be authenticated using JWS (JSON Web Signature) as
described in `RFC 7515 <https://www.rfc-editor.org/rfc/rfc7515>`_.

Authentication
--------------

Every ACME request (except GET /directory and HEAD /new-nonce) is a POST with a JWS body:

.. code-block:: json

   {
     "protected": "<base64url-encoded header>",
     "payload": "<base64url-encoded payload>",
     "signature": "<base64url-encoded signature>"
   }

The protected header must include:

- ``alg`` --- Signing algorithm (ES256, RS256, etc.)
- ``nonce`` --- Fresh nonce from the server
- ``url`` --- The request URL
- ``jwk`` --- Account public key (for new-account only)
- ``kid`` --- Account URL (for all other requests)

.. note::

   **Supported Algorithms**

   Configurable via ``security.allowed_algorithms``. Default: ``ES256``, ``RS256``.

POST-as-GET
------------

RFC 8555 requires that all resource fetches use POST requests with an empty (null) payload instead of
standard GET requests. This is called the **POST-as-GET** pattern and exists to ensure
replay protection via the ``Replay-Nonce`` mechanism on every request.

In a POST-as-GET request, the JWS payload is the empty string ``""`` (which base64url-encodes
to ``""``), not an empty JSON object. The protected header still includes the ``nonce``,
``url``, and ``kid`` fields as with any authenticated request.

POST-as-GET applies to the following operations:

- Fetching order status --- ``POST /order/{order_id}``
- Fetching authorization status --- ``POST /authz/{authz_id}``
- Fetching challenge status --- ``POST /chall/{challenge_id}`` (when polling, not triggering)
- Downloading certificates --- ``POST /cert/{certificate_id}``
- Listing account orders --- ``POST /acct/{account_id}/orders``

.. warning::

   **Empty Payload vs. Empty Object**

   POST-as-GET uses a **null/empty payload** (``""``), not ``{}``.
   Sending ``{}`` as the payload is used to trigger challenge validation, not for fetching resources.
   The server will reject a POST-as-GET request that contains a non-empty payload.

Directory
---------

**GET** ``/directory``

Returns the ACME directory object with all endpoint URLs. This is the entry point for ACME clients.

**Response:**

.. code-block:: json

   {
     "newNonce": "https://acme.example.com/new-nonce",
     "newAccount": "https://acme.example.com/new-account",
     "newOrder": "https://acme.example.com/new-order",
     "newAuthz": "https://acme.example.com/new-authz",
     "revokeCert": "https://acme.example.com/revoke-cert",
     "keyChange": "https://acme.example.com/key-change",
     "meta": {
       "termsOfService": "https://example.com/tos",
       "website": "https://example.com",
       "caaIdentities": ["acme.example.com"],
       "externalAccountRequired": false
     }
   }

Nonce
-----

**HEAD** ``/new-nonce``

Get a fresh nonce via the ``Replay-Nonce`` response header. Returns no body.

**GET** ``/new-nonce``

Same as HEAD but returns a 204 response. Both methods provide a fresh nonce in the ``Replay-Nonce`` header.

Account
-------

**POST** ``/new-account``

Create or look up an ACME account. Uses ``jwk`` in the JWS protected header.

**Payload:**

.. code-block:: json

   {
     "termsOfServiceAgreed": true,
     "contact": ["mailto:admin@example.com"],
     "onlyReturnExisting": false,
     "externalAccountBinding": { ... }
   }

**Response:** 201 Created (new account) or 200 OK (existing). The ``Location`` header contains the account URL.

**POST** ``/acct/{account_id}``

Update an existing account (change contact, deactivate). Uses ``kid`` authentication.

**Payload:**

.. code-block:: json

   {
     "contact": ["mailto:new@example.com"],
     "status": "deactivated"
   }

**POST** ``/acct/{account_id}/orders``

List orders for an account (POST-as-GET). Returns a paginated list of order URLs.

**Query Parameters:**

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Parameter
     - Type
     - Description
   * - ``cursor``
     - UUID
     - Cursor for pagination. Pass the cursor value from the previous response to fetch the next page of results.

**Response:** ``200 OK``

.. code-block:: json

   {
     "orders": [
       "https://acme.example.com/order/abc123",
       "https://acme.example.com/order/def456"
     ]
   }

When more results are available, the response includes a ``Link`` header with the URL for the next page:

.. code-block:: bash

   Link: <https://acme.example.com/acct/1234/orders?cursor=next-uuid>;rel="next"

Order
-----

**POST** ``/new-order``

Create a new certificate order.

**Payload:**

.. code-block:: json

   {
     "identifiers": [
       {"type": "dns", "value": "example.com"},
       {"type": "dns", "value": "*.example.com"}
     ],
     "notBefore": "2025-01-01T00:00:00Z",
     "notAfter": "2025-04-01T00:00:00Z",
     "replaces": "certID"
   }

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Required
     - Description
   * - ``identifiers``
     - **required**
     - Array of identifier objects with ``type`` (``dns`` or ``ip``) and ``value``.
   * - ``notBefore``
     - *optional*
     - Requested start of certificate validity (RFC 3339 timestamp).
   * - ``notAfter``
     - *optional*
     - Requested end of certificate validity (RFC 3339 timestamp).
   * - ``replaces``
     - *optional*
     - Certificate ID of an existing certificate to replace. Used for ARI-based renewal per `draft-ietf-acme-ari <https://datatracker.ietf.org/doc/draft-ietf-acme-ari/>`_. The server uses this to determine if the order qualifies for expedited renewal.

**Response:** 201 Created with order object containing status, authorization URLs, and finalize URL.

.. warning::

   **Maintenance Mode**

   When the server is in maintenance mode, this endpoint returns ``503 Service Unavailable``
   with a ``Retry-After: 60`` header. Clients should wait the indicated number of seconds
   before retrying the request.

**POST** ``/order/{order_id}``

Get the current state of an order (POST-as-GET).

**Response:**

.. code-block:: json

   {
     "status": "ready",
     "expires": "2025-01-08T00:00:00Z",
     "identifiers": [...],
     "authorizations": ["https://acme.example.com/authz/..."],
     "finalize": "https://acme.example.com/order/.../finalize"
   }

.. note::

   **Retry-After Header**

   When the order status is ``processing``, the response includes a ``Retry-After``
   header indicating how many seconds the client should wait before polling again. This occurs after
   the CSR has been submitted via the finalize endpoint and the CA backend is signing the certificate.

**POST** ``/order/{order_id}/finalize``

Submit a CSR to finalize the order. Only valid when order status is ``ready``.

**Payload:**

.. code-block:: json

   {
     "csr": "<base64url-encoded DER CSR>"
   }

Authorization
-------------

**POST** ``/authz/{authz_id}``

Get authorization details (POST-as-GET) or deactivate an authorization.
Shows identifier, status, and available challenges.

Fetch Authorization (POST-as-GET)
"""""""""""""""""""""""""""""""""

Send an empty payload to retrieve the current authorization state.

**Response:**

.. code-block:: json

   {
     "status": "pending",
     "identifier": {"type": "dns", "value": "example.com"},
     "challenges": [
       {
         "type": "http-01",
         "status": "pending",
         "url": "https://acme.example.com/chall/...",
         "token": "..."
       },
       {
         "type": "dns-01",
         "status": "pending",
         "url": "https://acme.example.com/chall/...",
         "token": "..."
       }
     ],
     "expires": "2025-02-01T00:00:00Z"
   }

Deactivate Authorization
"""""""""""""""""""""""""

Send a payload with ``"status": "deactivated"`` to deactivate the authorization. Once deactivated, the authorization cannot be used to fulfill an order.

**Payload:**

.. code-block:: json

   {
     "status": "deactivated"
   }

.. note::

   **Retry-After Header**

   When the authorization status is ``pending``, the response includes a
   ``Retry-After`` header indicating how many seconds the client should wait
   before polling again.

Pre-Authorization
-----------------

**POST** ``/new-authz``

Request pre-authorization for an identifier before creating an order.

**Payload:**

.. code-block:: json

   {
     "identifier": {"type": "dns", "value": "example.com"}
   }

**Response:** ``201 Created``

Returns the authorization object with its challenges, plus a ``Location`` header pointing to the new authorization URL.

Challenge
---------

**POST** ``/chall/{challenge_id}``

Respond to a challenge to begin validation. Send an empty JSON object ``{}`` to trigger validation.

**Payload:** ``{}``

**Response:**

.. code-block:: json

   {
     "type": "http-01",
     "status": "processing",
     "url": "https://acme.example.com/chall/...",
     "token": "...",
     "validated": null
   }

**Response Headers:**

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Header
     - Description
   * - ``Link: <authz_url>;rel="up"``
     - Points to the parent authorization resource for this challenge.
   * - ``Retry-After``
     - Present when challenge status is ``processing``. Indicates the number of seconds to wait before polling again.

Challenge Types
^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 15 30 55

   * - Type
     - Validation Method
     - Token Placement
   * - ``http-01``
     - HTTP request to port 80
     - File at ``http://{domain}/.well-known/acme-challenge/{token}``
   * - ``dns-01``
     - DNS TXT record query
     - TXT record at ``_acme-challenge.{domain}``
   * - ``tls-alpn-01``
     - TLS connection to port 443
     - Self-signed cert with acmeIdentifier extension, ALPN protocol ``acme-tls/1``

Certificate
-----------

**POST** ``/cert/{certificate_id}``

Download an issued certificate (POST-as-GET). Returns the full certificate chain in PEM format.

**Response:** ``application/pem-certificate-chain``

**POST** ``/revoke-cert``

Revoke a certificate. Can be authenticated by the account key or the certificate's private key.

**Payload:**

.. code-block:: json

   {
     "certificate": "<base64url-encoded DER certificate>",
     "reason": 0
   }

Reason codes follow `RFC 5280 Section 5.3.1 <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>`_.

Key Change
----------

**POST** ``/key-change``

Roll over an account key. The outer JWS is signed by the old key; the inner JWS is signed by the new key.

**Inner Payload:**

.. code-block:: json

   {
     "account": "https://acme.example.com/acct/...",
     "oldKey": { <JWK of old key> }
   }

Optional Endpoints
------------------

CRL (Certificate Revocation List)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**GET** ``/crl``

Download the current CRL in DER format. Requires ``crl.enabled: true``.

**Response:** ``application/pkix-crl``

ARI (ACME Renewal Information)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**GET** ``/renewalInfo/{cert_id}``

Get renewal information for a certificate. Requires ``ari.enabled: true``. Implements draft-ietf-acme-ari.

**Response:**

.. code-block:: json

   {
     "suggestedWindow": {
       "start": "2025-03-01T00:00:00Z",
       "end": "2025-03-15T00:00:00Z"
     },
     "retryAfter": 3600
   }

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Field
     - Description
   * - ``suggestedWindow.start``
     - ISO 8601 start of the suggested renewal window
   * - ``suggestedWindow.end``
     - ISO 8601 end of the window (equals certificate ``notAfter``)
   * - ``retryAfter``
     - Seconds until the renewal window starts (minimum 3600). Clients should retry after this interval.

If the certificate is revoked, the suggested window starts immediately (``start`` is set to the current time).

Metrics
^^^^^^^

**GET** ``/metrics``

Prometheus-compatible metrics endpoint. Requires ``metrics.enabled: true``.

**Response Content-Type:** ``text/plain; version=0.0.4; charset=utf-8``

.. note::

   **Authentication**

   When ``metrics.auth_required: true`` is configured, this endpoint requires an
   ``Authorization: Bearer <token>`` header. The token must be a valid admin API token.
   Requests without a valid token will receive a ``401 Unauthorized`` response.

Infrastructure Endpoints
------------------------

Health and readiness endpoints for monitoring and orchestration. These endpoints do not require JWS authentication.

**GET** ``/livez``

Minimal liveness probe. Returns immediately to indicate the application process is running and able to handle HTTP requests.

**Response:** ``200 OK``

.. code-block:: json

   {
     "alive": true,
     "version": "1.0.0"
   }

**GET** ``/healthz``

Comprehensive health check that inspects all subsystems. Returns ``200 OK`` when all checks pass, or ``503 Service Unavailable`` when any critical check fails.

**Response (healthy):** ``200 OK``

.. code-block:: json

   {
     "status": "ok",
     "checks": {
       "database": {
         "status": "ok",
         "pool": {"size": 10, "available": 8, "waiting": 0}
       },
       "ca_backend": {"status": "ok"},
       "crl": {"status": "ok", "stale": false},
       "workers": {
         "challenge": true,
         "cleanup": true,
         "expiration": true
       },
       "smtp": {"status": "ok"},
       "dns_resolver": {"status": "ok"}
     },
     "shutting_down": false
   }

**Response (degraded):** ``503 Service Unavailable``

.. code-block:: json

   {
     "status": "degraded",
     "checks": {
       "database": {"status": "error", "pool": {"size": 10, "available": 0, "waiting": 5}},
       ...
     },
     "shutting_down": false
   }

When the connection pool is exhausted, the database ping is skipped to avoid blocking the health probe:

.. code-block:: json

   {
     "status": "degraded",
     "checks": {
       "database": "pool_exhausted",
       ...
     },
     "shutting_down": false
   }

.. warning::

   **Critical Checks**

   The endpoint returns ``503`` with ``"status": "degraded"`` if any of the
   following critical checks fail: **database** (including ``pool_exhausted``), **CA backend**, or
   **CRL freshness** (when CRL is enabled). Non-critical checks (workers, SMTP,
   DNS resolver) are reported but do not affect the HTTP status code.

**GET** ``/readyz``

Kubernetes readiness probe. Indicates whether the server is ready to accept ACME requests. Checks the same critical subsystems as ``/healthz`` but returns a simplified response.

**Response (ready):** ``200 OK``

.. code-block:: json

   {
     "ready": true
   }

**Response (not ready):** ``503 Service Unavailable``

.. code-block:: json

   {
     "ready": false,
     "reason": "database unavailable"
   }

When the connection pool is critically exhausted:

.. code-block:: json

   {
     "ready": false,
     "reason": "Connection pool exhausted",
     "pool": {"size": 20, "available": 0, "waiting": 5}
   }

.. tip::

   **Kubernetes Integration**

   Use ``/livez`` for the ``livenessProbe`` and ``/readyz`` for the
   ``readinessProbe`` in your Kubernetes deployment. The readiness probe checks:
   database connectivity, CA backend availability, and CRL freshness (if CRL is enabled).

Security Headers
----------------

All responses from the ACMEEH server include the following security headers to protect against common web vulnerabilities:

.. list-table::
   :header-rows: 1
   :widths: 25 30 45

   * - Header
     - Value
     - Description
   * - ``X-Content-Type-Options``
     - ``nosniff``
     - Prevents browsers from MIME-sniffing the response content type.
   * - ``X-Frame-Options``
     - ``DENY``
     - Prevents the response from being rendered in frames or iframes.
   * - ``Content-Security-Policy``
     - ``default-src 'none'; frame-ancestors 'none'``
     - Restricts all content sources and prevents framing.
   * - ``Strict-Transport-Security``
     - ``max-age=<seconds>; includeSubDomains``
     - Enforces HTTPS connections. Only sent over HTTPS. The ``max-age`` value is configurable via ``security.hsts_max_age_seconds``.
   * - ``X-Request-ID``
     - ``<uuid>``
     - Unique identifier for distributed tracing and log correlation. If the client sends an ``X-Request-ID`` header, its value is echoed back; otherwise a new UUID is generated.

Common Response Headers
-----------------------

The following headers are present on ACME protocol responses:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Header
     - Description
   * - ``Replay-Nonce``
     - Fresh nonce for the next request (present on all responses).
   * - ``Location``
     - URL of the created/existing resource.
   * - ``Retry-After``
     - Seconds to wait before retrying (on pending/processing resources).
   * - ``Link: <directory_url>;rel="index"``
     - Points to the ACME directory. Present on all ACME responses to help clients discover the directory.
   * - ``Link``
     - Related resources (e.g., terms of service, parent authorization).
   * - ``Cache-Control: no-store``
     - Present on all ACME responses. Prevents caching of protocol responses to ensure clients always receive fresh data.

Error Responses
---------------

All errors follow `RFC 7807 <https://www.rfc-editor.org/rfc/rfc7807>`_ Problem Details format
with Content-Type ``application/problem+json``:

.. code-block:: json

   {
     "type": "urn:ietf:params:acme:error:unauthorized",
     "detail": "Account key does not match",
     "status": 403
   }

Errors may include a ``subproblems`` array for per-identifier failures
(see `RFC 8555 Section 6.7.1 <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>`_):

.. code-block:: json

   {
     "type": "urn:ietf:params:acme:error:compound",
     "detail": "Multiple errors occurred",
     "status": 400,
     "subproblems": [
       {
         "type": "urn:ietf:params:acme:error:dns",
         "detail": "DNS lookup failed for example.com",
         "identifier": {"type": "dns", "value": "example.com"}
       },
       {
         "type": "urn:ietf:params:acme:error:caa",
         "detail": "CAA record forbids issuance for test.example.com",
         "identifier": {"type": "dns", "value": "test.example.com"}
       }
     ]
   }

ACME Error Types
^^^^^^^^^^^^^^^^

All error types use the ``urn:ietf:params:acme:error:`` prefix. Common ACME error types:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Type
     - Description
   * - ``accountDoesNotExist``
     - Account not found
   * - ``alreadyRevoked``
     - Certificate already revoked
   * - ``badCSR``
     - Invalid CSR
   * - ``badNonce``
     - Invalid or expired nonce
   * - ``badPublicKey``
     - Invalid public key
   * - ``badRevocationReason``
     - Invalid revocation reason code
   * - ``badSignatureAlgorithm``
     - Unsupported signing algorithm
   * - ``caa``
     - CAA record forbids issuance
   * - ``compound``
     - Compound error with subproblems (`RFC 8555 Section 6.7.1 <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>`_)
   * - ``connection``
     - Challenge validation connection error
   * - ``dns``
     - DNS lookup failure
   * - ``externalAccountRequired``
     - External account binding required
   * - ``incorrectResponse``
     - Challenge response mismatch
   * - ``invalidContact``
     - Invalid contact URI
   * - ``malformed``
     - Malformed request
   * - ``orderNotReady``
     - Order not in ready state for finalization
   * - ``rateLimited``
     - Rate limit exceeded
   * - ``rejectedIdentifier``
     - Identifier rejected by policy
   * - ``serverInternal``
     - Internal server error
   * - ``tls``
     - TLS validation error
   * - ``unauthorized``
     - Authorization failure
   * - ``unsupportedContact``
     - Unsupported contact protocol
   * - ``unsupportedIdentifier``
     - Unsupported identifier type
   * - ``userActionRequired``
     - Out-of-band user action required

ACME Headers
------------

In addition to the common response headers and security headers documented above, the following
ACME-specific headers appear on every protocol response:

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Header
     - Value
     - Description
   * - ``Link``
     - ``<directory_url>;rel="index"``
     - Present on all ACME responses. Points to the directory resource so clients can always
       discover available endpoints regardless of which URL they started from.
   * - ``Cache-Control``
     - ``no-store``
     - Present on all ACME responses. Ensures that intermediaries and browsers do not cache
       protocol responses, which could lead to stale nonces or outdated resource states.
   * - ``Replay-Nonce``
     - ``<nonce>``
     - Present on all ACME responses. Provides a fresh nonce that the client must include
       in its next request's JWS protected header for replay protection.
