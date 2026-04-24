=========
Admin API
=========

*REST API for server management, users, audit, EAB, and more*

The Admin API provides a REST interface for managing the ACMEEH server. It is
optional and must be explicitly enabled in the configuration. The API supports
user management, audit logging, EAB credential management, identifier allowlists,
CSR profiles, certificate operations, notification management, CRL rebuilds, and
maintenance mode.


Admin Client
------------

``acmeeh-admin`` is the official Python client library and CLI for interacting with
the Admin API. Install it from `PyPI <https://pypi.org/project/acmeeh-admin/>`_:

.. code-block:: bash

   pip install acmeeh-admin

The package provides:

- **Python library** --- programmatic access via ``AcmeehAdminClient`` for automation and scripting.
- **CLI** --- the ``acmeeh-admin`` command-line tool for operators (user management, audit export, certificate search, EAB provisioning, maintenance mode, and more).

For full documentation and source code, see the
`acmeeh-admin repository <https://github.com/miichoow/ACMEEH-admin>`_.


Enabling the Admin API
----------------------

Add the following to your configuration file to enable the Admin API:

.. code-block:: yaml

   admin_api:
     enabled: true
     base_path: /api
     token_secret: ${ADMIN_TOKEN_SECRET}
     token_expiry_seconds: 3600

.. danger::
   **Security**

   The ``token_secret`` is used to sign JWT bearer tokens. Use a strong, random value
   (at least 32 characters) and keep it secret. The Admin API should be exposed only on
   internal or management networks, never on the public internet.


Creating the Initial Admin User
-------------------------------

Use the CLI to create the first admin user before starting the server:

.. code-block:: bash

   PYTHONPATH=src python -m acmeeh -c config.yaml admin create-user \
       --username admin --email admin@example.com --role admin

This prints a generated password to stdout. Store it securely --- it cannot be retrieved
later. If lost, use the ``POST /api/me/reset-password`` endpoint or create a new user.


Authentication
--------------

All Admin API endpoints (except ``POST /api/auth/login``) require a bearer token in the
``Authorization`` header. Obtain a token by logging in, then include it in subsequent requests:

.. code-block:: bash

   curl -H "Authorization: Bearer eyJ..." https://acme.example.com/api/users

Tokens expire after the configured ``token_expiry_seconds`` (default: 3600 seconds).
When a token expires, the server responds with ``401 Unauthorized`` and you must log in again.

**POST** ``/api/auth/login``

Authenticate with username and password to receive a bearer token. No authentication required.
Rate limited per IP address and username to prevent brute-force attacks.

**Request body:**

.. code-block:: json

   {
     "username": "admin",
     "password": "generated-password"
   }

**Response 200:**

.. code-block:: json

   {
     "token": "eyJ...",
     "user": {
       "id": "550e8400-e29b-41d4-a716-446655440000",
       "username": "admin",
       "email": "admin@example.com",
       "role": "admin",
       "enabled": true,
       "created_at": "2025-01-15T10:30:00Z",
       "updated_at": "2025-01-15T10:30:00Z",
       "last_login_at": "2025-06-01T08:15:00Z"
     }
   }

**Error 401:** Invalid username or password.

**Error 429:** Rate limit exceeded. Retry after the interval specified in the ``Retry-After`` header.

**POST** ``/api/auth/logout``

Revoke the current bearer token. Requires authentication.

**Response 200:**

.. code-block:: json

   {
     "status": "logged_out"
   }


Roles
-----

The Admin API uses role-based access control. Each endpoint requires one or more roles:

.. list-table::
   :header-rows: 1

   * - Role
     - Permissions
   * - ``admin``
     - Full access: create/delete users, manage EAB credentials, manage identifier allowlists,
       manage CSR profiles, bulk-revoke certificates, manage notifications, CRL rebuild,
       maintenance mode, audit log export
   * - ``auditor``
     - Read-only access: list and view users, view audit logs, list and view certificates,
       list and view CSR profiles, list and view ACME accounts (with redacted JWK),
       view current user profile


Pagination
----------

List endpoints support two pagination strategies:

Cursor-based pagination (preferred)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Used by the audit log and certificate list endpoints. The server returns a ``Link`` header
with a ``rel="next"`` URL containing the cursor for the next page:

.. code-block:: text

   Link: </api/audit-log?cursor=eyJ...&limit=50>; rel="next"

Pass the ``cursor`` query parameter from the Link header to fetch the next page.
When there are no more results, the ``Link`` header is absent.

Offset-based pagination (fallback)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Used by some list endpoints. Pass ``limit`` and ``offset`` query parameters:

.. code-block:: text

   GET /api/certificates?limit=50&offset=100


Users
-----

Manage admin panel users. Users have a role (``admin`` or ``auditor``) and can
be enabled or disabled. Passwords are server-generated and returned only at creation or reset time.

**GET** ``/api/users``

List all admin users. *admin, auditor*

**Response 200:**

.. code-block:: json

   [
     {
       "id": "550e8400-e29b-41d4-a716-446655440000",
       "username": "admin",
       "email": "admin@example.com",
       "role": "admin",
       "enabled": true,
       "created_at": "2025-01-15T10:30:00Z",
       "updated_at": "2025-01-15T10:30:00Z",
       "last_login_at": "2025-06-01T08:15:00Z"
     },
     {
       "id": "660e8400-e29b-41d4-a716-446655440001",
       "username": "auditor1",
       "email": "auditor@example.com",
       "role": "auditor",
       "enabled": true,
       "created_at": "2025-02-01T14:00:00Z",
       "updated_at": "2025-02-01T14:00:00Z",
       "last_login_at": null
     }
   ]

**POST** ``/api/users``

Create a new admin user. A password is auto-generated and returned only in this response.
*admin*

**Request body:**

.. code-block:: json

   {
     "username": "operator",
     "email": "op@example.com",
     "role": "auditor"
   }

**Response 201:**

.. code-block:: json

   {
     "id": "770e8400-e29b-41d4-a716-446655440002",
     "username": "operator",
     "email": "op@example.com",
     "role": "auditor",
     "enabled": true,
     "created_at": "2025-06-15T09:00:00Z",
     "updated_at": "2025-06-15T09:00:00Z",
     "last_login_at": null,
     "password": "a1B2c3D4e5F6g7H8"
   }

.. danger::
   **Important**

   The ``password`` field is only included in the creation response. Store it
   securely --- it cannot be retrieved again. If lost, use
   ``POST /api/me/reset-password`` to generate a new one.

**Error 400:** Missing ``username`` or ``email``, or invalid ``role`` value.

**GET** ``/api/users/{user_id}``

Get a specific user by ID. *admin, auditor*

**Response 200:**

.. code-block:: json

   {
     "id": "550e8400-e29b-41d4-a716-446655440000",
     "username": "admin",
     "email": "admin@example.com",
     "role": "admin",
     "enabled": true,
     "created_at": "2025-01-15T10:30:00Z",
     "updated_at": "2025-01-15T10:30:00Z",
     "last_login_at": "2025-06-01T08:15:00Z"
   }

**Error 404:** User not found.

**PATCH** ``/api/users/{user_id}``

Update a user. Supports partial updates --- only include the fields you want to change.
*admin*

**Request body (partial update):**

.. code-block:: json

   {
     "enabled": false
   }

Or change the role:

.. code-block:: json

   {
     "role": "admin"
   }

Or update multiple fields at once:

.. code-block:: json

   {
     "enabled": true,
     "role": "auditor"
   }

**Response 200:**

.. code-block:: json

   {
     "id": "770e8400-e29b-41d4-a716-446655440002",
     "username": "operator",
     "email": "op@example.com",
     "role": "auditor",
     "enabled": false,
     "created_at": "2025-06-15T09:00:00Z",
     "updated_at": "2025-06-15T12:30:00Z",
     "last_login_at": null
   }

**Error 404:** User not found.

**DELETE** ``/api/users/{user_id}``

Delete a user permanently. *admin*

**Response:** ``204 No Content``

**Error 404:** User not found.

**GET** ``/api/me``

Get the current authenticated user's profile. *admin, auditor*

**Response 200:**

.. code-block:: json

   {
     "id": "550e8400-e29b-41d4-a716-446655440000",
     "username": "admin",
     "email": "admin@example.com",
     "role": "admin",
     "enabled": true,
     "created_at": "2025-01-15T10:30:00Z",
     "updated_at": "2025-01-15T10:30:00Z",
     "last_login_at": "2025-06-01T08:15:00Z"
   }

**POST** ``/api/me/reset-password``

Reset your own password. Returns the user object with a new server-generated password.
*admin, auditor*

**Response 200:**

.. code-block:: json

   {
     "id": "550e8400-e29b-41d4-a716-446655440000",
     "username": "admin",
     "email": "admin@example.com",
     "role": "admin",
     "enabled": true,
     "created_at": "2025-01-15T10:30:00Z",
     "updated_at": "2025-06-15T12:45:00Z",
     "last_login_at": "2025-06-01T08:15:00Z",
     "password": "x9Y8w7V6u5T4s3R2"
   }

.. danger::
   **Important**

   The ``password`` field is only included in this response. Store it securely.


Audit Log
---------

The audit log records all administrative actions performed through the Admin API. Entries are
immutable and cannot be modified or deleted.

**GET** ``/api/audit-log``

Query the audit log with filtering and cursor-based pagination. *admin, auditor*

**Query parameters:**

.. list-table::
   :header-rows: 1

   * - Parameter
     - Type
     - Description
   * - ``action``
     - string
     - Filter by action type (e.g., ``user.create``, ``eab.revoke``)
   * - ``user_id``
     - UUID
     - Filter by the user who performed the action
   * - ``since``
     - ISO 8601
     - Return entries after this timestamp
   * - ``until``
     - ISO 8601
     - Return entries before this timestamp
   * - ``cursor``
     - string
     - Pagination cursor from the ``Link`` header
   * - ``limit``
     - integer
     - Maximum number of entries to return (default: 50)

**Response 200:**

.. code-block:: json

   [
     {
       "id": "aa0e8400-e29b-41d4-a716-446655440010",
       "user_id": "550e8400-e29b-41d4-a716-446655440000",
       "action": "user.create",
       "target_user_id": "770e8400-e29b-41d4-a716-446655440002",
       "details": {
         "username": "operator",
         "role": "auditor"
       },
       "ip_address": "10.0.1.50",
       "created_at": "2025-06-15T09:00:00Z"
     },
     {
       "id": "bb0e8400-e29b-41d4-a716-446655440011",
       "user_id": null,
       "action": "auth.login_failed",
       "target_user_id": null,
       "details": {
         "username": "unknown"
       },
       "ip_address": "192.168.1.100",
       "created_at": "2025-06-14T22:30:00Z"
     }
   ]

**Pagination:** The ``Link`` header contains the URL for the next page when
more results are available:

.. code-block:: text

   Link: </api/audit-log?cursor=eyJ...&limit=50>; rel="next"

**POST** ``/api/audit-log/export``

Export audit log entries as an NDJSON (newline-delimited JSON) stream. Supports the same
filters as the list endpoint. *admin*

**Request body (optional):**

.. code-block:: json

   {
     "action": "user.create",
     "user_id": "550e8400-e29b-41d4-a716-446655440000",
     "since": "2025-01-01T00:00:00Z",
     "until": "2025-06-30T23:59:59Z"
   }

All filter fields are optional. Omit the request body or send ``{}`` to export all entries.

**Response 200:** ``Content-Type: application/x-ndjson``

.. code-block:: text

   {"id":"aa0e...","user_id":"550e...","action":"user.create","target_user_id":"770e...","details":{"username":"operator","role":"auditor"},"ip_address":"10.0.1.50","created_at":"2025-06-15T09:00:00Z"}
   {"id":"bb0e...","user_id":null,"action":"auth.login_failed","target_user_id":null,"details":{"username":"unknown"},"ip_address":"192.168.1.100","created_at":"2025-06-14T22:30:00Z"}


External Account Binding (EAB)
------------------------------

When ``acme.eab_required`` is ``true``, ACME clients must present a valid
EAB credential during account registration. Use these endpoints to create, list, and revoke EAB credentials.

**GET** ``/api/eab``

List all EAB credentials. *admin*

**Response 200:**

.. code-block:: json

   [
     {
       "id": "cc0e8400-e29b-41d4-a716-446655440020",
       "kid": "eab-key-001",
       "label": "Team Alpha",
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "account_id": "dd0e8400-e29b-41d4-a716-446655440030",
       "used": true,
       "used_at": "2025-06-16T11:00:00Z",
       "revoked": false,
       "created_at": "2025-06-15T10:00:00Z"
     },
     {
       "id": "cc0e8400-e29b-41d4-a716-446655440021",
       "kid": "eab-key-002",
       "label": "Team Beta",
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "account_id": null,
       "used": false,
       "used_at": null,
       "revoked": false,
       "created_at": "2025-06-15T10:05:00Z"
     }
   ]

**POST** ``/api/eab``

Create a new EAB credential. The ``hmac_key`` is only returned in this response.
*admin*

**Request body:**

.. code-block:: json

   {
     "kid": "eab-key-003",
     "label": "Team Gamma"
   }

**Response 201:**

.. code-block:: json

   {
     "id": "cc0e8400-e29b-41d4-a716-446655440022",
     "kid": "eab-key-003",
     "label": "Team Gamma",
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "account_id": null,
     "used": false,
     "used_at": null,
     "revoked": false,
     "created_at": "2025-06-15T10:10:00Z",
     "hmac_key": "dGhpc0lzQVNlY3JldEtleUZvckVBQg"
   }

.. danger::
   **Important**

   The ``hmac_key`` is base64url-encoded and is only shown at creation time.
   Provide the ``kid`` and ``hmac_key`` to the ACME client for use
   during account registration with External Account Binding.

**Error 400:** Missing ``kid`` field.

**GET** ``/api/eab/{cred_id}``

Get a specific EAB credential. The ``hmac_key`` is never included in this response.
*admin*

**Response 200:**

.. code-block:: json

   {
     "id": "cc0e8400-e29b-41d4-a716-446655440020",
     "kid": "eab-key-001",
     "label": "Team Alpha",
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "account_id": "dd0e8400-e29b-41d4-a716-446655440030",
     "used": true,
     "used_at": "2025-06-16T11:00:00Z",
     "revoked": false,
     "created_at": "2025-06-15T10:00:00Z"
   }

**Error 404:** EAB credential not found.

**POST** ``/api/eab/{cred_id}/revoke``

Revoke an EAB credential so it can no longer be used for account registration.
Every ACME account that was registered with this credential is cascaded to
``revoked`` status (RFC 8555 §7.1.2) and its pending/valid authorizations
are deactivated — the client cannot place further orders. Under
``acme.eab_reusable`` a single EAB may have registered many accounts over
time; all of them are revoked, not only the currently-bound one. The
cascade is a no-op for accounts already ``deactivated`` or ``revoked``, and
the outcome is recorded in the audit log entry under
``details.linked_accounts`` (every valid account registered with this EAB)
and ``details.revoked_accounts`` (the subset whose status transitioned on
this call). *admin*

**Response 200:**

.. code-block:: json

   {
     "id": "cc0e8400-e29b-41d4-a716-446655440021",
     "kid": "eab-key-002",
     "label": "Team Beta",
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "account_id": null,
     "used": false,
     "used_at": null,
     "revoked": true,
     "created_at": "2025-06-15T10:05:00Z"
   }

**Error 404:** EAB credential not found.


EAB Allowed Identifiers
^^^^^^^^^^^^^^^^^^^^^^^^

Associate allowed identifiers with EAB credentials to restrict which identifiers
an account registered with a given EAB credential may request certificates for.

**GET** ``/api/eab/{cred_id}/allowed-identifiers``

List allowed identifiers associated with an EAB credential. *admin*

**Response 200:**

.. code-block:: json

   [
     {
       "id": "ee0e8400-e29b-41d4-a716-446655440040",
       "identifier_type": "dns",
       "identifier_value": "*.example.com",
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "created_at": "2025-06-15T10:00:00Z"
     }
   ]

**Error 404:** EAB credential not found.

**PUT** ``/api/eab/{cred_id}/allowed-identifiers/{identifier_id}``

Associate an allowed identifier with an EAB credential. *admin*

**Response:** ``204 No Content``

**Error 404:** EAB credential or identifier not found.

**DELETE** ``/api/eab/{cred_id}/allowed-identifiers/{identifier_id}``

Remove the association between an allowed identifier and an EAB credential. *admin*

**Response:** ``204 No Content``

**Error 404:** EAB credential or identifier not found.


EAB CSR Profile
^^^^^^^^^^^^^^^^

Assign a CSR profile to an EAB credential. Accounts registered with this credential
will have their certificate requests validated against the assigned profile.

**GET** ``/api/eab/{cred_id}/csr-profile``

Get the CSR profile assigned to an EAB credential. Returns ``null`` if no
profile is assigned. *admin*

**Response 200 (profile assigned):**

.. code-block:: json

   {
     "id": "ff0e8400-e29b-41d4-a716-446655440050",
     "name": "server-tls",
     "description": "Standard server TLS profile",
     "profile_data": {
       "key_usages": ["digital_signature", "key_encipherment"],
       "extended_key_usages": ["server_auth"],
       "validity_days": 90
     },
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "created_at": "2025-06-15T10:00:00Z",
     "updated_at": "2025-06-15T10:00:00Z"
   }

**Response 200 (no profile assigned):**

.. code-block:: json

   null

**Error 404:** EAB credential not found.

**PUT** ``/api/eab/{cred_id}/csr-profile/{profile_id}``

Assign a CSR profile to an EAB credential. *admin*

**Response:** ``204 No Content``

**Error 404:** EAB credential or CSR profile not found.

**DELETE** ``/api/eab/{cred_id}/csr-profile/{profile_id}``

Remove the CSR profile assignment from an EAB credential. *admin*

**Response:** ``204 No Content``

**Error 404:** EAB credential or CSR profile not found.


Allowed Identifiers
-------------------

Per-account identifier allowlists. When ``security.identifier_policy.enforce_account_allowlist``
is enabled, accounts can only request certificates for identifiers explicitly assigned to them.
Identifiers support wildcards (e.g., ``*.example.com``).

**GET** ``/api/allowed-identifiers``

List all allowed identifier entries. *admin*

**Response 200:**

.. code-block:: json

   [
     {
       "id": "ee0e8400-e29b-41d4-a716-446655440040",
       "identifier_type": "dns",
       "identifier_value": "*.example.com",
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "created_at": "2025-06-15T10:00:00Z",
       "account_ids": [
         "dd0e8400-e29b-41d4-a716-446655440030",
         "dd0e8400-e29b-41d4-a716-446655440031"
       ]
     },
     {
       "id": "ee0e8400-e29b-41d4-a716-446655440041",
       "identifier_type": "dns",
       "identifier_value": "internal.corp.local",
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "created_at": "2025-06-15T10:05:00Z",
       "account_ids": []
     }
   ]

**POST** ``/api/allowed-identifiers``

Create an allowed identifier entry. *admin*

**Request body:**

.. code-block:: json

   {
     "type": "dns",
     "value": "*.example.com"
   }

**Response 201:**

.. code-block:: json

   {
     "id": "ee0e8400-e29b-41d4-a716-446655440042",
     "identifier_type": "dns",
     "identifier_value": "*.example.com",
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "created_at": "2025-06-15T10:15:00Z",
     "account_ids": []
   }

**Error 400:** Missing ``type`` or ``value`` field.

**GET** ``/api/allowed-identifiers/{id}``

Get a specific allowed identifier entry, including associated account IDs.
*admin*

**Response 200:**

.. code-block:: json

   {
     "id": "ee0e8400-e29b-41d4-a716-446655440040",
     "identifier_type": "dns",
     "identifier_value": "*.example.com",
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "created_at": "2025-06-15T10:00:00Z",
     "account_ids": [
       "dd0e8400-e29b-41d4-a716-446655440030",
       "dd0e8400-e29b-41d4-a716-446655440031"
     ]
   }

**Error 404:** Identifier not found.

**DELETE** ``/api/allowed-identifiers/{id}``

Delete an allowed identifier entry. This cascades to remove all account associations
for this identifier. *admin*

**Response:** ``204 No Content``

**Error 404:** Identifier not found.

**PUT** ``/api/allowed-identifiers/{identifier_id}/accounts/{account_id}``

Associate an allowed identifier with an ACME account. After this association, the account
is permitted to request certificates for this identifier. *admin*

**Response:** ``204 No Content``

**Error 404:** Identifier or account not found.

**DELETE** ``/api/allowed-identifiers/{identifier_id}/accounts/{account_id}``

Remove the association between an allowed identifier and an ACME account. The account
will no longer be permitted to request certificates for this identifier.
*admin*

**Response:** ``204 No Content``

**Error 404:** Identifier or account not found.

**GET** ``/api/accounts/{account_id}/allowed-identifiers``

List all allowed identifiers for a specific ACME account. *admin*

**Response 200:**

.. code-block:: json

   [
     {
       "id": "ee0e8400-e29b-41d4-a716-446655440040",
       "identifier_type": "dns",
       "identifier_value": "*.example.com",
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "created_at": "2025-06-15T10:00:00Z",
       "account_ids": [
         "dd0e8400-e29b-41d4-a716-446655440030"
       ]
     }
   ]

**Error 404:** Account not found.


CSR Profiles
------------

Manage certificate profiles that control key usages, extended key usages, validity period, and
other certificate properties. Profiles can be assigned to ACME accounts to enforce certificate
policies per account. Set ``security.require_csr_profile: true`` to reject certificate
finalization for accounts without an assigned profile (see :ref:`csr-profile-enforcement`).

**GET** ``/api/csr-profiles``

List all CSR profiles. *admin, auditor*

**Response 200:**

.. code-block:: json

   [
     {
       "id": "ff0e8400-e29b-41d4-a716-446655440050",
       "name": "server-tls",
       "description": "Standard server TLS profile",
       "profile_data": {
         "key_usages": ["digital_signature", "key_encipherment"],
         "extended_key_usages": ["server_auth"],
         "validity_days": 90
       },
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "created_at": "2025-06-15T10:00:00Z",
       "updated_at": "2025-06-15T10:00:00Z"
     },
     {
       "id": "ff0e8400-e29b-41d4-a716-446655440051",
       "name": "client-auth",
       "description": "Client authentication profile",
       "profile_data": {
         "key_usages": ["digital_signature"],
         "extended_key_usages": ["client_auth"],
         "validity_days": 365
       },
       "created_by": "550e8400-e29b-41d4-a716-446655440000",
       "created_at": "2025-06-15T10:05:00Z",
       "updated_at": "2025-06-15T10:05:00Z"
     }
   ]

**POST** ``/api/csr-profiles``

Create a new CSR profile. *admin*

**Request body:**

.. code-block:: json

   {
     "name": "server-tls",
     "description": "Standard server TLS profile",
     "profile_data": {
       "key_usages": ["digital_signature", "key_encipherment"],
       "extended_key_usages": ["server_auth"],
       "validity_days": 90
     }
   }

**Response 201:**

.. code-block:: json

   {
     "id": "ff0e8400-e29b-41d4-a716-446655440052",
     "name": "server-tls",
     "description": "Standard server TLS profile",
     "profile_data": {
       "key_usages": ["digital_signature", "key_encipherment"],
       "extended_key_usages": ["server_auth"],
       "validity_days": 90
     },
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "created_at": "2025-06-15T10:20:00Z",
     "updated_at": "2025-06-15T10:20:00Z"
   }

**Error 400:** Missing ``name`` or ``profile_data`` field.

**GET** ``/api/csr-profiles/{profile_id}``

Get a specific CSR profile, including the list of associated account IDs.
*admin, auditor*

**Response 200:**

.. code-block:: json

   {
     "id": "ff0e8400-e29b-41d4-a716-446655440050",
     "name": "server-tls",
     "description": "Standard server TLS profile",
     "profile_data": {
       "key_usages": ["digital_signature", "key_encipherment"],
       "extended_key_usages": ["server_auth"],
       "validity_days": 90
     },
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "created_at": "2025-06-15T10:00:00Z",
     "updated_at": "2025-06-15T10:00:00Z",
     "account_ids": [
       "dd0e8400-e29b-41d4-a716-446655440030"
     ]
   }

**Error 404:** CSR profile not found.

**PUT** ``/api/csr-profiles/{profile_id}``

Update a CSR profile. This is a full replacement --- all fields must be provided.
*admin*

**Request body:**

.. code-block:: json

   {
     "name": "server-tls-updated",
     "description": "Updated server TLS profile with longer validity",
     "profile_data": {
       "key_usages": ["digital_signature", "key_encipherment"],
       "extended_key_usages": ["server_auth"],
       "validity_days": 180
     }
   }

**Response 200:**

.. code-block:: json

   {
     "id": "ff0e8400-e29b-41d4-a716-446655440050",
     "name": "server-tls-updated",
     "description": "Updated server TLS profile with longer validity",
     "profile_data": {
       "key_usages": ["digital_signature", "key_encipherment"],
       "extended_key_usages": ["server_auth"],
       "validity_days": 180
     },
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "created_at": "2025-06-15T10:00:00Z",
     "updated_at": "2025-06-15T14:00:00Z"
   }

**Error 400:** Missing ``name`` or ``profile_data`` field.

**Error 404:** CSR profile not found.

**DELETE** ``/api/csr-profiles/{profile_id}``

Delete a CSR profile. *admin*

**Response:** ``204 No Content``

**Error 404:** CSR profile not found.

**POST** ``/api/csr-profiles/{profile_id}/validate``

Dry-run validate a CSR against a profile without issuing a certificate. Useful for testing
that a CSR conforms to a profile's constraints before submitting an order.
*admin, auditor*

**Request body:**

.. code-block:: json

   {
     "csr": "MIICYzCCAUsCAQAwHj...base64-DER-encoded-CSR"
   }

**Response 200:** Validation result object describing whether the CSR passes
the profile's requirements, and any violations found.

**Error 404:** CSR profile not found.

**PUT** ``/api/csr-profiles/{profile_id}/accounts/{account_id}``

Assign a CSR profile to an ACME account. The account's certificate requests will be
validated against this profile. *admin*

**Response:** ``204 No Content``

**Error 404:** CSR profile or account not found.

**DELETE** ``/api/csr-profiles/{profile_id}/accounts/{account_id}``

Remove a CSR profile assignment from an ACME account. The account will revert to the
default certificate policy. *admin*

**Response:** ``204 No Content``

**Error 404:** CSR profile or account not found.

**GET** ``/api/accounts/{account_id}/csr-profile``

Get the CSR profile assigned to a specific ACME account. Returns ``null`` if no
profile is assigned. *admin, auditor*

**Response 200 (profile assigned):**

.. code-block:: json

   {
     "id": "ff0e8400-e29b-41d4-a716-446655440050",
     "name": "server-tls",
     "description": "Standard server TLS profile",
     "profile_data": {
       "key_usages": ["digital_signature", "key_encipherment"],
       "extended_key_usages": ["server_auth"],
       "validity_days": 90
     },
     "created_by": "550e8400-e29b-41d4-a716-446655440000",
     "created_at": "2025-06-15T10:00:00Z",
     "updated_at": "2025-06-15T10:00:00Z"
   }

**Response 200 (no profile assigned):**

.. code-block:: json

   null

**Error 404:** Account not found.


CSR Profile Reference
---------------------

The ``profile_data`` object controls how CSRs are validated against the profile. All fields
are optional --- omitted fields disable that particular check. Here is a complete example with every
supported field:

.. code-block:: json

   {
     "authorized_keys": {
       "RSA": 2048,
       "EC.secp256r1": 256,
       "EC.secp384r1": 384,
       "EC.secp521r1": 521,
       "Ed25519": 0,
       "Ed448": 0
     },
     "authorized_signature_algorithms": [
       "SHA256withRSA",
       "SHA384withRSA",
       "SHA512withRSA",
       "SHA256withECDSA",
       "SHA384withECDSA",
       "SHA512withECDSA",
       "Ed25519",
       "Ed448"
     ],
     "authorized_key_usages": [
       "digital_signature",
       "content_commitment",
       "key_encipherment",
       "data_encipherment",
       "key_agreement",
       "key_cert_sign",
       "crl_sign",
       "encipher_only",
       "decipher_only"
     ],
     "authorized_extended_key_usages": [
       "serverAuth",
       "clientAuth",
       "codeSigning",
       "emailProtection",
       "timeStamping",
       "OCSPSigning"
     ],
     "common_name_minimum": 0,
     "common_name_maximum": -1,
     "common_name_regex": ".*",
     "san_minimum": -1,
     "san_maximum": -1,
     "san_regex": ".*",
     "san_types": [
       "DNS_NAME",
       "IP_ADDRESS",
       "RFC822_NAME",
       "URI"
     ],
     "subject_regex": ".*",
     "wildcard_in_common_name": true,
     "wildcard_in_san": true,
     "max_subdomain_depth": 10,
     "depth_base_domains": ["corp.internal"],
     "reuse_key": true,
     "renewal_window_days": 0
   }

Field Reference
^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - Field
     - Type
     - Description
   * - ``authorized_keys``
     - object
     - Map of key type label to minimum key size in bits. Use ``0`` for fixed-size
       algorithms (Ed25519, Ed448). CSRs with a key type not in this map are rejected.
   * - ``authorized_signature_algorithms``
     - array of strings
     - Allowed CSR signature algorithms. Values are case-sensitive and must match exactly.
   * - ``authorized_key_usages``
     - array of strings
     - Allowed Key Usage extension values. If the CSR includes a Key Usage extension with
       values not in this list, validation fails.
   * - ``authorized_extended_key_usages``
     - array of strings
     - Allowed Extended Key Usage values. If the CSR includes an EKU extension with
       values not in this list, validation fails.
   * - ``common_name_minimum``
     - integer
     - Minimum number of CN attributes required. ``-1`` = no minimum (default).
   * - ``common_name_maximum``
     - integer
     - Maximum number of CN attributes allowed. ``-1`` = no maximum (default).
   * - ``common_name_regex``
     - string
     - Python regex that each CN value must fully match (``fullmatch``).
   * - ``san_minimum``
     - integer
     - Minimum number of SANs required. ``-1`` = no minimum (default).
   * - ``san_maximum``
     - integer
     - Maximum number of SANs allowed. ``-1`` = no maximum (default).
   * - ``san_regex``
     - string
     - Python regex that each SAN value must fully match.
   * - ``san_types``
     - array of strings
     - Allowed SAN types. CSRs containing a SAN type not in this list are rejected.
   * - ``subject_regex``
     - string
     - Python regex matched against the CSR subject in RFC 4514 format
       (e.g., ``CN=example.com,O=Corp,C=US``).
   * - ``wildcard_in_common_name``
     - boolean
     - ``false`` rejects CN values starting with ``*.``.
       Omit or set ``true`` to allow wildcards.
   * - ``wildcard_in_san``
     - boolean
     - ``false`` rejects DNS SAN values starting with ``*.``.
       Omit or set ``true`` to allow wildcards.
   * - ``max_subdomain_depth``
     - integer
     - Maximum number of labels beyond a base domain. Requires ``depth_base_domains``.
       Example: depth 2 with base ``corp.internal`` allows ``a.b.corp.internal``
       but not ``a.b.c.corp.internal``.
   * - ``depth_base_domains``
     - array of strings
     - Base domains for subdomain depth checking. Both this and ``max_subdomain_depth``
       must be present for the check to activate.
   * - ``reuse_key``
     - boolean
     - ``false`` rejects CSRs whose public key matches a previously-issued certificate.
       Omit or set ``true`` to allow key reuse.
   * - ``renewal_window_days``
     - integer
     - When positive, blocks issuance if an active certificate for the same hosts does not
       expire within this many days. ``0`` disables the check (default).

Allowed Values
^^^^^^^^^^^^^^

Key Type Labels (``authorized_keys``)
""""""""""""""""""""""""""""""""""""""

Key type labels must match exactly what the server derives from the CSR public key:

.. list-table::
   :header-rows: 1

   * - Label
     - Key Type
     - Size Constraint
   * - ``RSA``
     - RSA
     - Minimum bits (e.g., 2048)
   * - ``EC.secp256r1``
     - ECDSA P-256
     - 256
   * - ``EC.secp384r1``
     - ECDSA P-384
     - 384
   * - ``EC.secp521r1``
     - ECDSA P-521
     - 521
   * - ``Ed25519``
     - EdDSA (Curve25519)
     - Fixed --- use 0
   * - ``Ed448``
     - EdDSA (Curve448)
     - Fixed --- use 0

The ``EC.`` prefix followed by the curve name is required for elliptic curve keys. The curve name
comes from Python's ``cryptography`` library (e.g., ``secp256r1``, not ``prime256v1``).

Signature Algorithms (``authorized_signature_algorithms``)
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

These are the only recognized values (case-sensitive):

.. list-table::
   :header-rows: 1

   * - Value
     - Algorithm
   * - ``SHA256withRSA``
     - RSA with SHA-256
   * - ``SHA384withRSA``
     - RSA with SHA-384
   * - ``SHA512withRSA``
     - RSA with SHA-512
   * - ``SHA256withECDSA``
     - ECDSA with SHA-256
   * - ``SHA384withECDSA``
     - ECDSA with SHA-384
   * - ``SHA512withECDSA``
     - ECDSA with SHA-512
   * - ``Ed25519``
     - EdDSA Curve25519
   * - ``Ed448``
     - EdDSA Curve448

.. danger::
   **Important**

   Algorithm names are **case-sensitive** and use a specific format
   (e.g., ``SHA256withRSA``, not ``sha256WithRSAEncryption``).
   Algorithms not listed above (DSA, MD5, SHA-1, GOST, RSASSA-PSS) are not supported.

Key Usages (``authorized_key_usages``)
"""""""""""""""""""""""""""""""""""""""

Values use ``snake_case`` matching Python's ``cryptography.x509.KeyUsage`` attributes:

.. list-table::
   :header-rows: 1

   * - Value
     - Description
   * - ``digital_signature``
     - Verify digital signatures (TLS, authentication)
   * - ``content_commitment``
     - Non-repudiation
   * - ``key_encipherment``
     - Encrypt keys (RSA key exchange)
   * - ``data_encipherment``
     - Encrypt data directly
   * - ``key_agreement``
     - Key agreement (ECDH)
   * - ``key_cert_sign``
     - Sign certificates (CA only)
   * - ``crl_sign``
     - Sign CRLs (CA only)
   * - ``encipher_only``
     - Encipher during key agreement
   * - ``decipher_only``
     - Decipher during key agreement

Extended Key Usages (``authorized_extended_key_usages``)
""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Values use ``camelCase`` names. Only these six OIDs are mapped by name:

.. list-table::
   :header-rows: 1

   * - Value
     - OID
     - Description
   * - ``serverAuth``
     - 1.3.6.1.5.5.7.3.1
     - TLS server authentication
   * - ``clientAuth``
     - 1.3.6.1.5.5.7.3.2
     - TLS client authentication
   * - ``codeSigning``
     - 1.3.6.1.5.5.7.3.3
     - Code signing
   * - ``emailProtection``
     - 1.3.6.1.5.5.7.3.4
     - S/MIME email
   * - ``timeStamping``
     - 1.3.6.1.5.5.7.3.8
     - Trusted timestamping
   * - ``OCSPSigning``
     - 1.3.6.1.5.5.7.3.9
     - OCSP response signing

For EKU OIDs not listed above, the dotted-string OID itself (e.g., ``1.3.6.1.5.5.7.3.17``) is
used as the comparison value.

SAN Types (``san_types``)
"""""""""""""""""""""""""

.. list-table::
   :header-rows: 1

   * - Value
     - Description
   * - ``DNS_NAME``
     - DNS domain name
   * - ``IP_ADDRESS``
     - IPv4 or IPv6 address
   * - ``RFC822_NAME``
     - Email address
   * - ``URI``
     - Uniform Resource Identifier

Example Profiles
^^^^^^^^^^^^^^^^

Web Server TLS
""""""""""""""

.. code-block:: json

   {
     "authorized_keys": { "RSA": 2048, "EC.secp256r1": 256, "EC.secp384r1": 384 },
     "authorized_signature_algorithms": ["SHA256withRSA", "SHA384withRSA", "SHA256withECDSA", "SHA384withECDSA"],
     "authorized_key_usages": ["digital_signature", "key_encipherment"],
     "authorized_extended_key_usages": ["serverAuth"],
     "common_name_minimum": 1,
     "common_name_maximum": 1,
     "common_name_regex": "^[a-z0-9.-]+\\.corp\\.internal$",
     "san_minimum": 1,
     "san_maximum": 10,
     "san_regex": "^[a-z0-9.-]+\\.corp\\.internal$",
     "san_types": ["DNS_NAME"],
     "wildcard_in_common_name": false,
     "wildcard_in_san": false,
     "max_subdomain_depth": 2,
     "depth_base_domains": ["corp.internal"],
     "reuse_key": false,
     "renewal_window_days": 30
   }

Client Authentication
"""""""""""""""""""""

.. code-block:: json

   {
     "authorized_keys": { "RSA": 2048, "EC.secp256r1": 256 },
     "authorized_signature_algorithms": ["SHA256withRSA", "SHA256withECDSA"],
     "authorized_key_usages": ["digital_signature"],
     "authorized_extended_key_usages": ["clientAuth"],
     "san_minimum": 1,
     "san_maximum": 1,
     "san_types": ["RFC822_NAME"],
     "wildcard_in_common_name": false,
     "reuse_key": false
   }

Code Signing
""""""""""""

.. code-block:: json

   {
     "authorized_keys": { "RSA": 4096, "EC.secp384r1": 384 },
     "authorized_signature_algorithms": ["SHA384withRSA", "SHA512withRSA", "SHA384withECDSA"],
     "authorized_key_usages": ["digital_signature"],
     "authorized_extended_key_usages": ["codeSigning"],
     "common_name_minimum": 1,
     "common_name_maximum": 1,
     "reuse_key": false
   }


ACME Accounts
-------------

Inspect ACME accounts registered against the server. These endpoints are read-only;
ACME clients create and deactivate accounts through the RFC 8555 ``/new-account`` and
account update flows (:doc:`api-reference`). Both endpoints are available to ``admin``
and ``auditor`` roles; the ``auditor`` view omits the full JWK and exposes only the
JWK thumbprint.

**GET** ``/api/accounts``

List ACME accounts with filtering and offset-based pagination.
*admin, auditor*

**Query parameters:**

.. list-table::
   :header-rows: 1

   * - Parameter
     - Type
     - Description
   * - ``status``
     - string
     - Filter by account status. One of ``valid``, ``deactivated``, ``revoked``.
   * - ``eab_only``
     - boolean
     - When ``true``, return only accounts registered via External Account Binding.
       Accepts ``true``/``false``/``1``/``0``.
   * - ``eab_kid``
     - string
     - Return only the account bound to this EAB ``kid``. Implies ``eab_only=true``.
   * - ``contact``
     - string
     - Case-insensitive substring match against registered contact URIs
       (e.g. ``example.com`` matches ``mailto:ops@example.com``).
   * - ``created_before``
     - ISO 8601
     - Only accounts created strictly before this timestamp.
   * - ``created_after``
     - ISO 8601
     - Only accounts created strictly after this timestamp.
   * - ``limit``
     - integer
     - Maximum results to return (default: ``admin_api.default_page_size``, typically 50).
   * - ``offset``
     - integer
     - Offset for pagination (default: 0).

**Response 200 (admin role):**

.. code-block:: json

   [
     {
       "id": "dd0e8400-e29b-41d4-a716-446655440030",
       "jwk_thumbprint": "x8F2...sha256-b64url",
       "jwk": {
         "kty": "EC",
         "crv": "P-256",
         "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
         "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
       },
       "status": "valid",
       "tos_agreed": true,
       "eab_kid": "kid-team-a",
       "created_at": "2026-01-05T09:12:00+00:00",
       "updated_at": "2026-01-05T09:12:00+00:00"
     }
   ]

**Response 200 (auditor role):** same shape as above, but the ``jwk`` field is omitted;
only ``jwk_thumbprint`` is exposed.

**Pagination:** Offset-based with a ``Link`` header when more results are available:

.. code-block:: text

   Link: </api/accounts?limit=50&offset=50>; rel="next"

**Errors:**

* **400** — invalid ``status``, ``eab_only``, ``created_before``, ``created_after``,
  ``limit``, or ``offset``.
* **401** — missing or invalid bearer token.
* **403** — caller lacks the ``admin`` or ``auditor`` role.

**GET** ``/api/accounts/{account_id}``

Get a single ACME account with its registered contacts, bound EAB ``kid`` (if any),
and assigned CSR profile (if any). *admin, auditor*

**Response 200 (admin role):**

.. code-block:: json

   {
     "id": "dd0e8400-e29b-41d4-a716-446655440030",
     "jwk_thumbprint": "x8F2...sha256-b64url",
     "jwk": {
       "kty": "EC",
       "crv": "P-256",
       "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
       "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
     },
     "status": "valid",
     "tos_agreed": true,
     "eab_kid": "kid-team-a",
     "created_at": "2026-01-05T09:12:00+00:00",
     "updated_at": "2026-01-05T09:12:00+00:00",
     "contacts": ["mailto:ops@example.com"],
     "csr_profile_id": "aa0e8400-e29b-41d4-a716-446655440090"
   }

The ``contacts`` array is always present (empty when no contacts are registered).
``csr_profile_id`` is only present when a CSR profile has been assigned to the account
(see :ref:`csr-profile-enforcement`). ``eab_kid`` is ``null`` when the account was not
registered via External Account Binding.

**Response 200 (auditor role):** same shape, but the ``jwk`` field is omitted.

**Errors:**

* **401** — missing or invalid bearer token.
* **403** — caller lacks the ``admin`` or ``auditor`` role.
* **404** — no ACME account with that ID.


Certificates
------------

Search, inspect, and bulk-revoke certificates issued by the ACME server.

**GET** ``/api/certificates``

Search and list certificates with filtering and pagination.
*admin, auditor*

**Query parameters:**

.. list-table::
   :header-rows: 1

   * - Parameter
     - Type
     - Description
   * - ``account_id``
     - UUID
     - Filter by ACME account
   * - ``serial``
     - string
     - Filter by serial number (exact match)
   * - ``fingerprint``
     - string
     - Filter by SHA-256 fingerprint (hex)
   * - ``status``
     - string
     - Filter by status (``active``, ``revoked``, ``expired``)
   * - ``domain``
     - string
     - Filter by SAN domain value
   * - ``expiring_before``
     - ISO 8601
     - Find certificates expiring before this date
   * - ``limit``
     - integer
     - Maximum results to return (default: 50)
   * - ``offset``
     - integer
     - Offset for pagination

**Response 200:**

.. code-block:: json

   [
     {
       "id": "110e8400-e29b-41d4-a716-446655440060",
       "account_id": "dd0e8400-e29b-41d4-a716-446655440030",
       "order_id": "220e8400-e29b-41d4-a716-446655440070",
       "serial_number": "01A2B3C4D5E6F7",
       "fingerprint": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
       "not_before": "2025-06-15T10:00:00Z",
       "not_after": "2025-09-13T10:00:00Z",
       "revoked_at": null,
       "revocation_reason": null,
       "san_values": ["example.com", "www.example.com"],
       "created_at": "2025-06-15T10:00:00Z"
     },
     {
       "id": "110e8400-e29b-41d4-a716-446655440061",
       "account_id": "dd0e8400-e29b-41d4-a716-446655440031",
       "order_id": "220e8400-e29b-41d4-a716-446655440071",
       "serial_number": "02B3C4D5E6F7A8",
       "fingerprint": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
       "not_before": "2025-05-01T08:00:00Z",
       "not_after": "2025-07-30T08:00:00Z",
       "revoked_at": "2025-06-10T16:30:00Z",
       "revocation_reason": "keyCompromise",
       "san_values": ["api.internal.corp"],
       "created_at": "2025-05-01T08:00:00Z"
     }
   ]

**Pagination:** Uses ``Link`` header with offset-based pagination:

.. code-block:: text

   Link: </api/certificates?limit=50&offset=50>; rel="next"

**GET** ``/api/certificates/{serial}``

Get a specific certificate by serial number. *admin, auditor*

**Response 200:**

.. code-block:: json

   {
     "id": "110e8400-e29b-41d4-a716-446655440060",
     "account_id": "dd0e8400-e29b-41d4-a716-446655440030",
     "order_id": "220e8400-e29b-41d4-a716-446655440070",
     "serial_number": "01A2B3C4D5E6F7",
     "fingerprint": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
     "not_before": "2025-06-15T10:00:00Z",
     "not_after": "2025-09-13T10:00:00Z",
     "revoked_at": null,
     "revocation_reason": null,
     "san_values": ["example.com", "www.example.com"],
     "created_at": "2025-06-15T10:00:00Z"
   }

**Error 404:** Certificate not found.

**GET** ``/api/certificates/by-fingerprint/{fingerprint}``

Look up a certificate by its SHA-256 fingerprint (hex-encoded).
*admin, auditor*

**Response 200:**

.. code-block:: json

   {
     "id": "110e8400-e29b-41d4-a716-446655440060",
     "account_id": "dd0e8400-e29b-41d4-a716-446655440030",
     "order_id": "220e8400-e29b-41d4-a716-446655440070",
     "serial_number": "01A2B3C4D5E6F7",
     "fingerprint": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
     "not_before": "2025-06-15T10:00:00Z",
     "not_after": "2025-09-13T10:00:00Z",
     "revoked_at": null,
     "revocation_reason": null,
     "san_values": ["example.com", "www.example.com"],
     "created_at": "2025-06-15T10:00:00Z"
   }

**Error 404:** No certificate found with the given fingerprint.

**POST** ``/api/certificates/bulk-revoke``

Revoke multiple certificates at once using flexible filter criteria. Supports a dry-run mode
to preview which certificates would be affected before committing.
*admin*

**Request body:**

.. code-block:: json

   {
     "filter": {
       "account_id": "dd0e8400-e29b-41d4-a716-446655440030",
       "serial_numbers": ["01A2B3C4D5E6F7", "02B3C4D5E6F7A8"],
       "domain": "example.com",
       "issued_before": "2025-06-01T00:00:00Z",
       "issued_after": "2025-01-01T00:00:00Z"
     },
     "reason": 4,
     "dry_run": false
   }

All filter fields are optional and can be combined. At least one filter field must be provided.
The ``reason`` field uses RFC 5280 revocation reason codes:

.. list-table::
   :header-rows: 1

   * - Code
     - Reason
   * - 0
     - unspecified
   * - 1
     - keyCompromise
   * - 2
     - cACompromise
   * - 3
     - affiliationChanged
   * - 4
     - superseded
   * - 5
     - cessationOfOperation
   * - 9
     - privilegeWithdrawn

**Response 200 (dry_run=true):**

.. code-block:: json

   {
     "dry_run": true,
     "matching_certificates": 5,
     "serial_numbers": [
       "01A2B3C4D5E6F7",
       "02B3C4D5E6F7A8",
       "03C4D5E6F7A8B9",
       "04D5E6F7A8B9CA",
       "05E6F7A8B9CADB"
     ]
   }

**Response 200 (dry_run=false):**

.. code-block:: json

   {
     "revoked": 5,
     "errors": [],
     "total_matched": 5
   }

If some certificates fail to revoke, they are listed in the ``errors`` array:

.. code-block:: json

   {
     "revoked": 3,
     "errors": [
       {"serial_number": "04D5E6F7A8B9CA", "error": "already revoked"},
       {"serial_number": "05E6F7A8B9CADB", "error": "CA backend error"}
     ],
     "total_matched": 5
   }

**Error 400:** Missing ``filter`` field, empty filter object, or invalid reason code.


Notifications
-------------

View and manage notification delivery. Notifications are sent for events such as certificate
expiration warnings, revocations, and other administrative events.

**GET** ``/api/notifications``

List notifications with filtering and pagination. *admin*

**Query parameters:**

.. list-table::
   :header-rows: 1

   * - Parameter
     - Type
     - Description
   * - ``status``
     - string
     - Filter by status (``pending``, ``sent``, ``failed``)
   * - ``limit``
     - integer
     - Maximum results to return (default: 50)
   * - ``offset``
     - integer
     - Offset for pagination

**Response 200:**

.. code-block:: json

   [
     {
       "id": "330e8400-e29b-41d4-a716-446655440080",
       "notification_type": "expiration_warning",
       "recipient": "admin@example.com",
       "subject": "Certificate expiring: example.com",
       "status": "sent",
       "account_id": "dd0e8400-e29b-41d4-a716-446655440030",
       "error_detail": null,
       "retry_count": 0,
       "created_at": "2025-06-15T06:00:00Z",
       "sent_at": "2025-06-15T06:00:05Z"
     },
     {
       "id": "330e8400-e29b-41d4-a716-446655440081",
       "notification_type": "revocation_succeeded",
       "recipient": "ops@example.com",
       "subject": "Certificate revoked: api.internal.corp",
       "status": "failed",
       "account_id": "dd0e8400-e29b-41d4-a716-446655440031",
       "error_detail": "SMTP connection timeout",
       "retry_count": 3,
       "created_at": "2025-06-10T16:30:00Z",
       "sent_at": null
     }
   ]

**POST** ``/api/notifications/retry``

Retry all failed notifications. Resets the retry count and re-queues failed notifications
for delivery. *admin*

**Response 200:**

.. code-block:: json

   {
     "retried": 5
   }

**POST** ``/api/notifications/purge``

Purge old notifications older than the specified number of days.
*admin*

**Request body (optional):**

.. code-block:: json

   {
     "days": 30
   }

If omitted, defaults to 30 days.

**Response 200:**

.. code-block:: json

   {
     "purged": 100
   }

**Error 400:** ``days`` must be at least 1.


CRL Management
--------------

Manage the Certificate Revocation List. Requires ``crl.enabled: true`` in the server
configuration.

**POST** ``/api/crl/rebuild``

Force an immediate CRL rebuild. Returns the current CRL health status after rebuild.
*admin*

**Response 200:** CRL health status object with details about the rebuilt CRL.

**Error 503:** CRL subsystem is not enabled in the server configuration.


Maintenance Mode
----------------

Toggle maintenance mode for the ACME server. When maintenance mode is enabled, new order
and pre-authorization requests return ``503 Service Unavailable`` with a ``Retry-After``
header. In-progress operations (order finalization, challenge validation, certificate
downloads, account operations) are allowed to complete. The Admin API remains accessible
during maintenance.

**GET** ``/api/maintenance``

Get the current maintenance mode status. *admin*

**Response 200:**

.. code-block:: json

   {
     "maintenance_mode": false
   }

**POST** ``/api/maintenance``

Enable or disable maintenance mode. When enabled, new order and pre-authorization
requests return ``503 Service Unavailable`` to clients while in-progress operations
(order finalization, challenge validation, certificate downloads) are allowed to complete.
The Admin API remains fully accessible. *admin*

**Request body:**

.. code-block:: json

   {
     "enabled": true
   }

**Response 200:**

.. code-block:: json

   {
     "maintenance_mode": true
   }

To disable maintenance mode:

.. code-block:: json

   {
     "enabled": false
   }

**Response 200:**

.. code-block:: json

   {
     "maintenance_mode": false
   }

**Error 400:** Missing ``enabled`` field.


Error Responses
---------------

Admin API errors are returned as JSON objects with an appropriate HTTP status code:

.. code-block:: json

   {
     "error": "Unauthorized",
     "message": "Invalid or expired token"
   }

Common error status codes:

.. list-table::
   :header-rows: 1

   * - Status
     - Meaning
   * - ``400``
     - Bad Request --- missing or invalid fields in the request body
   * - ``401``
     - Unauthorized --- missing, invalid, or expired bearer token
   * - ``403``
     - Forbidden --- authenticated but insufficient role for this endpoint
   * - ``404``
     - Not Found --- requested resource does not exist
   * - ``429``
     - Too Many Requests --- rate limit exceeded (login endpoint)
   * - ``503``
     - Service Unavailable --- required subsystem not enabled (e.g., CRL)
