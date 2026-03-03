===========
CA Backends
===========

*Certificate signing backends: internal, external, HSM, ACME proxy, and custom*

ACMEEH supports multiple CA backends for signing certificates. The backend is selected
via ``ca.backend`` in the configuration. All backends implement the ``CABackend``
abstract base class with ``sign()`` and ``revoke()`` methods.

.. list-table::
   :header-rows: 1
   :widths: 15 35 25

   * - Backend
     - Use Case
     - Key Storage
   * - ``internal``
     - File-based root CA signing
     - PEM files on disk
   * - ``external``
     - Delegate to HTTP API (e.g., Vault, EJBCA)
     - Remote system
   * - ``hsm``
     - Hardware Security Module via PKCS#11
     - HSM device
   * - ``acme_proxy``
     - Proxy to upstream ACME CA (e.g., Let's Encrypt)
     - Upstream CA
   * - ``ext:<path>``
     - Custom plugin class
     - User-defined

CABackend Interface
-------------------

All CA backends extend the ``CABackend`` abstract base class defined in
``acmeeh.ca.base``. A backend must implement the two abstract methods
(``sign`` and ``revoke``) and may optionally override ``startup_check``.

Abstract Methods (must implement)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

sign(csr, \*, profile, validity_days, serial_number=None, ct_submitter=None) -> IssuedCertificate
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Sign a parsed ``x509.CertificateSigningRequest`` object and return an ``IssuedCertificate``.
The ``profile`` parameter selects the certificate profile (key usages, extended key usages).
``validity_days`` controls the certificate lifetime. ``serial_number`` may be
pre-assigned by the caller; if ``None``, the backend generates one. ``ct_submitter``
is an optional Certificate Transparency submitter used by backends that support CT pre-certificate flow.

revoke(\*, serial_number, certificate_pem, reason=None) -> None
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Revoke a previously issued certificate. ``serial_number`` is the hex-encoded serial.
``certificate_pem`` is the full PEM of the certificate to revoke. ``reason``
is an optional ``RevocationReason`` enum value (per RFC 5280, e.g., ``unspecified``, ``keyCompromise``).

Optional Methods
^^^^^^^^^^^^^^^^

startup_check() -> None
"""""""""""""""""""""""

Called once on application startup to verify backend connectivity and configuration.
The default implementation is a no-op. Backends should raise ``CAError`` if
the check fails (e.g., HSM token not reachable, external API unreachable).

deferred (property) -> bool
"""""""""""""""""""""""""""

Indicates whether ``sign()`` may block for an unbounded amount of time (e.g., waiting
for upstream DNS propagation or external approval). When a backend returns ``True``,
the order finalization handler runs ``sign()`` in a background thread and returns
the order with status ``processing`` (RFC 8555 §7.4) so the HTTP request is not blocked.

The default implementation returns ``False``. The built-in ``acme_proxy`` backend
overrides this to return ``True``.

IssuedCertificate Dataclass
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Returned by ``sign()`` on success:

.. list-table::
   :header-rows: 1
   :widths: 20 15 45

   * - Field
     - Type
     - Description
   * - ``pem_chain``
     - ``str``
     - Full PEM certificate chain (leaf + intermediates)
   * - ``not_before``
     - ``datetime``
     - Certificate validity start
   * - ``not_after``
     - ``datetime``
     - Certificate validity end
   * - ``serial_number``
     - ``str``
     - Hex-encoded serial number
   * - ``fingerprint``
     - ``str``
     - SHA-256 hex digest of leaf certificate DER

CAError Exception
^^^^^^^^^^^^^^^^^

Raised by backends on failure. The ``retryable`` flag indicates whether the operation may succeed if retried:

.. list-table::
   :header-rows: 1
   :widths: 15 10 10 45

   * - Field
     - Type
     - Default
     - Description
   * - ``detail``
     - ``str``
     -  ---
     - Human-readable failure description
   * - ``retryable``
     - ``bool``
     - ``False``
     - Whether the failure is transient

.. note::

   **Retryable vs. Non-Retryable**

   A retryable ``CAError`` signals a transient failure (network timeout, temporary unavailability).
   The circuit breaker counts only retryable errors toward its failure threshold. Non-retryable errors
   (invalid CSR, permission denied) are passed through immediately.

Internal Backend
----------------

The internal backend signs certificates directly using a root CA certificate and private key
stored as PEM files on disk. This is the simplest backend and works well for development
and small-scale internal PKI deployments.

Configuration
^^^^^^^^^^^^^

.. code-block:: yaml

   ca:
     backend: internal
     default_validity_days: 90
     max_validity_days: 397
     internal:
       root_cert_path: /etc/acmeeh/ca/root-ca.pem
       root_key_path: /etc/acmeeh/ca/root-ca-key.pem
       chain_path: /etc/acmeeh/ca/chain.pem       # optional intermediate chain
       serial_source: database                   # database or random
       hash_algorithm: sha256                    # sha256, sha384, sha512

.. list-table::
   :header-rows: 1
   :widths: 20 15 45

   * - Field
     - Default
     - Description
   * - ``root_cert_path``
     - ``""``
     - Path to the CA certificate PEM file
   * - ``root_key_path``
     - ``""``
     - Path to the CA private key PEM file
   * - ``chain_path``
     - ``null``
     - Optional intermediate certificate chain
   * - ``serial_source``
     - ``database``
     - Serial number generation: ``database`` (sequential) or ``random``
   * - ``hash_algorithm``
     - ``sha256``
     - Signature hash algorithm

.. warning::

   **Security Note**

   The private key file must be readable only by the ACMEEH process. Set file permissions to ``0600`` or ``0400``.

Serial Numbers
^^^^^^^^^^^^^^

Serial numbers are generated per RFC 5280: a random 20-byte value with the high bit cleared
(maximum 159 bits), ensuring positive ASN.1 INTEGER encoding. Two sources are available:

- ``database`` --- Sequential serial numbers allocated from the database. Guarantees uniqueness across multiple ACMEEH instances sharing the same database.
- ``random`` --- Cryptographically random 20-byte values. Suitable for single-instance deployments.

Certificate Transparency Support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The internal backend supports Certificate Transparency (CT) pre-certificate flow when CT logging
is enabled (``ct_logging.enabled: true`` in the configuration). The signing process works
as follows:

#. A pre-certificate is built with the CT poison extension (OID ``1.3.6.1.4.1.11129.2.4.3``) and signed by the issuer.
#. The pre-certificate is submitted to the configured CT logs.
#. Received SCTs (Signed Certificate Timestamps) are embedded in the final certificate as an SCT list extension (OID ``1.3.6.1.4.1.11129.2.4.2``).
#. The final certificate (with embedded SCTs) is signed by the issuer and returned.

If no SCTs are received from any configured CT log, the backend falls back to standard signing without embedded SCTs.

External Backend
----------------

The external backend delegates certificate signing and revocation to a remote HTTP API.
This is useful for integrating with existing PKI infrastructure like HashiCorp Vault,
EJBCA, or any custom signing service.

Configuration
^^^^^^^^^^^^^

.. code-block:: yaml

   ca:
     backend: external
     external:
       sign_url: https://vault.internal:8200/v1/pki/sign/acmeeh
       revoke_url: https://vault.internal:8200/v1/pki/revoke
       auth_header: X-Vault-Token
       auth_value: ${VAULT_TOKEN}
       ca_cert_path: /etc/acmeeh/ca/vault-ca.pem
       client_cert_path: /etc/acmeeh/tls/client.pem   # optional mTLS
       client_key_path: /etc/acmeeh/tls/client-key.pem
       timeout_seconds: 30
       max_retries: 3
       retry_delay_seconds: 1.0

.. list-table::
   :header-rows: 1
   :widths: 20 20 40

   * - Field
     - Default
     - Description
   * - ``sign_url``
     - ``""``
     - URL of the signing endpoint
   * - ``revoke_url``
     - ``""``
     - URL of the revocation endpoint
   * - ``auth_header``
     - ``Authorization``
     - Authentication header name
   * - ``auth_value``
     - ``""``
     - Authentication header value
   * - ``ca_cert_path``
     - ``null``
     - CA certificate for TLS verification
   * - ``client_cert_path``
     - ``null``
     - Client certificate for mTLS
   * - ``client_key_path``
     - ``null``
     - Client key for mTLS
   * - ``timeout_seconds``
     - ``30``
     - HTTP request timeout
   * - ``max_retries``
     - ``0``
     - Retry count on failure
   * - ``retry_delay_seconds``
     - ``1.0``
     - Delay between retries

API Contract
^^^^^^^^^^^^

The external backend communicates with the remote signing service using a simple JSON-over-HTTP protocol.
Below is the exact request and response format for each operation.

Sign Request (POST to sign_url)
"""""""""""""""""""""""""""""""

.. code-block:: json

   {
     "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
     "profile": "default",
     "validity_days": 90
   }

Sign Response (HTTP 200)
""""""""""""""""""""""""

.. code-block:: json

   {
     "certificate_chain": "-----BEGIN CERTIFICATE-----\n..."
   }

The ``certificate_chain`` field contains the full PEM chain (leaf certificate followed by any intermediates), concatenated.

Revoke Request (POST to revoke_url)
""""""""""""""""""""""""""""""""""""

.. code-block:: json

   {
     "serial_number": "0a1b2c...",
     "reason": 0
   }

Revoke Response
"""""""""""""""

HTTP 200 on success. No response body is required.

Error Handling and Retries
^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Retryable errors:** HTTP 5xx responses and network errors (connection refused, timeout). These raise a ``CAError`` with ``retryable=True``.
- **Non-retryable errors:** HTTP 4xx responses. These raise a ``CAError`` with ``retryable=False``.
- **Retry strategy:** Exponential backoff calculated as ``retry_delay_seconds * 2^attempt`` (e.g., 1s, 2s, 4s for a 1-second base delay).

.. tip::

   **Optional Revocation**

   If ``revoke_url`` is not configured, revocation requests are logged as a warning but do not
   fail. This is useful when the remote signing service does not support revocation or when revocation
   is handled out-of-band.

HSM Backend
-----------

The HSM backend uses a PKCS#11 interface to sign certificates with keys stored in a
Hardware Security Module. This provides the highest level of private key protection.

.. note::

   **Additional Dependency**

   Install the ``python-pkcs11`` package: ``pip install python-pkcs11``

Configuration
^^^^^^^^^^^^^

.. code-block:: yaml

   ca:
     backend: hsm
     hsm:
       pkcs11_library: /usr/lib/softhsm/libsofthsm2.so
       token_label: acmeeh-signing
       pin: ${HSM_PIN}
       key_label: signing-key
       key_type: ec                              # ec or rsa
       hash_algorithm: sha256
       issuer_cert_path: /etc/acmeeh/ca/issuer.pem
       chain_path: /etc/acmeeh/ca/chain.pem
       serial_source: database
       login_required: true
       session_pool_size: 4
       session_pool_timeout_seconds: 30

.. list-table::
   :header-rows: 1
   :widths: 30 15 40

   * - Field
     - Default
     - Description
   * - ``pkcs11_library``
     - ``""``
     - Path to the PKCS#11 shared library
   * - ``token_label``
     - ``null``
     - Token label (use this or ``slot_id``)
   * - ``slot_id``
     - ``null``
     - Slot ID (alternative to ``token_label``)
   * - ``pin``
     - ``""``
     - Token PIN
   * - ``key_label``
     - ``null``
     - Key label (use this or ``key_id``)
   * - ``key_id``
     - ``null``
     - Key ID (alternative to ``key_label``)
   * - ``key_type``
     - ``ec``
     - Key type: ``ec`` or ``rsa``
   * - ``hash_algorithm``
     - ``sha256``
     - Hash algorithm: sha256, sha384, sha512
   * - ``issuer_cert_path``
     - ``""``
     - Path to the issuer certificate PEM
   * - ``chain_path``
     - ``null``
     - Optional intermediate chain
   * - ``serial_source``
     - ``database``
     - Serial number source
   * - ``login_required``
     - ``true``
     - Require PIN login to token
   * - ``session_pool_size``
     - ``4``
     - PKCS#11 session pool size
   * - ``session_pool_timeout_seconds``
     - ``30``
     - Session acquisition timeout

How HSM Signing Works
^^^^^^^^^^^^^^^^^^^^^

The HSM backend uses a "dummy-key-then-re-sign" pattern:

#. Build the certificate with an ephemeral key and sign it locally
#. Extract the TBS (To-Be-Signed) certificate data
#. Send the TBS data to the HSM for signing via PKCS#11
#. Reassemble the final DER-encoded certificate with the HSM signature

This approach allows using the standard ``cryptography`` library for certificate building while keeping the private key exclusively in the HSM.

ACME Proxy Backend
------------------

The ACME proxy backend acts as a client to an upstream ACME CA (like Let's Encrypt)
to obtain certificates. This allows ACMEEH to serve as a unified ACME front-end while
delegating actual issuance to a public CA.

Configuration
^^^^^^^^^^^^^

.. code-block:: yaml

   ca:
     backend: acme_proxy
     acme_proxy:
       directory_url: https://acme-v02.api.letsencrypt.org/directory
       email: admin@example.com
       storage_path: /var/lib/acmeeh/acme-proxy
       challenge_type: dns-01
       challenge_handler: my_dns.CloudflareDNS
       challenge_handler_config:
         api_token: ${CF_API_TOKEN}
       eab_kid: ${ACME_EAB_KID:-}
       eab_hmac_key: ${ACME_EAB_HMAC:-}
       proxy_url: null                        # optional HTTP proxy
       verify_ssl: true
       timeout_seconds: 300

.. list-table::
   :header-rows: 1
   :widths: 25 20 40

   * - Field
     - Default
     - Description
   * - ``directory_url``
     - ``""``
     - Upstream ACME directory URL
   * - ``email``
     - ``""``
     - Contact email for upstream account
   * - ``storage_path``
     - ``./acme_proxy_storage``
     - Local storage for account keys and state
   * - ``challenge_type``
     - ``dns-01``
     - Challenge type for upstream validation
   * - ``challenge_handler``
     - ``""``
     - Python class path for challenge handling
   * - ``challenge_handler_config``
     - ``{}``
     - Config dict passed to challenge handler
   * - ``eab_kid``
     - ``null``
     - EAB Key ID (if upstream requires External Account Binding)
   * - ``eab_hmac_key``
     - ``null``
     - EAB HMAC key (base64url-encoded)
   * - ``proxy_url``
     - ``null``
     - HTTP proxy for upstream requests
   * - ``verify_ssl``
     - ``true``
     - Verify upstream TLS certificates
   * - ``timeout_seconds``
     - ``300``
     - Request timeout

Behavioral Notes
^^^^^^^^^^^^^^^^

- The ``profile`` and ``validity_days`` parameters are accepted by the ``sign()`` method but are ignored --- the upstream CA determines the certificate profile and validity period.
- Certificate Transparency logging is handled entirely by the upstream CA, not by ACMEEH.
- All operations (sign and revoke) are serialized with a thread lock for safety, since the underlying ACME client library is not thread-safe.
- Revocation is best-effort: failures are logged but do not raise errors back to the caller.
- EAB credentials (``eab_kid`` and ``eab_hmac_key``) are configured on the ACMEOW client via ``set_external_account_binding()`` before account registration. If the upstream CA requires EAB, both fields must be set.
- The ``acme_proxy`` backend sets ``deferred=True``, so order finalization runs ``sign()`` in a background thread. The thread timeout is controlled by ``ca.deferred_signing_timeout`` (default: 600 seconds). This prevents slow upstream CA operations (DNS propagation, approval workflows) from triggering gunicorn worker timeouts.

.. note::

   **Dependency**

   The ACME proxy backend requires the ACMEOW library (``pip install acmeow``).
   The ``directory_url`` and ``email`` config fields map to the ``server_url`` and ``email``
   parameters of the ACMEOW ``AcmeClient`` constructor.

Custom Backend
--------------

Load a custom CA backend from any Python package using the ``ext:`` prefix.
Your class must extend ``CABackend`` from ``acmeeh.ca.base``.

Configuration
^^^^^^^^^^^^^

.. code-block:: yaml

   ca:
     backend: ext:mycompany.pki.VaultBackend

Implementation
^^^^^^^^^^^^^^

.. code-block:: python

   from acmeeh.ca.base import CABackend, IssuedCertificate

   class VaultBackend(CABackend):
       def __init__(self, ca_settings):
           # ca_settings is the CASettings object (ca section of config)
           super().__init__(ca_settings)
           ...

       def sign(self, csr, *, profile, validity_days,
                serial_number=None, ct_submitter=None):
           # csr is a parsed x509.CertificateSigningRequest object
           # Sign the CSR and return an IssuedCertificate
           return IssuedCertificate(
               pem_chain=cert_pem,
               not_before=not_before,
               not_after=not_after,
               serial_number=serial_hex,
               fingerprint=fingerprint_hex,
           )

       def revoke(self, *, serial_number, certificate_pem, reason=None):
           # Revoke a certificate
           ...

       def startup_check(self):
           # Optional: verify connectivity on startup
           ...

Circuit Breaker
---------------

All CA backends are wrapped with a circuit breaker that prevents cascading failures.
After ``circuit_breaker_failure_threshold`` consecutive failures, the circuit
opens and requests fail immediately for ``circuit_breaker_recovery_timeout``
seconds before attempting recovery.

.. code-block:: yaml

   ca:
     circuit_breaker_failure_threshold: 5
     circuit_breaker_recovery_timeout: 30

State Machine
^^^^^^^^^^^^^

The circuit breaker operates as a three-state machine:

.. list-table::
   :header-rows: 1
   :widths: 15 40 40

   * - State
     - Behavior
     - Transition
   * - **CLOSED**
     - Normal operation. All requests pass through to the backend. Consecutive failures are counted.
     - After ``failure_threshold`` consecutive retryable failures, transitions to **OPEN**.
   * - **OPEN**
     - Requests fail immediately with a retryable ``CAError`` without contacting the backend.
     - After ``recovery_timeout`` seconds elapse, transitions to **HALF_OPEN**.
   * - **HALF_OPEN**
     - A single probe request is allowed through to test if the backend has recovered.
     - On success, transitions to **CLOSED** and resets the failure counter. On failure, transitions back to **OPEN**.

.. warning::

   **Only Retryable Errors Count**

   Only retryable ``CAError`` exceptions count toward the failure threshold. Non-retryable errors
   (such as invalid CSR or permission denied) are passed through to the caller without affecting the
   circuit breaker state.

Failover Backend
----------------

The failover backend wraps multiple CA backends and tries them in order. If a backend
returns a retryable error, the next backend in the list is attempted. This provides
automatic failover for high-availability deployments.

Behavior
^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 15 65

   * - Operation
     - Behavior
   * - ``sign()``
     - Tries backends in order. Stops on the first success or non-retryable error. Falls through to the next backend only on retryable errors. Raises the last error if all backends fail.
   * - ``revoke()``
     - Best-effort across all backends. Attempts revocation on every backend regardless of individual failures. Raises the last error only if all backends fail.
   * - ``startup_check()``
     - Checks all backends. Requires at least one backend to be healthy. Logs warnings for unhealthy backends but does not fail unless all are unreachable.

The failover backend tracks health status per backend after each operation, allowing it to
prioritize healthy backends in subsequent requests.

.. note::

   **Internal Use**

   The failover backend is used internally when multiple backends are configured. It is not
   configured directly via ``ca.backend`` but is automatically engaged by the backend
   registry when appropriate.

Certificate Profiles
--------------------

Profiles control the key usages, extended key usages, and validity of issued certificates.
A ``default`` profile is always available. Custom profiles can be defined and assigned
per-account via the admin API.

.. code-block:: yaml

   ca:
     profiles:
       default:
         key_usages: [digital_signature, key_encipherment]
         extended_key_usages: [server_auth]
       client_auth:
         key_usages: [digital_signature]
         extended_key_usages: [client_auth]
         validity_days: 365
         max_validity_days: 730
       code_signing:
         key_usages: [digital_signature]
         extended_key_usages: [code_signing]
         validity_days: 180

.. list-table::
   :header-rows: 1
   :widths: 25 10 50

   * - Field
     - Required
     - Description
   * - ``key_usages``
     - Yes
     - List of key usage flags (e.g., ``digital_signature``, ``key_encipherment``, ``key_agreement``)
   * - ``extended_key_usages``
     - Yes
     - List of extended key usage OIDs (e.g., ``server_auth``, ``client_auth``, ``code_signing``)
   * - ``validity_days``
     - No
     - Profile-specific certificate validity in days. Overrides ``ca.default_validity_days`` for certificates issued under this profile.
   * - ``max_validity_days``
     - No
     - Profile-specific maximum validity in days. Overrides ``ca.max_validity_days`` for this profile. Requests exceeding this value are clamped.

.. tip::

   **Validity Precedence**

   When a profile defines ``validity_days``, it takes precedence over the global
   ``ca.default_validity_days``. Similarly, ``max_validity_days`` on a profile
   overrides the global ``ca.max_validity_days``. If neither is set on the profile,
   the global values are used.

Certificate Extensions
----------------------

The internal and HSM backends add the following X.509v3 extensions to issued certificates.
External and ACME proxy backends delegate extension handling to the remote signing service
or upstream CA respectively.

.. list-table::
   :header-rows: 1
   :widths: 25 10 50

   * - Extension
     - Critical
     - Source / Value
   * - **Subject Alternative Name** (SAN)
     - No
     - Populated from the CSR. Contains DNS names and/or IP addresses as requested by the client.
   * - **Basic Constraints**
     - Yes
     - ``ca=false``. Issued certificates are always end-entity certificates.
   * - **Key Usage**
     - Yes
     - Determined by the certificate profile (e.g., ``digital_signature``, ``key_encipherment``).
   * - **Extended Key Usage**
     - No
     - Determined by the certificate profile (e.g., ``server_auth``, ``client_auth``).
   * - **Authority Key Identifier**
     - No
     - Derived from the issuer (CA) certificate. Allows clients to chain certificates to the correct issuer.
   * - **Subject Key Identifier**
     - No
     - Derived from the public key in the CSR, per RFC 5280.

Subject Common Name
^^^^^^^^^^^^^^^^^^^

The certificate Subject CN (Common Name) is automatically set to the first DNS name from the
Subject Alternative Name extension. If no DNS names are present (e.g., an IP-only certificate),
the first IP address is used instead. This ensures the Subject CN is always populated for
compatibility with legacy clients that do not support SAN-based validation.

Testing the Backend
-------------------

Use the CLI to verify your CA backend works correctly:

.. code-block:: bash

   # Test signing with an ephemeral CSR
   PYTHONPATH=src python -m acmeeh -c config.yaml ca test-sign

This creates a temporary CSR, submits it to the configured backend, and reports success or failure.
