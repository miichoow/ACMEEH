# ACMEEH Configuration Examples

Each YAML file is a self-contained, valid configuration targeting a specific deployment scenario or feature. Copy one as a starting point and adapt it to your needs.

## Quick Start

```bash
# Validate a config without starting the server
PYTHONPATH=src .venv/Scripts/python.exe -m acmeeh -c examples/minimal.yaml --validate-only

# Run with a config
PYTHONPATH=src DB_PASSWORD=secret .venv/Scripts/python.exe -m acmeeh -c examples/development.yaml --dev
```

## Example Index

### Deployment Scenarios

| File | Description |
|------|-------------|
| [`minimal.yaml`](minimal.yaml) | Bare minimum — only required fields. Good starting template. |
| [`development.yaml`](development.yaml) | Local dev: single worker, DEBUG logs, relaxed limits, auto DB setup. |
| [`production-internal-ca.yaml`](production-internal-ca.yaml) | Full production with internal CA, hardened security, email, hooks, TOS. |
| [`docker-compose.yaml`](docker-compose.yaml) | Docker Compose: container hostnames, env vars, auto DB setup. |
| [`behind-reverse-proxy.yaml`](behind-reverse-proxy.yaml) | Behind nginx/HAProxy: trusted proxies, base path, forwarded headers. |
| [`gevent-workers.yaml`](gevent-workers.yaml) | High-concurrency with gevent async workers. |

### CA Backends

| File | Description |
|------|-------------|
| [`external-ca.yaml`](external-ca.yaml) | External CA via HTTP API (e.g., Vault PKI) with mTLS client auth. |
| [`acme-proxy-eab.yaml`](acme-proxy-eab.yaml) | ACME proxy: forward to upstream CA via ACMEOW, EAB both sides, admin API, allowlists. |
| [`custom-ca-plugin.yaml`](custom-ca-plugin.yaml) | Custom CA plugin loaded via `ext:package.module.Class`. |
| [`hsm-backend.yaml`](hsm-backend.yaml) | HSM CA backend via PKCS#11 with session pool. |
| [`certificate-profiles.yaml`](certificate-profiles.yaml) | Multiple cert profiles: web, client-auth, dual-purpose, code-signing, short-lived. |

### Challenges

| File | Description |
|------|-------------|
| [`all-challenge-types.yaml`](all-challenge-types.yaml) | All three built-in types: http-01, dns-01, tls-alpn-01. |
| [`custom-challenge-validator.yaml`](custom-challenge-validator.yaml) | Custom challenge validator plugin via `ext:` prefix. |

### Security & Policy

| File | Description |
|------|-------------|
| [`strict-security.yaml`](strict-security.yaml) | Maximum hardening: ECDSA-only, no wildcards, EAB, tight rate limits. |
| [`ip-certificates.yaml`](ip-certificates.yaml) | Allow IP address identifiers in certificates. |
| [`admin-api.yaml`](admin-api.yaml) | Admin API with EAB management, allowlists, and CSR profiles. |

### Operations & Monitoring

| File | Description |
|------|-------------|
| [`metrics-prometheus.yaml`](metrics-prometheus.yaml) | Prometheus `/metrics` endpoint with a production-like proxy setup. |
| [`retention-cleanup.yaml`](retention-cleanup.yaml) | All retention/cleanup settings: order, authz, challenge max-age, and audit retention. |
| [`audit-export.yaml`](audit-export.yaml) | Audit export via webhook and syslog, combined with audit retention and local audit logging. |
| [`background-workers.yaml`](background-workers.yaml) | Challenge background worker, expiration warnings, and stale-order detection. |
| [`quotas-rate-limits.yaml`](quotas-rate-limits.yaml) | Quota/rate-limit tuning: all sub-keys, database backend, per-identifier limits, account allowlist. |

### Features

| File | Description |
|------|-------------|
| [`hooks-all-events.yaml`](hooks-all-events.yaml) | Lifecycle hooks: all 10 event types with real-world hook examples. |
| [`email-notifications.yaml`](email-notifications.yaml) | Full SMTP + email validation + notification retry configuration. |
| [`custom-acme-paths.yaml`](custom-acme-paths.yaml) | Remapped ACME endpoint paths with API base path prefix. |
| [`environment-variables.yaml`](environment-variables.yaml) | All `${VAR}` / `${VAR:-default}` substitution patterns. |
| [`crl-ari.yaml`](crl-ari.yaml) | CRL publishing and ACME Renewal Information. |
| [`ct-logging.yaml`](ct-logging.yaml) | Certificate Transparency log submission with SCT embedding. |

## Configuration Sections Reference

Every section is optional except `server` (with `external_url`) and `database` (with `database` and `user`).

| Section | Purpose | Key Options |
|---------|---------|-------------|
| `server` | ACME server bind/port, gunicorn workers | `external_url`, `workers`, `worker_class`, `timeout` |
| `proxy` | Reverse proxy support | `enabled`, `trusted_proxies`, header names |
| `security` | Algorithms, key sizes, rate limits, domain policy | `allowed_algorithms`, `rate_limits`, `identifier_policy` |
| `acme` | ACME protocol settings | `paths`, `eab_required`, `caa_identities`, `website_url` |
| `api` | Flask routing | `base_path` |
| `challenges` | Challenge validator config | `enabled` list, `http01`, `dns01`, `tlsalpn01` sub-configs |
| `ca` | Certificate authority backend | `backend`, `profiles`, `internal`, `external` |
| `dns` | Global DNS resolver settings | `resolvers`, `timeout_seconds`, `retries` |
| `email` | Contact email policy | `require_contact`, `allowed_domains`, `validate_mx` |
| `smtp` | Outbound mail relay | `host`, `port`, `use_tls`, `from_address` |
| `logging` | Log level/format, audit logging | `level`, `format`, `audit.file`, `audit.syslog` |
| `database` | PostgreSQL connection | `host`, `sslmode`, `max_connections`, `auto_setup` |
| `notifications` | Notification queue processing | `max_retries`, `batch_size`, `retry_interval_seconds` |
| `hooks` | Lifecycle hook plugins | `registered[]` with `class`, `events`, `config` |
| `nonce` | Replay nonce settings | `expiry_seconds`, `length` (min 16) |
| `order` | Order/authorization lifetimes | `expiry_seconds`, `authorization_expiry_seconds` |
| `tos` | Terms of Service enforcement | `url`, `require_agreement` |
| `admin_api` | Admin REST API for EAB, allowlists, CSR profiles | `enabled`, `base_path`, `token_secret`, `initial_admin_email` |
| `crl` | Certificate Revocation List publishing | `enabled`, `path`, `rebuild_interval_seconds` |
| `ari` | ACME Renewal Information (RFC draft) | `enabled`, `path`, `renewal_percentage` |
| `ct_logging` | Certificate Transparency log submission | `enabled`, `logs[]`, `submit_precert` |
| `metrics` | Prometheus metrics endpoint | `enabled`, `path` |
| `account` | Account management settings | `allow_contact_update`, `allow_deactivation` |
| `quotas` | Per-account certificate/order quotas | `enabled`, `max_certificates_per_account_per_day` |
| `audit_retention` | Audit log retention policy | `enabled`, `max_age_days`, `cleanup_interval_seconds` |
| `audit_export` | External audit event export | `webhook_url`, `syslog_host`, `syslog_port` |
| `retention` | Cleanup of expired orders/authz/challenges | `enabled`, interval and max-age settings |
