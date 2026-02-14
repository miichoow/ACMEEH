# ACMEEH

**Enterprise ACME (RFC 8555) server for internal PKI**

[![Tests](https://github.com/miichoow/ACMEEH/actions/workflows/test.yml/badge.svg)](https://github.com/miichoow/ACMEEH/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/acmeeh)](https://pypi.org/project/acmeeh/)
[![Python](https://img.shields.io/pypi/pyversions/acmeeh)](https://pypi.org/project/acmeeh/)
[![License](https://img.shields.io/github/license/miichoow/ACMEEH)](LICENSE)
[![Codecov](https://img.shields.io/codecov/c/github/miichoow/ACMEEH)](https://codecov.io/gh/miichoow/ACMEEH)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Docker](https://img.shields.io/docker/v/miichoow/acmeeh?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/miichoow/acmeeh)
[![Docker Image Size](https://img.shields.io/docker/image-size/miichoow/acmeeh?sort=semver)](https://hub.docker.com/r/miichoow/acmeeh)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://miichoow.github.io/ACMEEH/)

[Documentation](https://miichoow.github.io/ACMEEH/) |
[PyPI](https://pypi.org/project/acmeeh/) |
[Docker Hub](https://hub.docker.com/r/miichoow/acmeeh) |
[GitHub](https://github.com/miichoow/ACMEEH)

---

## Overview

ACMEEH is a production-ready ACME server built for organizations that need automated certificate management on their internal network. It fully implements [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) and is compatible with every standards-compliant ACME client — [certbot](https://certbot.eff.org/), [acme.sh](https://acme.sh/), [Caddy](https://caddyserver.com/), [Traefik](https://traefik.io/), [Lego](https://go-acme.github.io/lego/), and others.

Plug in your own CA — a local root key, an HSM, HashiCorp Vault, or an upstream ACME provider — and ACMEEH handles the rest: challenge validation, certificate issuance, revocation, CRL/OCSP distribution, renewal information, and lifecycle hooks.

Built with Python 3.12+, Flask, PostgreSQL, and gunicorn.

## Features

- **Pluggable CA Backends** — Internal file-based CA, external HTTP API (Vault, EJBCA), PKCS#11 HSM, ACME proxy to upstream CA, or bring your own with `ext:` plugins. All backends include a circuit breaker for resilience.
- **Challenge Validation** — HTTP-01, DNS-01, and TLS-ALPN-01 with configurable timeouts, retries, and background validation workers.
- **Revocation Infrastructure** — Built-in CRL generation, OCSP responder, and ACME Renewal Information (ARI) — each independently toggleable.
- **Admin REST API** — Token-authenticated API for user management, audit logs, EAB credentials, identifier allowlists, CSR profiles, certificate search, bulk revocation, and maintenance mode.
- **Hook System** — 10 lifecycle events (account registration, order creation, challenge validation, certificate issuance/revocation/delivery, CT submission) with pluggable handlers.
- **Security Controls** — Per-endpoint rate limiting, key size and algorithm policies, identifier allowlists, External Account Binding (EAB), CAA enforcement (RFC 8659), CSR validation profiles, and per-account quotas.
- **Prometheus Metrics** — `/metrics` endpoint for certificate counts, issuance rates, challenge stats, and CA backend health.
- **Email Notifications** — SMTP alerts for certificate expiration with configurable warning days, retry with backoff, and Jinja2 templates.
- **Certificate Transparency** — RFC 6962 pre-certificate submission to multiple CT logs with SCT collection.
- **Structured Logging & Audit** — JSON and text log formats, audit trail with file/syslog output, and optional webhook export.
- **Background Workers** — Daemon threads for challenge validation, certificate expiration checks, nonce/order/challenge cleanup, and data retention — all HA-safe with PostgreSQL advisory locks.

## Installation

### From PyPI

**Linux / macOS:**

```bash
python3.12 -m venv .venv
source .venv/bin/activate

pip install acmeeh

# Optional: HSM (PKCS#11) support
pip install acmeeh[hsm]
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1

pip install acmeeh

# Optional: HSM (PKCS#11) support
pip install acmeeh[hsm]
```

After installation the `acmeeh` command is available:

```bash
acmeeh -c config.yaml --validate-only
acmeeh -c config.yaml --dev
```

### From Source

**Linux / macOS:**

```bash
git clone https://github.com/miichoow/ACMEEH.git
cd ACMEEH

python3.12 -m venv .venv
source .venv/bin/activate

# Install in editable mode (includes all dependencies)
pip install -e ".[dev]"

# Or install dependencies manually
pip install -r requirements.txt
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/miichoow/ACMEEH.git
cd ACMEEH

python -m venv .venv
.venv\Scripts\Activate.ps1

# Install in editable mode (includes all dependencies)
pip install -e ".[dev]"

# Or install dependencies manually
pip install -r requirements.txt
```

### Docker

```bash
# 1. Copy the example env file and set your database password
cp docker/.env.example .env
vi .env   # set POSTGRES_PASSWORD

# 2. Place your CA root certificate and key
mkdir -p certs
cp /path/to/root.pem     certs/root.pem
cp /path/to/root-key.pem certs/root-key.pem

# 3. Build and start (ACMEEH + PostgreSQL)
docker compose up -d

# 4. Verify
curl http://localhost:8443/livez
curl http://localhost:8443/directory
```

Build with optional features:

```bash
# HSM (PKCS#11) support
docker compose build --build-arg INSTALL_HSM=1

# Gevent async workers
docker compose build --build-arg INSTALL_GEVENT=1
```

See the [Docker documentation](docs/docker.rst) for the full reference — environment variables, configuration, common operations, reverse proxy setup, scaling, and troubleshooting.

### Dependencies

Core dependencies (installed automatically via `pip install acmeeh`):

| Package | Purpose |
|---------|---------|
| Flask | Web framework |
| cryptography | X.509, JWS, key operations |
| dnspython | DNS-01 challenge validation |
| Jinja2 | Notification email templates |
| psycopg\[binary\] | PostgreSQL driver |
| pyConfigKit | Configuration management |
| PyPGKit | Database repository layer |

Optional:

| Package | Install with | Purpose |
|---------|-------------|---------|
| python-pkcs11 | `pip install acmeeh[hsm]` | HSM backend via PKCS#11 |
| gunicorn | `pip install gunicorn` | Production server (Linux/macOS only) |
| pytest, pytest-cov | `pip install acmeeh[dev]` | Testing and coverage |

### Quick Start

```bash
# Set up PostgreSQL
psql -U postgres -c "CREATE USER acmeeh WITH PASSWORD 'secret';"
psql -U postgres -c "CREATE DATABASE acmeeh OWNER acmeeh;"

# Create config.yaml (see Configuration section below)

# Validate config
acmeeh -c config.yaml --validate-only

# Start development server
DB_PASSWORD=secret acmeeh -c config.yaml --dev
```

> **Note:** On Windows, gunicorn is not available. Use `--dev` for the Flask development server,
> or deploy behind a WSGI server like waitress.

## Configuration

ACMEEH uses a single YAML configuration file with 26 settings sections. Only three fields are required:

```yaml
server:
  external_url: https://acme.example.com

database:
  database: acmeeh
  user: acmeeh
  password: ${DB_PASSWORD}          # env var substitution
  auto_setup: true                  # create tables on first run

ca:
  backend: internal
  internal:
    root_cert_path: /path/to/root-ca.pem
    root_key_path: /path/to/root-ca-key.pem

challenges:
  enabled:
    - http-01
```

Environment variables are supported via `${VAR}` or `${VAR:-default}` syntax anywhere in the YAML.

See the [full configuration reference](docs/configuration.rst) for all settings.

## CLI Reference

| Command | Description |
|---------|-------------|
| `acmeeh -c config.yaml` | Start the server (gunicorn) |
| `acmeeh -c config.yaml --dev` | Start Flask development server |
| `acmeeh -c config.yaml --validate-only` | Validate config and exit |
| `acmeeh -c config.yaml db status` | Check database connectivity |
| `acmeeh -c config.yaml db migrate` | Run database migrations |
| `acmeeh -c config.yaml ca test-sign` | Test CA signing with ephemeral CSR |
| `acmeeh -c config.yaml crl rebuild` | Force CRL rebuild |
| `acmeeh -c config.yaml admin create-user --username admin --email admin@example.com` | Create admin user |
| `acmeeh -c config.yaml inspect order <id>` | Inspect an order |
| `acmeeh -c config.yaml inspect certificate <id>` | Inspect a certificate |
| `acmeeh -c config.yaml inspect account <id>` | Inspect an account |

Global flags: `-c/--config` (required), `--debug`, `--dev`, `--validate-only`, `-v/--version`

## CA Backends

| Backend | Description |
|---------|-------------|
| `internal` | Sign with a root CA key stored as PEM files on disk |
| `external` | Delegate signing to a remote HTTP API (e.g., HashiCorp Vault, EJBCA) |
| `hsm` | Sign using a Hardware Security Module via PKCS#11 |
| `acme_proxy` | Proxy to an upstream ACME CA (e.g., Let's Encrypt) |
| `ext:<path>` | Load a custom backend class (e.g., `ext:mycompany.pki.VaultBackend`) |

All backends support a circuit breaker that prevents cascading failures on repeated signing errors.

See the [CA backends documentation](docs/ca-backends.rst) for detailed setup instructions.

## Challenge Types

| Type | Validation |
|------|-----------|
| `http-01` | HTTP request to `http://{domain}/.well-known/acme-challenge/{token}` on port 80 |
| `dns-01` | DNS TXT record query at `_acme-challenge.{domain}` |
| `tls-alpn-01` | TLS connection to port 443 with ALPN protocol `acme-tls/1` |

For the `acme_proxy` backend, set `challenges.auto_accept: true` to auto-accept all downstream challenges (real validation happens upstream).

Custom challenge validators can be added as plugins.

## Architecture

```
ACME Clients (certbot, acme.sh, Caddy, ...)
                    │
             HTTPS / RFC 8555
                    │
    ┌───────────────────────────────┐
    │         Flask API Layer       │
    │  directory, nonce, account,   │
    │  order, authz, challenge,     │
    │  certificate, key-change      │
    ├───────────────────────────────┤
    │        Service Layer          │
    │  AccountService, OrderService │
    │  ChallengeService, CertSvc    │
    ├──────────┬────────────────────┤
    │Repository│    CA Backend      │
    │  Layer   │ internal/external/ │
    │(PyPGKit) │ hsm/acme_proxy/    │
    │          │ ext:custom         │
    ├──────────┴────────────────────┤
    │     DI Container (context.py) │
    └───────────────┬───────────────┘
                    │
             PostgreSQL 14+
```

## Testing

If installed with `pip install -e ".[dev]"`, pytest is already available and `PYTHONPATH` is handled automatically.

**Linux / macOS:**

```bash
# Run all tests
pytest

# Run a specific test
pytest tests/test_config.py::test_name -v

# Run with coverage
pytest --cov=acmeeh --cov-report=html
```

**Windows (PowerShell):**

```powershell
# Run all tests
pytest

# Run a specific test
pytest tests\test_config.py::test_name -v

# Run with coverage
pytest --cov=acmeeh --cov-report=html
```

If you installed dependencies manually (without `pip install -e .`), prefix commands with `PYTHONPATH=src` on Linux or set it on Windows:

```bash
# Linux / macOS
PYTHONPATH=src python -m pytest tests/
```

```powershell
# Windows (PowerShell)
$env:PYTHONPATH = "src"; python -m pytest tests/
```

## Documentation

Full documentation is available in the [`docs/`](docs/) folder (Sphinx/reStructuredText, compatible with [Read the Docs](https://readthedocs.org/)):

- [Installation](docs/installation.rst) — Prerequisites, setup, first run
- [Configuration Reference](docs/configuration.rst) — All 27 settings sections
- [ACME API Reference](docs/api-reference.rst) — RFC 8555 endpoints and JWS auth
- [CA Backends](docs/ca-backends.rst) — Internal, external, HSM, ACME proxy, custom
- [Admin API](docs/admin.rst) — REST API for server management
- [Docker](docs/docker.rst) — Dockerfile, Compose, env vars, operations
- [Deployment](docs/deployment.rst) — Production setup, reverse proxy, monitoring
- [Development](docs/development.rst) — Project structure, testing, hooks

To build the docs locally:

```bash
pip install -r docs/requirements.txt
sphinx-build -b html docs docs/_build/html
```

## License

[Apache License 2.0](LICENSE)
