# ── Builder stage ─────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS builder

ARG INSTALL_HSM=0
ARG INSTALL_ACME_PROXY=0
ARG INSTALL_GEVENT=0
ARG EXTRA_PIP_PACKAGES=""

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies first (layer caching)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Install optional extras
RUN if [ "$INSTALL_HSM" = "1" ]; then \
        pip install --no-cache-dir python-pkcs11>=0.7; \
    fi && \
    if [ "$INSTALL_ACME_PROXY" = "1" ]; then \
        pip install --no-cache-dir "acmeow>=1.1"; \
    fi && \
    if [ "$INSTALL_GEVENT" = "1" ]; then \
        pip install --no-cache-dir gevent>=24.0; \
    fi && \
    if [ -n "$EXTRA_PIP_PACKAGES" ]; then \
        pip install --no-cache-dir $EXTRA_PIP_PACKAGES; \
    fi

# Install the package itself
COPY pyproject.toml /build/pyproject.toml
COPY src/ /build/src/
RUN pip install --no-cache-dir /build

# ── Runtime stage ────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

ARG ACMEEH_UID=1000
ARG ACMEEH_GID=1000
ARG INSTALL_HSM=0

LABEL org.opencontainers.image.title="ACMEEH" \
      org.opencontainers.image.description="Enterprise ACME (RFC 8555) server for internal PKI" \
      org.opencontainers.image.url="https://github.com/miichoow/ACMEEH" \
      org.opencontainers.image.source="https://github.com/miichoow/ACMEEH" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
        tini \
    && if [ "$INSTALL_HSM" = "1" ]; then \
        apt-get install -y --no-install-recommends softhsm2; \
    fi \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g "${ACMEEH_GID}" acmeeh && \
    useradd -u "${ACMEEH_UID}" -g acmeeh -m -s /bin/false acmeeh

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Application directories
RUN mkdir -p /app/certs /app/data /var/log/acmeeh && \
    chown -R acmeeh:acmeeh /app /var/log/acmeeh

WORKDIR /app

# Default config (can be overridden via bind mount)
COPY --chown=acmeeh:acmeeh docker/config.yaml /app/config.yaml

USER acmeeh

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8443/healthz || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["acmeeh", "-c", "/app/config.yaml"]
