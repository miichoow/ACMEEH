-- ACMEEH Database Schema
-- PostgreSQL 14+
-- =========================================================================

-- ---------------------------------------------------------------------------
-- Schema version tracking
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT        PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version)
VALUES ('001_initial')
ON CONFLICT (version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Trigger function: auto-update updated_at on row modification
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Sequence: certificate serial numbers (for ca.internal.serial_source = 'database')
-- ---------------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS certificate_serial_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    CACHE 1;

-- =========================================================================
-- ACCOUNTS
-- =========================================================================
CREATE TABLE IF NOT EXISTS accounts (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    jwk_thumbprint  VARCHAR(128)    NOT NULL,
    jwk             JSONB           NOT NULL,
    status          VARCHAR(20)     NOT NULL DEFAULT 'valid',
    tos_agreed      BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT accounts_status_check
        CHECK (status IN ('valid', 'deactivated', 'revoked'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_jwk_thumbprint
    ON accounts (jwk_thumbprint);

DROP TRIGGER IF EXISTS trg_accounts_updated_at ON accounts;
CREATE TRIGGER trg_accounts_updated_at
    BEFORE UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================================
-- ACCOUNT CONTACTS
-- =========================================================================
CREATE TABLE IF NOT EXISTS account_contacts (
    id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  UUID            NOT NULL
                    REFERENCES accounts (id) ON DELETE CASCADE,
    contact_uri VARCHAR(512)    NOT NULL,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT account_contacts_unique_pair
        UNIQUE (account_id, contact_uri)
);

CREATE INDEX IF NOT EXISTS idx_account_contacts_account_id
    ON account_contacts (account_id);

CREATE INDEX IF NOT EXISTS idx_account_contacts_contact_uri
    ON account_contacts (contact_uri);

-- =========================================================================
-- ORDERS
-- =========================================================================
CREATE TABLE IF NOT EXISTS orders (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          UUID            NOT NULL
                            REFERENCES accounts (id) ON DELETE RESTRICT,
    status              VARCHAR(20)     NOT NULL DEFAULT 'pending',
    identifiers         JSONB           NOT NULL,
    identifiers_hash    VARCHAR(64)     NOT NULL,
    expires             TIMESTAMPTZ,
    not_before          TIMESTAMPTZ,
    not_after           TIMESTAMPTZ,
    error               JSONB,
    certificate_id      UUID,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT orders_status_check
        CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid'))
);

CREATE INDEX IF NOT EXISTS idx_orders_account_status
    ON orders (account_id, status);

CREATE INDEX IF NOT EXISTS idx_orders_account_identifiers_hash
    ON orders (account_id, identifiers_hash);

CREATE INDEX IF NOT EXISTS idx_orders_expires_actionable
    ON orders (expires)
    WHERE status IN ('pending', 'ready', 'processing');

DROP TRIGGER IF EXISTS trg_orders_updated_at ON orders;
CREATE TRIGGER trg_orders_updated_at
    BEFORE UPDATE ON orders
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================================
-- AUTHORIZATIONS
-- =========================================================================
CREATE TABLE IF NOT EXISTS authorizations (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          UUID            NOT NULL
                            REFERENCES accounts (id) ON DELETE RESTRICT,
    identifier_type     VARCHAR(10)     NOT NULL,
    identifier_value    VARCHAR(255)    NOT NULL,
    status              VARCHAR(20)     NOT NULL DEFAULT 'pending',
    expires             TIMESTAMPTZ,
    wildcard            BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT authorizations_status_check
        CHECK (status IN ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked')),
    CONSTRAINT authorizations_identifier_type_check
        CHECK (identifier_type IN ('dns', 'ip'))
);

CREATE INDEX IF NOT EXISTS idx_authorizations_reuse_lookup
    ON authorizations (account_id, identifier_type, identifier_value, status);

CREATE INDEX IF NOT EXISTS idx_authorizations_expires_pending
    ON authorizations (expires)
    WHERE status = 'pending';

DROP TRIGGER IF EXISTS trg_authorizations_updated_at ON authorizations;
CREATE TRIGGER trg_authorizations_updated_at
    BEFORE UPDATE ON authorizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================================
-- ORDER ↔ AUTHORIZATION (many-to-many)
-- =========================================================================
CREATE TABLE IF NOT EXISTS order_authorizations (
    order_id            UUID    NOT NULL
                            REFERENCES orders (id) ON DELETE CASCADE,
    authorization_id    UUID    NOT NULL
                            REFERENCES authorizations (id) ON DELETE CASCADE,

    PRIMARY KEY (order_id, authorization_id)
);

CREATE INDEX IF NOT EXISTS idx_order_authorizations_authz
    ON order_authorizations (authorization_id);

-- =========================================================================
-- CHALLENGES
-- =========================================================================
CREATE TABLE IF NOT EXISTS challenges (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id    UUID            NOT NULL
                            REFERENCES authorizations (id) ON DELETE CASCADE,
    type                VARCHAR(20)     NOT NULL,
    token               VARCHAR(255)    NOT NULL,
    status              VARCHAR(20)     NOT NULL DEFAULT 'pending',
    error               JSONB,
    validated_at        TIMESTAMPTZ,
    retry_count         INTEGER         NOT NULL DEFAULT 0,
    next_retry_at       TIMESTAMPTZ,
    locked_by           VARCHAR(128),
    locked_at           TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT challenges_status_check
        CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    CONSTRAINT challenges_unique_authz_type
        UNIQUE (authorization_id, type)
);

CREATE INDEX IF NOT EXISTS idx_challenges_authorization_id
    ON challenges (authorization_id);

CREATE INDEX IF NOT EXISTS idx_challenges_processing_lock
    ON challenges (status, locked_by)
    WHERE status = 'processing';

DROP TRIGGER IF EXISTS trg_challenges_updated_at ON challenges;
CREATE TRIGGER trg_challenges_updated_at
    BEFORE UPDATE ON challenges
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================================
-- CERTIFICATES
-- =========================================================================
CREATE TABLE IF NOT EXISTS certificates (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          UUID            NOT NULL
                            REFERENCES accounts (id) ON DELETE RESTRICT,
    order_id            UUID            NOT NULL
                            REFERENCES orders (id) ON DELETE RESTRICT,
    serial_number       VARCHAR(64)     NOT NULL,
    fingerprint         VARCHAR(128)    NOT NULL,
    pem_chain           TEXT            NOT NULL,
    not_before_cert     TIMESTAMPTZ     NOT NULL,
    not_after_cert      TIMESTAMPTZ     NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   SMALLINT,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_serial_number
    ON certificates (serial_number);

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_fingerprint
    ON certificates (fingerprint);

CREATE INDEX IF NOT EXISTS idx_certificates_account_id
    ON certificates (account_id);

CREATE INDEX IF NOT EXISTS idx_certificates_order_id
    ON certificates (order_id);

CREATE INDEX IF NOT EXISTS idx_certificates_expiring_active
    ON certificates (not_after_cert)
    WHERE revoked_at IS NULL;

DROP TRIGGER IF EXISTS trg_certificates_updated_at ON certificates;
CREATE TRIGGER trg_certificates_updated_at
    BEFORE UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================================
-- Add deferred FK from orders → certificates
-- =========================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'orders_certificate_id_fk'
          AND table_name = 'orders'
    ) THEN
        ALTER TABLE orders
            ADD CONSTRAINT orders_certificate_id_fk
            FOREIGN KEY (certificate_id) REFERENCES certificates (id);
    END IF;
END;
$$;

-- =========================================================================
-- NOTIFICATIONS
-- =========================================================================
CREATE TABLE IF NOT EXISTS notifications (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_type   VARCHAR(40)     NOT NULL,
    recipient           VARCHAR(512)    NOT NULL,
    account_id          UUID            REFERENCES accounts(id) ON DELETE SET NULL,
    subject             VARCHAR(998)    NOT NULL,
    body                TEXT            NOT NULL,
    status              VARCHAR(20)     NOT NULL DEFAULT 'pending',
    error_detail        TEXT,
    retry_count         INTEGER         NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    sent_at             TIMESTAMPTZ,

    CONSTRAINT notifications_status_check
        CHECK (status IN ('pending', 'sent', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_account_id
    ON notifications (account_id);

CREATE INDEX IF NOT EXISTS idx_notifications_retry_eligible
    ON notifications (status, retry_count)
    WHERE status = 'failed';

CREATE INDEX IF NOT EXISTS idx_notifications_created_at
    ON notifications (created_at);

-- =========================================================================
-- NONCES
-- =========================================================================
CREATE TABLE IF NOT EXISTS nonces (
    nonce       VARCHAR(256)    PRIMARY KEY,
    expires_at  TIMESTAMPTZ     NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nonces_expires_at
    ON nonces (expires_at);

-- =========================================================================
-- Admin API schema
-- =========================================================================
CREATE SCHEMA IF NOT EXISTS admin;

CREATE TABLE IF NOT EXISTS admin.users (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    username         VARCHAR(100) NOT NULL UNIQUE,
    email            VARCHAR(512) NOT NULL,
    password_hash    VARCHAR(256) NOT NULL,
    role             VARCHAR(20)  NOT NULL DEFAULT 'auditor',
    enabled          BOOLEAN      NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_login_at    TIMESTAMPTZ,
    CONSTRAINT admin_users_role_check CHECK (role IN ('admin', 'auditor'))
);

CREATE TABLE IF NOT EXISTS admin.audit_log (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID         REFERENCES admin.users(id) ON DELETE SET NULL,
    action         VARCHAR(100) NOT NULL,
    target_user_id UUID,
    details        JSONB,
    ip_address     VARCHAR(45),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_user
    ON admin.audit_log (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at
    ON admin.audit_log (created_at);

CREATE TABLE IF NOT EXISTS admin.eab_credentials (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    kid            VARCHAR(255) NOT NULL UNIQUE,
    hmac_key       VARCHAR(512) NOT NULL,
    account_id     UUID         REFERENCES accounts(id) ON DELETE SET NULL,
    created_by     UUID         REFERENCES admin.users(id) ON DELETE SET NULL,
    label          VARCHAR(255) NOT NULL DEFAULT '',
    used           BOOLEAN      NOT NULL DEFAULT false,
    used_at        TIMESTAMPTZ,
    revoked        BOOLEAN      NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_eab_credentials_kid
    ON admin.eab_credentials (kid);

CREATE INDEX IF NOT EXISTS idx_admin_eab_credentials_account
    ON admin.eab_credentials (account_id)
    WHERE account_id IS NOT NULL;

-- Reuse public.set_updated_at() trigger
DROP TRIGGER IF EXISTS trg_admin_users_updated_at ON admin.users;
CREATE TRIGGER trg_admin_users_updated_at
    BEFORE UPDATE ON admin.users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================================
-- Allowed Identifiers (per-account domain/IP allowlist)
-- =========================================================================
CREATE TABLE IF NOT EXISTS admin.allowed_identifiers (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier_type   VARCHAR(10)  NOT NULL,
    identifier_value  VARCHAR(255) NOT NULL,
    created_by        UUID         REFERENCES admin.users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT allowed_identifiers_type_check
        CHECK (identifier_type IN ('dns', 'ip')),
    CONSTRAINT allowed_identifiers_unique_pair
        UNIQUE (identifier_type, identifier_value)
);

-- Junction: ACME account <-> allowed identifier (many-to-many)
CREATE TABLE IF NOT EXISTS admin.account_allowed_identifiers (
    allowed_identifier_id UUID NOT NULL
        REFERENCES admin.allowed_identifiers(id) ON DELETE CASCADE,
    account_id            UUID NOT NULL
        REFERENCES accounts(id) ON DELETE CASCADE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (allowed_identifier_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_account_allowed_identifiers_account
    ON admin.account_allowed_identifiers (account_id);

INSERT INTO schema_migrations (version)
VALUES ('002_account_allowlist')
ON CONFLICT (version) DO NOTHING;

-- =========================================================================
-- NONCE AUDIT (optional — enabled via nonce.audit_consumed)
-- =========================================================================
CREATE TABLE IF NOT EXISTS nonce_audit (
    nonce       VARCHAR(256)    NOT NULL,
    consumed_at TIMESTAMPTZ     NOT NULL DEFAULT now(),
    client_ip   VARCHAR(45)
);

CREATE INDEX IF NOT EXISTS idx_nonce_audit_consumed_at
    ON nonce_audit (consumed_at);

INSERT INTO schema_migrations (version)
VALUES ('003_enhancements')
ON CONFLICT (version) DO NOTHING;

-- =========================================================================
-- CSR Profiles (admin-managed certificate policy documents)
-- =========================================================================
CREATE TABLE IF NOT EXISTS admin.csr_profiles (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL UNIQUE,
    description     TEXT         NOT NULL DEFAULT '',
    profile_data    JSONB        NOT NULL,
    created_by      UUID         REFERENCES admin.users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_admin_csr_profiles_updated_at ON admin.csr_profiles;
CREATE TRIGGER trg_admin_csr_profiles_updated_at
    BEFORE UPDATE ON admin.csr_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Junction: ACME account <-> CSR profile (one profile per account)
CREATE TABLE IF NOT EXISTS admin.account_csr_profiles (
    account_id      UUID NOT NULL
        REFERENCES accounts(id) ON DELETE CASCADE
        PRIMARY KEY,
    csr_profile_id  UUID NOT NULL
        REFERENCES admin.csr_profiles(id) ON DELETE CASCADE,
    assigned_by     UUID REFERENCES admin.users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_account_csr_profiles_profile
    ON admin.account_csr_profiles (csr_profile_id);

-- Add columns to certificates for key-reuse and renewal-window checks
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'certificates'
          AND column_name = 'public_key_fingerprint'
    ) THEN
        ALTER TABLE certificates
            ADD COLUMN public_key_fingerprint VARCHAR(128);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'certificates'
          AND column_name = 'san_values'
    ) THEN
        ALTER TABLE certificates
            ADD COLUMN san_values JSONB;
    END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_certificates_public_key_fingerprint
    ON certificates (public_key_fingerprint)
    WHERE public_key_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_certificates_san_values
    ON certificates USING gin (san_values)
    WHERE san_values IS NOT NULL;

INSERT INTO schema_migrations (version)
VALUES ('004_csr_profiles')
ON CONFLICT (version) DO NOTHING;

-- =========================================================================
-- Rate limit counters (distributed, database-backed rate limiting)
-- =========================================================================
CREATE TABLE IF NOT EXISTS rate_limit_counters (
    compound_key TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    counter      INTEGER     NOT NULL DEFAULT 1,
    PRIMARY KEY (compound_key, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_counters_expiry
    ON rate_limit_counters (window_start);

-- =========================================================================
-- Certificate expiration notices (deduplication for expiry warnings)
-- =========================================================================
CREATE TABLE IF NOT EXISTS certificate_expiration_notices (
    certificate_id UUID    NOT NULL REFERENCES certificates(id),
    warning_days   INTEGER NOT NULL,
    notified_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (certificate_id, warning_days)
);

INSERT INTO schema_migrations (version)
VALUES ('005_enhancements_v2')
ON CONFLICT (version) DO NOTHING;

-- =========================================================================
-- Admin token blacklist (HA-safe — shared across instances)
-- =========================================================================
CREATE TABLE IF NOT EXISTS admin.token_blacklist (
    token_signature VARCHAR(512)  PRIMARY KEY,
    revoked_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_token_blacklist_expires
    ON admin.token_blacklist (expires_at);

-- =========================================================================
-- CRL cache (HA-safe — shared across instances)
-- =========================================================================
CREATE TABLE IF NOT EXISTS crl_cache (
    id          INTEGER      PRIMARY KEY DEFAULT 1,
    crl_der     BYTEA        NOT NULL,
    built_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_count INTEGER    NOT NULL DEFAULT 0,
    CONSTRAINT crl_cache_singleton CHECK (id = 1)
);

INSERT INTO schema_migrations (version)
VALUES ('006_ha_improvements')
ON CONFLICT (version) DO NOTHING;

-- =========================================================================
-- Additional indexes for query optimization
-- =========================================================================

-- Stale challenge detection (background worker queries by status + timestamp)
CREATE INDEX IF NOT EXISTS idx_challenges_stale_lookup
    ON challenges (status, updated_at)
    WHERE status IN ('pending', 'processing');

INSERT INTO schema_migrations (version)
VALUES ('007_stale_challenge_index')
ON CONFLICT (version) DO NOTHING;
