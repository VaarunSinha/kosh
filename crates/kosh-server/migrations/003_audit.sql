-- Append-only audit log + JWT revocation list.

CREATE TABLE audit_log (
    id           BIGSERIAL PRIMARY KEY,
    workspace_id UUID,
    user_id      UUID,
    event        TEXT NOT NULL,
    ref_id       TEXT,
    environment  TEXT,
    ip_address   INET,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Events: secret.{created,updated,deleted,accessed}, member.{invited,removed,
-- role_changed}, sync.{push,pull}, key.rotated, auth.{token_revoked},
-- forbidden.attempt (KE-504 security signal).

-- The app role may append and read, but never mutate or delete history.
GRANT SELECT, INSERT ON audit_log TO kosh_app;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO kosh_app;
REVOKE UPDATE, DELETE ON audit_log FROM kosh_app;

-- Revoked JWTs (by jti) for stateful logout on top of stateless tokens.
-- Rows can be pruned once expired, so DELETE is permitted here.
CREATE TABLE revoked_tokens (
    jti        UUID PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

GRANT SELECT, INSERT, DELETE ON revoked_tokens TO kosh_app;
