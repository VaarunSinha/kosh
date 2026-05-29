-- Initial schema. Zero-knowledge: the server stores only ciphertext
-- (encrypted_blob), encrypted per-member env keys, and members' public keys.
-- No users/password table exists: a user's identity is the UUID in their JWT.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE workspaces (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    owner_id    UUID NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, owner_id)
);

CREATE TABLE environments (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name         TEXT NOT NULL CHECK (name ~ '^[a-z0-9-]+$'),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE members (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL,
    role         TEXT NOT NULL
                 CHECK (role IN ('owner', 'admin', 'developer', 'readonly', 'ci')),
    joined_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, user_id)
);

CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    environment_id  UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    ref_id          TEXT NOT NULL,
    key_name        TEXT NOT NULL,
    encrypted_blob  BYTEA NOT NULL,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotation_due_at TIMESTAMPTZ,
    UNIQUE (workspace_id, environment_id, ref_id)
);

-- The env private key, encrypted once per member with that member's public key.
-- The server never sees the plaintext env key.
CREATE TABLE env_keys (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id      UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    environment_id    UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    member_id         UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    encrypted_env_key BYTEA NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (environment_id, member_id)
);

CREATE TABLE user_public_keys (
    user_id     UUID PRIMARY KEY,
    public_key  BYTEA NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
