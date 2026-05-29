-- Row-Level Security + the non-superuser application role.
--
-- Postgres superusers BYPASS RLS, so isolation only holds when the server
-- connects as a dedicated non-superuser role. Migrations run as the admin
-- (superuser); request handling uses `kosh_app`.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kosh_app') THEN
        CREATE ROLE kosh_app LOGIN PASSWORD 'kosh_app';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO kosh_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    workspaces, environments, members, secrets, env_keys, user_public_keys
    TO kosh_app;

-- Per-workspace child tables. Every row carries workspace_id, and every
-- workspace-scoped request runs `SET LOCAL app.workspace_id = '<uuid>'` inside
-- its transaction. An unset GUC -> NULL -> the comparison is never true -> zero
-- rows (fail-closed). `workspaces` itself is intentionally NOT under RLS: a user
-- spans many workspaces, so its access is gated by membership checks in the
-- handlers, not by a single-workspace GUC.
--
-- `app.user_id` (the authenticated caller) is also set on every request so a
-- user can always read their own membership rows across workspaces (needed to
-- list "my workspaces"); within a scoped workspace they additionally see all
-- member rows for that workspace.

ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE members      ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets      ENABLE ROW LEVEL SECURITY;
ALTER TABLE env_keys     ENABLE ROW LEVEL SECURITY;

CREATE POLICY workspace_isolation ON environments
    FOR ALL
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid)
    WITH CHECK (workspace_id = current_setting('app.workspace_id', true)::uuid);

CREATE POLICY workspace_isolation ON secrets
    FOR ALL
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid)
    WITH CHECK (workspace_id = current_setting('app.workspace_id', true)::uuid);

CREATE POLICY workspace_isolation ON env_keys
    FOR ALL
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid)
    WITH CHECK (workspace_id = current_setting('app.workspace_id', true)::uuid);

CREATE POLICY member_visibility ON members
    FOR ALL
    USING (
        workspace_id = current_setting('app.workspace_id', true)::uuid
        OR user_id = current_setting('app.user_id', true)::uuid
    )
    WITH CHECK (workspace_id = current_setting('app.workspace_id', true)::uuid);
