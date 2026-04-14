CREATE TABLE audit_logs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   TEXT NOT NULL,
    actor_id     UUID REFERENCES users(id),
    actor_email  TEXT,
    target_type  TEXT,
    target_id    TEXT,
    client_id    UUID REFERENCES clients(id),
    ip_address   INET,
    outcome      TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    metadata     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_select ON audit_logs
    FOR SELECT USING (true);

CREATE POLICY audit_logs_insert ON audit_logs
    FOR INSERT WITH CHECK (true);

REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;
