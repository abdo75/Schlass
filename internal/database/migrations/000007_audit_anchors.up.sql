-- 000007_audit_anchors.up.sql
-- Spec: docs/specs/audit-log-system.md REQ-AUD-022 and §13.1.
-- Stores immutable-destination proof refs for periodic audit chain anchors.

CREATE TABLE audit_anchors (
    tenant_id    UUID NOT NULL,
    sequence_no  BIGINT NOT NULL,
    row_hash     BYTEA NOT NULL,
    backend      TEXT NOT NULL,
    proof_ref    TEXT NOT NULL,
    anchored_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sequence_no)
);

REVOKE UPDATE, DELETE ON audit_anchors FROM PUBLIC;
GRANT SELECT, INSERT ON audit_anchors TO schlass_app;

INSERT INTO instance_config (key, value) VALUES
    ('audit.anchor.backend',           '"none"'),
    ('audit.anchor.bucket',            'null'),
    ('audit.anchor.path',              'null'),
    ('audit.anchor.events_per_anchor', '10000'),
    ('audit.anchor.interval_secs',     '3600')
ON CONFLICT (key) DO NOTHING;
