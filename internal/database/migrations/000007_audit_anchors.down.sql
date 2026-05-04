-- 000007_audit_anchors.down.sql
-- Backout for REQ-AUD-022 anchor proof storage and configuration keys.

DELETE FROM instance_config
 WHERE key IN (
    'audit.anchor.backend',
    'audit.anchor.bucket',
    'audit.anchor.path',
    'audit.anchor.events_per_anchor',
    'audit.anchor.interval_secs'
 );

DROP TABLE IF EXISTS audit_anchors;
