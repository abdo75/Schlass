-- internal/database/migrations/000011_drop_audit_actor_fk.up.sql
-- Drops the foreign key from audit_logs.actor_id to users(id).
--
-- Append-only audit tables and live user tables have incompatible referential
-- integrity semantics: if the FK is enforced, deleting a user who has any
-- audit history fails; the only cascade option that doesn't violate append-only
-- (SET NULL) requires UPDATE privilege on audit_logs, which the RLS policy
-- explicitly revokes from schlass_app.
--
-- The denormalized actor_email column (added in Sprint 1) already carries the
-- human-readable actor identity across user deletion. actor_id remains as a
-- plain UUID column — historical rows still point at the (possibly deleted)
-- user for join-when-present queries.
--
-- See docs/superpowers/specs/2026-04-15-sprint3-user-management-design.md §2.3.

ALTER TABLE audit_logs DROP CONSTRAINT audit_logs_actor_id_fkey;
