-- internal/database/migrations/000011_drop_audit_actor_fk.down.sql
-- Re-adds the FK as NOT VALID so the down migration doesn't choke on
-- historical audit rows whose actor_id points to a user that was already
-- hard-deleted before the down-migration runs.

ALTER TABLE audit_logs
  ADD CONSTRAINT audit_logs_actor_id_fkey
  FOREIGN KEY (actor_id) REFERENCES users(id) NOT VALID;
