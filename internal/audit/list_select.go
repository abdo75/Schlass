package audit

// REQ-AUD-011/REQ-AUD-070: actor_email is no longer a column. The viewer
// derives display fields via live joins and CASE expressions at read time.
// Pseudonymized rows (actor_id NULL + metadata.pseudonymized_at set)
// render as the literal 'pseudonymized' so the side panel never shows
// a raw NULL.
//
// The response shape still has actor_email so the React feature in
// web/src/features/audit/ does not need to move (M7 is the viewer
// polish milestone).
const listSelectSQL = `
SELECT a.id::text, a.event_type, a.outcome,
       a.actor_id::text,
       CASE
         WHEN a.actor_id IS NOT NULL THEN u_actor.email
         WHEN (a.metadata->>'pseudonymized_at') IS NOT NULL THEN 'pseudonymized'
         ELSE NULL
       END AS actor_email,
       COALESCE(
         CASE
           WHEN a.actor_id IS NOT NULL THEN u_actor.email
           WHEN (a.metadata->>'pseudonymized_at') IS NOT NULL THEN 'pseudonymized'
         END,
         CASE WHEN a.actor_id IS NOT NULL THEN 'Former user' END,
         'System'
       ) AS actor_display,
       (
         a.actor_id IS NULL
         AND (a.metadata->>'pseudonymized_at') IS NOT NULL
       ) AS actor_pseudonymized,
       a.target_type, a.target_id,
       CASE
         WHEN a.target_id IS NULL OR a.target_id = '' THEN
           CASE
             WHEN a.target_type = 'user' THEN 'User'
             WHEN a.target_type = 'client' THEN 'Client'
             WHEN a.target_type = 'config' OR a.target_type = 'instance_config' THEN 'Setting'
             WHEN a.target_type = 'permission' THEN 'Permission'
             WHEN a.target_type = 'signing_key' THEN 'Signing key'
             WHEN a.target_type = 'instance' THEN 'Instance'
             WHEN a.target_type = 'audit_log' THEN 'Audit log'
             ELSE a.target_type
           END
         WHEN a.target_type = 'user' THEN COALESCE(u.email, 'Former user')
         WHEN a.target_type = 'client' THEN COALESCE(c.name, a.target_id)
         WHEN a.target_type = 'config' OR a.target_type = 'instance_config' THEN a.target_id
         WHEN a.target_type = 'permission' THEN a.target_id
         WHEN a.target_type = 'signing_key' THEN LEFT(a.target_id, 8)
         WHEN a.target_type = 'instance' THEN COALESCE(a.metadata->>'instance_name', 'Instance')
         WHEN a.target_type = 'audit_log' THEN 'Audit log'
         ELSE NULL
       END AS target_display,
       a.client_id::text, a.client_ip_coarse::text, COALESCE(a.metadata, '{}'::jsonb), a.created_at
FROM audit_logs a
LEFT JOIN users u_actor ON a.actor_id = u_actor.id
LEFT JOIN users u ON a.target_type = 'user' AND a.target_id = u.id::text
LEFT JOIN clients c ON a.target_type = 'client' AND a.target_id = c.id::text
`
