package audit

const listSelectSQL = `
SELECT a.id::text, a.event_type, a.outcome,
       a.actor_id::text, NULLIF(a.actor_email, ''),
       COALESCE(
         NULLIF(a.actor_email, ''),
         CASE WHEN a.actor_id IS NOT NULL AND NULLIF(a.actor_email, '') IS NULL THEN 'Former user' END,
         'System'
       ) AS actor_display,
       (a.actor_id IS NOT NULL AND NULLIF(a.actor_email, '') IS NULL) AS actor_pseudonymized,
       a.target_type, a.target_id,
       CASE
         WHEN a.target_type = 'user' THEN COALESCE(u.email, 'Former user')
         WHEN a.target_type = 'client' THEN COALESCE(c.name, a.target_id)
         WHEN a.target_type = 'config' OR a.target_type = 'instance_config' THEN a.target_id
         WHEN a.target_type = 'permission' THEN a.target_id
         WHEN a.target_type = 'signing_key' THEN LEFT(a.target_id, 8)
         WHEN a.target_type = 'instance' THEN COALESCE(a.metadata->>'instance_name', 'Instance')
         WHEN a.target_type = 'audit_log' THEN 'Audit log'
         ELSE NULL
       END AS target_display,
       a.client_id::text, a.ip_address::text, COALESCE(a.metadata, '{}'::jsonb), a.created_at
FROM audit_logs a
LEFT JOIN users u ON a.target_type = 'user' AND a.target_id = u.id::text
LEFT JOIN clients c ON a.target_type = 'client' AND a.target_id = c.id::text
`
