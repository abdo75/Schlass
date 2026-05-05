// Frozen event-type taxonomy. Every emitted event_type MUST appear in
// EventTypes — Emit returns ErrUnknownEventType otherwise. New events go
// through code review with a registry entry so we always know retention,
// criticality, and outbound CAEP mapping.
//
// Spec: docs/specs/audit-log-system.md §3 (REQ-AUD-008). Names are kept
// as currently emitted by the codebase; spec §3 lists the normalized
// shape that future renames (out of scope for M1) will converge on.
package audit

import (
	"errors"
	"fmt"
)

// Category groups events for the viewer and for retention defaults.
type Category string

const (
	CategoryAuth    Category = "auth"
	CategorySession Category = "session"
	CategoryOIDC    Category = "oidc"
	CategoryAuthz   Category = "authz"
	CategoryAdmin   Category = "admin"
	CategoryPrivacy Category = "privacy"
	CategoryDenial  Category = "denial"
	CategorySetup   Category = "setup"
)

// RetentionBucket selects the M5 retention partition. `security` rows
// live 1y hot + 6y cold; `operational` rows live 90 days only.
type RetentionBucket string

const (
	BucketSecurity    RetentionBucket = "security"
	BucketOperational RetentionBucket = "operational"
)

// EventTypeSpec carries the per-event metadata that the rest of the
// system needs at emit time, retention time, and stream time.
type EventTypeSpec struct {
	Category        Category
	RetentionBucket RetentionBucket
	IsCritical      bool   // REQ-AUD-060: failure to write returns 5xx
	OutboundCAEP    string // CAEP SET URN, empty if not projected
}

// ErrUnknownEventType is returned by Emit when an event_type is not
// registered. This is fail-closed: an unregistered event must not slip
// through silently because retention + streaming behaviour is undefined
// for it.
var ErrUnknownEventType = errors.New("audit: unregistered event_type")

// CAEP SET URNs from OpenID Shared Signals. Public schema identifiers,
// not secrets — gosec false-positives on the "credential" literal.
//
//nolint:gosec // G101: public CAEP schema URN, not a credential
const (
	caepSessionRevoked   = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	caepCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	caepAccountDisabled  = "https://schemas.openid.net/secevent/caep/event-type/account-disabled"
	caepRiskLevelChange  = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
)

// EventTypes is the frozen registry. Keep entries grouped by category so
// future additions stay consistent. Population order is alphabetical
// inside each group.
var EventTypes = map[string]EventTypeSpec{
	// --- Authentication (REQ-AUD-001) ---
	"account.locked":                 {Category: CategoryAuth, RetentionBucket: BucketSecurity, IsCritical: true, OutboundCAEP: caepAccountDisabled},
	"auth.permission_denied":         {Category: CategoryDenial, RetentionBucket: BucketSecurity},
	"auth.stepup.failed":             {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"auth.stepup.required":           {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"auth.stepup.satisfied":          {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"login.failed":                   {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"login.succeeded":                {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"logout.completed":               {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"mfa.challenge_failed":           {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"mfa.challenge_succeeded":        {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"mfa.enrollment_completed":       {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"mfa.recovery_code_used":         {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"mfa.reset":                      {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"mfa.self_reset":                 {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"password.changed":               {Category: CategoryAuth, RetentionBucket: BucketSecurity, OutboundCAEP: caepCredentialChange},
	"password_reset.admin_blocked":   {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"password_reset.cleanup_swept":   {Category: CategoryAuth, RetentionBucket: BucketOperational},
	"password_reset.completed":       {Category: CategoryAuth, RetentionBucket: BucketSecurity, OutboundCAEP: caepCredentialChange},
	"password_reset.confirm_failed":  {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"password_reset.recovery_issued": {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"password_reset.requested":       {Category: CategoryAuth, RetentionBucket: BucketSecurity},

	// --- Session lifecycle (REQ-AUD-002) ---
	"session.reauth_forced": {Category: CategorySession, RetentionBucket: BucketSecurity},
	"session.revoked":       {Category: CategorySession, RetentionBucket: BucketSecurity, OutboundCAEP: caepSessionRevoked},
	"session.terminated":    {Category: CategorySession, RetentionBucket: BucketSecurity, OutboundCAEP: caepSessionRevoked},

	// --- OIDC / OAuth protocol (REQ-AUD-003) ---
	"oidc.authorize.invalid_request": {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.authorize.succeeded":       {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.client.auth_failed":        {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.code.client_mismatch":      {Category: CategoryOIDC, RetentionBucket: BucketSecurity, IsCritical: true},
	"oidc.code.exchanged":            {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.code.grant_removed":        {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.code.pkce_mismatch":        {Category: CategoryOIDC, RetentionBucket: BucketSecurity, IsCritical: true},
	"oidc.code.redirect_mismatch":    {Category: CategoryOIDC, RetentionBucket: BucketSecurity, IsCritical: true},
	"oidc.code.replay_detected":      {Category: CategoryOIDC, RetentionBucket: BucketSecurity, IsCritical: true},
	"oidc.code.scope_removed":        {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.code.user_disabled":        {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.code.user_not_found":       {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.refresh.reuse_detected":    {Category: CategoryOIDC, RetentionBucket: BucketSecurity, IsCritical: true, OutboundCAEP: caepRiskLevelChange},
	"oidc.refresh.user_disabled":     {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.signing_key.generated":     {Category: CategoryAdmin, RetentionBucket: BucketSecurity},
	"oidc.signing_key.retired":       {Category: CategoryAdmin, RetentionBucket: BucketSecurity, IsCritical: true},
	"oidc.signing_key.rotated":       {Category: CategoryAdmin, RetentionBucket: BucketSecurity, IsCritical: true},
	"oidc.token.refreshed":           {Category: CategoryOIDC, RetentionBucket: BucketSecurity},
	"oidc.userinfo.accessed":         {Category: CategoryOIDC, RetentionBucket: BucketOperational},

	// --- Administrative (REQ-AUD-005) ---
	"client.created":               {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"client.deleted":               {Category: CategoryAdmin, RetentionBucket: BucketSecurity, IsCritical: true},
	"client.disabled":              {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"client.enabled":               {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"client.grants_updated":        {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"client.name_updated":          {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"client.redirect_uris_updated": {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"client.scopes_updated":        {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"client.secret_rotated":        {Category: CategoryAdmin, RetentionBucket: BucketSecurity, IsCritical: true, OutboundCAEP: caepCredentialChange},

	"user.audit_pseudonymized":    {Category: CategoryPrivacy, RetentionBucket: BucketSecurity},
	"user.created":                {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"user.deleted":                {Category: CategoryAdmin, RetentionBucket: BucketSecurity},
	"user.disabled":               {Category: CategoryAdmin, RetentionBucket: BucketSecurity, OutboundCAEP: caepAccountDisabled},
	"user.enabled":                {Category: CategoryAdmin, RetentionBucket: BucketOperational},
	"user.password_reset":         {Category: CategoryAdmin, RetentionBucket: BucketSecurity, OutboundCAEP: caepCredentialChange},
	"user.revoke_before_enforced": {Category: CategoryAuth, RetentionBucket: BucketSecurity},
	"user.revoke_before_set":      {Category: CategoryAdmin, RetentionBucket: BucketSecurity, IsCritical: true, OutboundCAEP: caepSessionRevoked},
	"user.sessions_terminated":    {Category: CategoryAdmin, RetentionBucket: BucketSecurity, OutboundCAEP: caepSessionRevoked},
	"user.updated":                {Category: CategoryAdmin, RetentionBucket: BucketOperational},

	// --- Privacy / audit-of-audit (REQ-AUD-006) ---
	"audit.anchor.created":  {Category: CategoryPrivacy, RetentionBucket: BucketSecurity},
	"audit.exported":        {Category: CategoryPrivacy, RetentionBucket: BucketSecurity},
	"audit.purge.executed":  {Category: CategoryPrivacy, RetentionBucket: BucketSecurity, IsCritical: true},
	"audit.purge.requested": {Category: CategoryPrivacy, RetentionBucket: BucketSecurity},
	"audit.stream.dropped":  {Category: CategoryPrivacy, RetentionBucket: BucketSecurity},
	"audit.viewed":          {Category: CategoryPrivacy, RetentionBucket: BucketOperational},
	"privacy.user.erased":   {Category: CategoryPrivacy, RetentionBucket: BucketSecurity, IsCritical: true},

	// --- Setup (REQ-AUD-008) ---
	"setup.completed": {Category: CategorySetup, RetentionBucket: BucketSecurity},
}

// configChangeKeys lists the instance_config keys that emit
// `config.<key>.changed` events from the settings handler. Kept here so
// the registry stays the single source of truth — adding a new
// instance_config key without updating this slice fails fast at startup.
var configChangeKeys = []string{
	"access_token_ttl_secs",
	"audit.anchor.backend",
	"audit.anchor.bucket",
	"audit.anchor.events_per_anchor",
	"audit.anchor.interval_secs",
	"audit.anchor.path",
	"audit.client_ip_mode",
	"audit.cold_tier.backend",
	"audit_export_max_rows",
	"audit_view_logging_enabled",
	"audit.retention.operational_days",
	"audit.retention.security_cold_years",
	"audit.retention.security_hot_days",
	"audit.stream.backend",
	"audit.stream.batch_size",
	"audit.stream.endpoint",
	"audit.stream.poll_secs",
	"audit.stream.token_ref",
	"instance_name",
	"lockout_duration_secs",
	"lockout_threshold",
	"mfa_required",
	"password_min_length",
	"password_require_digit",
	"password_require_upper",
	"refresh_token_ttl_secs",
	"smtp_from",
	"smtp_host",
	"smtp_password",
	"smtp_port",
	"smtp_username",
}

func init() {
	for _, k := range configChangeKeys {
		eventType := "config." + k + ".changed"
		if _, dup := EventTypes[eventType]; dup {
			panic(fmt.Sprintf("audit: duplicate registry entry for %q", eventType))
		}
		EventTypes[eventType] = EventTypeSpec{
			Category:        CategoryAdmin,
			RetentionBucket: BucketOperational,
		}
	}
}

// Lookup returns the spec for an event_type and whether it is registered.
func Lookup(eventType string) (EventTypeSpec, bool) {
	spec, ok := EventTypes[eventType]
	return spec, ok
}
