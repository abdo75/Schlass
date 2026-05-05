package audit

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ListQuery struct {
	Since      time.Time
	Until      time.Time
	View       string
	Actor      string
	TargetType string
	TargetID   string
	EventTypes []string
	Outcome    string
	Search     string
	Page       int
	PageSize   int
}

func parseListQuery(v url.Values) (ListQuery, error) {
	// Stable viewer filter contract. Keep the current SPA names
	// (event_types/actor/since/until) and add the spec-mandated outcome + q.
	// Unknown query parameters are rejected so filter drift fails closed.
	accepted := map[string]struct{}{
		"actor":       {},
		"event_types": {},
		"outcome":     {},
		"page":        {},
		"page_size":   {},
		"q":           {},
		"since":       {},
		"target_id":   {},
		"target_type": {},
		"until":       {},
		"view":        {},
	}
	for key := range v {
		if _, ok := accepted[key]; !ok {
			return ListQuery{}, fmt.Errorf("unknown query parameter %q", key)
		}
	}
	until := parseTimeOrNow(v.Get("until"))
	q := ListQuery{
		Until:      until,
		View:       defaultString(v.Get("view"), "all"),
		Actor:      v.Get("actor"),
		TargetType: v.Get("target_type"),
		TargetID:   v.Get("target_id"),
		Outcome:    v.Get("outcome"),
		Search:     strings.TrimSpace(v.Get("q")),
		Page:       clamp(parseIntOr(v.Get("page"), 1), 1, 1_000_000),
		PageSize:   clamp(parseIntOr(v.Get("page_size"), 25), 1, 100),
	}
	if q.Outcome != "" && q.Outcome != "success" && q.Outcome != "failure" && q.Outcome != "denied" {
		return ListQuery{}, fmt.Errorf("outcome must be success, failure, or denied")
	}
	q.Since = parseSinceOr(v.Get("since"), until.Add(-24*time.Hour), until)
	if et := v.Get("event_types"); et != "" {
		for _, item := range strings.Split(et, ",") {
			if item = strings.TrimSpace(item); item != "" {
				q.EventTypes = append(q.EventTypes, item)
			}
		}
	}
	return q, nil
}

func (q ListQuery) toSQL() (string, []any) {
	parts := []string{"a.created_at >= $1", "a.created_at <= $2"}
	args := []any{q.Since, q.Until}

	if q.View != "all" {
		parts = append(parts, viewClause(q.View))
	}
	if q.Actor == "system" {
		parts = append(parts, "a.actor_id IS NULL")
	} else if q.Actor != "" {
		// REQ-AUD-011 (M2): actor_email is gone from audit_logs. Filter
		// resolves the live email via a users sub-select; rows whose
		// actor was deleted/pseudonymized fall out of the match set.
		parts = append(parts, "a.actor_id = (SELECT id FROM users WHERE email = $"+strconv.Itoa(len(args)+1)+" LIMIT 1)")
		args = append(args, q.Actor)
	}
	if q.TargetType == "system" {
		parts = append(parts, "a.target_type = ANY($"+strconv.Itoa(len(args)+1)+")")
		args = append(args, systemTargetTypes())
	} else if q.TargetType != "" {
		parts = append(parts, "a.target_type = $"+strconv.Itoa(len(args)+1))
		args = append(args, q.TargetType)
	}
	if q.TargetID != "" {
		parts = append(parts, "a.target_id = $"+strconv.Itoa(len(args)+1))
		args = append(args, q.TargetID)
	}
	if len(q.EventTypes) > 0 {
		parts = append(parts, "a.event_type = ANY($"+strconv.Itoa(len(args)+1)+")")
		args = append(args, q.EventTypes)
	}
	if q.Outcome != "" {
		parts = append(parts, "a.outcome = $"+strconv.Itoa(len(args)+1))
		args = append(args, q.Outcome)
	}
	if q.Search != "" {
		// v1 free-text implementation: simple ILIKE over reason_code and the
		// JSON metadata payload. Full-text indexes are intentionally out of M7.
		// User-supplied `_` and `%` are LIKE wildcards; escape them so a
		// search for `audit_log` matches the literal underscore, not any-char.
		escaped := likeEscape(q.Search)
		parts = append(parts, "(COALESCE(a.reason_code, '') ILIKE $"+strconv.Itoa(len(args)+1)+" ESCAPE '\\' OR COALESCE(a.metadata::text, '') ILIKE $"+strconv.Itoa(len(args)+1)+" ESCAPE '\\')")
		args = append(args, "%"+escaped+"%")
	}
	return strings.Join(parts, " AND "), args
}

func (q ListQuery) toSQLWithSelfAudit(callerID uuid.UUID) (string, []any) {
	where, args := q.toSQL()
	args = append(args, callerID)
	// REQ-AUD-041 applies to the concrete list/export result set. Actors and
	// Targets intentionally use toSQL() because they are bucket helpers for the
	// same UI; the rows remain visible in List/Export even under hostile filters.
	selfClause := "(a.event_type = 'audit.viewed' AND a.actor_id = $" + strconv.Itoa(len(args)) + " AND a.created_at >= $1 AND a.created_at <= $2)"
	return "((" + where + ") OR " + selfClause + ")", args
}

func viewClause(view string) string {
	switch view {
	case "sign-in":
		return "a.event_type IN ('login.succeeded','login.failed','logout.completed','session.revoked','session.terminated','session.reauth_forced','account.locked','mfa.challenge_succeeded','mfa.challenge_failed','mfa.recovery_code_used')"
	case "admin":
		return "a.actor_id IS NOT NULL AND (a.event_type LIKE 'user.%' OR a.event_type LIKE 'client.%' OR a.event_type LIKE 'config.%' OR a.event_type IN ('mfa.reset','oidc.signing_key.rotated','oidc.signing_key.retired'))"
	case "client":
		return "a.event_type LIKE 'client.%'"
	default:
		return "TRUE"
	}
}

func parseTimeOrNow(s string) time.Time {
	if s == "" || s == "now" {
		return time.Now().UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func parseSinceOr(s string, fallback time.Time, until time.Time) time.Time {
	if s == "" {
		return fallback
	}
	if t, ok := parseRelativeSince(s, until); ok {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return fallback
}

func parseRelativeSince(s string, until time.Time) (time.Time, bool) {
	if len(s) < 2 {
		return time.Time{}, false
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return time.Time{}, false
	}
	switch s[len(s)-1] {
	case 'h':
		return until.Add(-time.Duration(n) * time.Hour), true
	case 'd':
		return until.AddDate(0, 0, -n), true
	default:
		return time.Time{}, false
	}
}

func parseIntOr(s string, fallback int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

func clamp(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func systemTargetTypes() []string {
	return []string{"config", "instance_config", "audit_log", "signing_key", "instance", "permission"}
}

// likeEscape escapes the LIKE meta-characters `\`, `%`, `_` so user-supplied
// `q` is matched literally. Paired with `ESCAPE '\\'` in the SQL fragment.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func likeEscape(s string) string {
	return likeEscaper.Replace(s)
}
