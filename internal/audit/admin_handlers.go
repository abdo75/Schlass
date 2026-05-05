package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/httputil"
)

func (h *Handler) PutRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SecurityHotDays   int `json:"security_hot_days"`
		SecurityColdYears int `json:"security_cold_years"`
		OperationalDays   int `json:"operational_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.SecurityHotDays <= 0 || req.OperationalDays <= 0 || req.SecurityColdYears*365 < req.SecurityHotDays {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid retention window.")
		return
	}
	changes := []configChange{
		{key: "audit.retention.security_hot_days", value: req.SecurityHotDays},
		{key: "audit.retention.security_cold_years", value: req.SecurityColdYears},
		{key: "audit.retention.operational_days", value: req.OperationalDays},
	}
	if err := h.applyConfigChanges(r, changes); err != nil {
		if errors.Is(err, errInvalidSession) {
			httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
			return
		}
		writeErr(w, "audit.PutRetention", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// PostPurge records an operator purge request. It does not run cmd/audit-purge
// in-process because that job requires the audit_purge_runner DSN, which the
// web application intentionally does not hold.
func (h *Handler) PostPurge(w http.ResponseWriter, r *http.Request) {
	user, ok := h.currentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeErr(w, "audit.PostPurge begin", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.audit.Emit(r.Context(), tx, Event{
		EventType:  "audit.purge.requested",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "audit_log",
		TargetID:   "global",
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
	}); err != nil {
		writeErr(w, "audit.PostPurge audit", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeErr(w, "audit.PostPurge commit", err)
		return
	}
	httputil.WriteJSON(w, http.StatusAccepted, map[string]any{"queued": false, "operator_action": "run cmd/audit-purge out of band"})
}

func (h *Handler) PutAnchor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Backend         string `json:"backend"`
		Bucket          string `json:"bucket"`
		Path            string `json:"path"`
		EventsPerAnchor int    `json:"events_per_anchor"`
		IntervalSecs    int    `json:"interval_secs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	switch req.Backend {
	case "appendfile", "s3", "gcs", "none":
	default:
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid anchor backend.")
		return
	}
	if req.EventsPerAnchor <= 0 || req.IntervalSecs <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid anchor cadence.")
		return
	}
	changes := []configChange{
		{key: "audit.anchor.backend", value: req.Backend},
		{key: "audit.anchor.bucket", value: req.Bucket},
		{key: "audit.anchor.path", value: req.Path},
		{key: "audit.anchor.events_per_anchor", value: req.EventsPerAnchor},
		{key: "audit.anchor.interval_secs", value: req.IntervalSecs},
	}
	if err := h.applyConfigChanges(r, changes); err != nil {
		if errors.Is(err, errInvalidSession) {
			httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
			return
		}
		writeErr(w, "audit.PutAnchor", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) PostErase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	targetID, err := uuid.Parse(req.UserID)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid user_id.")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Erasure reason is required.")
		return
	}
	user, ok := h.currentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeErr(w, "audit.PostErase begin", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	rows, err := h.audit.PseudonymizeUser(r.Context(), tx, targetID)
	if err != nil {
		writeErr(w, "audit.PostErase pseudonymize", err)
		return
	}
	if err := h.audit.Emit(r.Context(), tx, Event{
		EventType:  "privacy.user.erased",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   targetID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"reason": reason, "rows_updated": rows},
	}); err != nil {
		writeErr(w, "audit.PostErase audit", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeErr(w, "audit.PostErase commit", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"rows_updated": rows})
}

type configChange struct {
	key   string
	value any
}

// errInvalidSession is returned by applyConfigChanges when the request reaches
// the handler with no CurrentUser in context. The handler maps this to 401
// INVALID_SESSION; defense-in-depth — the route is also gated by
// authMW + RequirePermission + RequireRecentMFA upstream, so reaching here
// without a user is a wiring bug, never a normal response path.
var errInvalidSession = errors.New("audit.applyConfigChanges: no current user")

func (h *Handler) applyConfigChanges(r *http.Request, changes []configChange) error {
	user, ok := h.currentUser(r.Context())
	if !ok {
		return errInvalidSession
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	for _, c := range changes {
		var oldRaw json.RawMessage
		newRaw, err := json.Marshal(c.value)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(r.Context(), `SELECT value FROM instance_config WHERE key = $1`, c.key).Scan(&oldRaw); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(oldRaw), newRaw) {
			continue
		}
		if err := h.cfg.Set(r.Context(), tx, c.key, c.value); err != nil {
			return err
		}
		if err := h.emitConfigChanged(r, tx, user, c.key, json.RawMessage(oldRaw), c.value); err != nil {
			return err
		}
	}
	return tx.Commit(r.Context())
}

func (h *Handler) emitConfigChanged(r *http.Request, tx pgx.Tx, user CurrentUser, key string, oldValue, newValue any) error {
	if err := h.audit.Emit(r.Context(), tx, Event{
		EventType:  "config." + key + ".changed",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "instance_config",
		TargetID:   key,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"old_value": oldValue, "new_value": newValue},
	}); err != nil {
		slog.Error("audit config change: emit failed", "key", key, "error", err)
		return err
	}
	return nil
}
