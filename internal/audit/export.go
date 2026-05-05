package audit

import (
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abdo75/Schlass/internal/httputil"
)

func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Since      string   `json:"since"`
		Until      string   `json:"until"`
		View       string   `json:"view"`
		Actor      string   `json:"actor"`
		TargetType string   `json:"target_type"`
		TargetID   string   `json:"target_id"`
		EventTypes []string `json:"event_types"`
		Format     string   `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	values := url.Values{}
	values.Set("since", req.Since)
	values.Set("until", req.Until)
	values.Set("view", req.View)
	values.Set("actor", req.Actor)
	values.Set("target_type", req.TargetType)
	values.Set("target_id", req.TargetID)
	if len(req.EventTypes) > 0 {
		values.Set("event_types", joinEventTypes(req.EventTypes))
	}
	q := parseListQuery(values)
	format := req.Format
	if format != "csv" && format != "jsonl" {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "format must be csv or jsonl")
		return
	}

	ctx := r.Context()
	user, ok := h.currentUser(ctx)
	if !ok {
		// Defense-in-depth: Export runs behind authMW + RequirePermission +
		// RequireRecentMFA, so missing user is a wiring bug. REQ-AUD-041
		// self-include must always fire.
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	capRows, err := h.cfg.GetInt(ctx, h.pool, "audit_export_max_rows")
	if err != nil {
		writeErr(w, "audit.Export cap", err)
		return
	}
	where, args := q.toSQLWithSelfAudit(user.ID)

	var totalMatching int
	if err := h.pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_logs a WHERE "+where, args...).Scan(&totalMatching); err != nil {
		writeErr(w, "audit.Export count", err)
		return
	}
	truncated := capRows > 0 && totalMatching > capRows
	if truncated {
		w.Header().Set("X-Audit-Truncated", "true")
	}

	rows, err := h.pool.Query(ctx, listSelectSQL+" WHERE "+where+" ORDER BY a.created_at DESC", args...)
	if err != nil {
		writeErr(w, "audit.Export query", err)
		return
	}
	defer rows.Close()

	emitted := 0
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="audit-log.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "created_at", "event_type", "outcome", "actor_email", "actor_display", "target_type", "target_id", "target_display", "ip_address", "metadata_json"})
		for rows.Next() {
			if capRows > 0 && emitted >= capRows {
				break
			}
			item, err := scanItem(rows)
			if err != nil {
				writeErr(w, "audit.Export csv scan", err)
				return
			}
			mj, _ := json.Marshal(item.Metadata)
			_ = cw.Write([]string{
				item.ID, item.CreatedAt.Format(time.RFC3339), item.EventType, item.Outcome,
				ptrStr(item.ActorEmail), item.ActorDisplay,
				ptrStr(item.TargetType), ptrStr(item.TargetID), ptrStr(item.TargetDisplay),
				ptrStr(item.IPAddress), string(mj),
			})
			emitted++
		}
		cw.Flush()
	case "jsonl":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="audit-log.jsonl"`)
		enc := json.NewEncoder(w)
		for rows.Next() {
			if capRows > 0 && emitted >= capRows {
				break
			}
			item, err := scanItem(rows)
			if err != nil {
				writeErr(w, "audit.Export jsonl scan", err)
				return
			}
			_ = enc.Encode(item)
			emitted++
		}
	}
	if err := rows.Err(); err != nil {
		writeErr(w, "audit.Export rows", err)
		return
	}
	if err := h.emitExported(r, format, q, emitted, truncated); err != nil {
		slog.Warn("audit.exported emit failed after export response", "error", err)
	}
}

func (h *Handler) emitExported(r *http.Request, format string, q ListQuery, rowCount int, truncated bool) error {
	user, ok := h.currentUser(r.Context())
	if !ok {
		return nil
	}
	ctx := r.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.audit.Emit(ctx, tx, Event{
		EventType:  "audit.exported",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "audit_log",
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"format":            format,
			"view":              q.View,
			"since":             q.Since.Format(time.RFC3339),
			"until":             q.Until.Format(time.RFC3339),
			"event_types_count": len(q.EventTypes),
			"row_count":         rowCount,
			"truncated":         truncated,
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func ptrStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func joinEventTypes(v []string) string {
	out := make([]string, 0, len(v))
	for _, item := range v {
		if item != "" {
			out = append(out, item)
		}
	}
	return strings.Join(out, ",")
}
