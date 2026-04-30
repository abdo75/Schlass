package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/session"
)

type Handler struct {
	pool        *pgxpool.Pool
	sessions    session.Store
	cfg         *instanceconfig.Service
	audit       Logger
	currentUser func(context.Context) (CurrentUser, bool)
}

type CurrentUser struct {
	ID    uuid.UUID
	Email string
}

func NewHandler(pool *pgxpool.Pool, sessions session.Store, cfg *instanceconfig.Service, audit Logger, currentUser func(context.Context) (CurrentUser, bool)) *Handler {
	return &Handler{pool: pool, sessions: sessions, cfg: cfg, audit: audit, currentUser: currentUser}
}

type ListResponse struct {
	Items    []ItemDTO `json:"items"`
	Total    int       `json:"total"`
	Page     int       `json:"page"`
	PageSize int       `json:"page_size"`
}

type ItemDTO struct {
	ID                 string         `json:"id"`
	EventType          string         `json:"event_type"`
	Outcome            string         `json:"outcome"`
	ActorID            *string        `json:"actor_id"`
	ActorEmail         *string        `json:"actor_email"`
	ActorDisplay       string         `json:"actor_display"`
	ActorPseudonymized bool           `json:"actor_pseudonymized"`
	TargetType         *string        `json:"target_type"`
	TargetID           *string        `json:"target_id"`
	TargetDisplay      *string        `json:"target_display"`
	ClientID           *string        `json:"client_id"`
	IPAddress          *string        `json:"ip_address"`
	Metadata           map[string]any `json:"metadata"`
	CreatedAt          time.Time      `json:"created_at"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := parseListQuery(r.URL.Query())
	where, args := q.toSQL()
	ctx := r.Context()

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		writeErr(w, "audit.List begin", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var total int
	if err := tx.QueryRow(ctx, "SELECT COUNT(*) FROM audit_logs a WHERE "+where, args...).Scan(&total); err != nil {
		writeErr(w, "audit.List count", err)
		return
	}

	queryArgs := append(append([]any{}, args...), q.PageSize, (q.Page-1)*q.PageSize)
	rows, err := tx.Query(ctx, listSelectSQL+" WHERE "+where+" ORDER BY a.created_at DESC LIMIT $"+
		strconv.Itoa(len(args)+1)+" OFFSET $"+strconv.Itoa(len(args)+2), queryArgs...)
	if err != nil {
		writeErr(w, "audit.List query", err)
		return
	}
	items, err := scanItems(rows)
	if err != nil {
		writeErr(w, "audit.List scan", err)
		return
	}

	if err := h.maybeEmitViewed(ctx, tx, r); err != nil {
		writeErr(w, "audit.List viewed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, "audit.List commit", err)
		return
	}
	h.markViewedAfterCommit(r.Context())

	httputil.WriteJSON(w, http.StatusOK, ListResponse{Items: items, Total: total, Page: q.Page, PageSize: q.PageSize})
}

type ActorsResponse struct {
	Users       []ActorBucket `json:"users"`
	SystemCount int           `json:"system_count"`
}

type ActorBucket struct {
	ActorID    string `json:"actor_id"`
	ActorEmail string `json:"actor_email"`
	Count      int    `json:"count"`
}

func (h *Handler) Actors(w http.ResponseWriter, r *http.Request) {
	q := parseListQuery(r.URL.Query())
	where, args := q.toSQL()
	ctx := r.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT a.actor_id::text, a.actor_email, COUNT(*)
		FROM audit_logs a
		WHERE `+where+` AND a.actor_id IS NOT NULL AND a.actor_email IS NOT NULL
		GROUP BY a.actor_id, a.actor_email
		ORDER BY COUNT(*) DESC
		LIMIT 100`, args...)
	if err != nil {
		writeErr(w, "audit.Actors query", err)
		return
	}
	defer rows.Close()
	out := ActorsResponse{Users: []ActorBucket{}}
	for rows.Next() {
		var b ActorBucket
		if err := rows.Scan(&b.ActorID, &b.ActorEmail, &b.Count); err != nil {
			writeErr(w, "audit.Actors scan", err)
			return
		}
		out.Users = append(out.Users, b)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, "audit.Actors rows", err)
		return
	}
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs a WHERE `+where+` AND a.actor_id IS NULL`, args...).Scan(&out.SystemCount); err != nil {
		writeErr(w, "audit.Actors system count", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

type TargetsResponse struct {
	Items []TargetBucket `json:"items"`
}

type TargetBucket struct {
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Display    string `json:"display"`
	Extra      string `json:"extra,omitempty"`
}

func (h *Handler) Targets(w http.ResponseWriter, r *http.Request) {
	q := parseListQuery(r.URL.Query())
	targetType := r.URL.Query().Get("type")
	if targetType == "" {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "type required")
		return
	}

	if targetType == "system" {
		h.systemTargets(w, r, q)
		return
	}

	where, args := q.toSQL()
	args = append(args, targetType)
	where += " AND a.target_type = $" + strconv.Itoa(len(args))

	selectExtra := ""
	join := ""
	switch targetType {
	case "client":
		selectExtra = ", COALESCE(c.client_type, '')"
		join = "LEFT JOIN clients c ON c.id::text = a.target_id"
	case "user":
		selectExtra = ", COALESCE(u.role, '')"
		join = "LEFT JOIN users u ON u.id::text = a.target_id"
	}

	rows, err := h.pool.Query(r.Context(), `
		SELECT DISTINCT a.target_id, COALESCE(`+coalesceDisplay(targetType)+`) AS display`+selectExtra+`
		FROM audit_logs a
		`+join+`
		WHERE `+where+` AND a.target_id IS NOT NULL AND a.target_id <> ''
		ORDER BY display ASC
		LIMIT 200`, args...)
	if err != nil {
		writeErr(w, "audit.Targets query", err)
		return
	}
	defer rows.Close()
	out := TargetsResponse{Items: []TargetBucket{}}
	for rows.Next() {
		b := TargetBucket{TargetType: targetType}
		if selectExtra == "" {
			if err := rows.Scan(&b.TargetID, &b.Display); err != nil {
				writeErr(w, "audit.Targets scan", err)
				return
			}
		} else if err := rows.Scan(&b.TargetID, &b.Display, &b.Extra); err != nil {
			writeErr(w, "audit.Targets scan", err)
			return
		}
		out.Items = append(out.Items, b)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, "audit.Targets rows", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) systemTargets(w http.ResponseWriter, r *http.Request, q ListQuery) {
	where, args := q.toSQL()
	args = append(args, systemTargetTypes())
	where += " AND a.target_type = ANY($" + strconv.Itoa(len(args)) + ")"

	rows, err := h.pool.Query(r.Context(), `
		SELECT DISTINCT a.target_type, COALESCE(a.target_id, ''),
			CASE
				WHEN a.target_type = 'signing_key' THEN LEFT(a.target_id, 8)
				WHEN a.target_type = 'instance' THEN COALESCE(a.metadata->>'instance_name', 'Instance')
				WHEN a.target_type = 'audit_log' THEN 'Audit log'
				ELSE COALESCE(NULLIF(a.target_id, ''), a.target_type)
			END AS display
		FROM audit_logs a
		WHERE `+where+`
		ORDER BY display ASC
		LIMIT 200`, args...)
	if err != nil {
		writeErr(w, "audit.systemTargets query", err)
		return
	}
	defer rows.Close()
	out := TargetsResponse{Items: []TargetBucket{}}
	for rows.Next() {
		var b TargetBucket
		if err := rows.Scan(&b.TargetType, &b.TargetID, &b.Display); err != nil {
			writeErr(w, "audit.systemTargets scan", err)
			return
		}
		b.Extra = humanizeTargetType(b.TargetType)
		out.Items = append(out.Items, b)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, "audit.systemTargets rows", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func humanizeTargetType(t string) string {
	switch t {
	case "signing_key":
		return "Signing key"
	case "instance":
		return "Instance"
	case "instance_config", "config":
		return "Setting"
	case "audit_log":
		return "Audit log"
	case "permission":
		return "Permission"
	default:
		return t
	}
}

func coalesceDisplay(t string) string {
	// Always return at least two arguments — single-arg COALESCE is invalid SQL.
	switch t {
	case "client":
		return "c.name, a.target_id"
	case "user":
		return "u.email, 'Former user'"
	default:
		return "a.target_id, ''"
	}
}

func scanItems(rows pgx.Rows) ([]ItemDTO, error) {
	defer rows.Close()
	var items []ItemDTO
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanItem(row pgx.Row) (ItemDTO, error) {
	var item ItemDTO
	var actorID, actorEmail, targetType, targetID, targetDisplay, clientID, ipAddress sql.NullString
	var metadata []byte
	if err := row.Scan(
		&item.ID, &item.EventType, &item.Outcome,
		&actorID, &actorEmail, &item.ActorDisplay, &item.ActorPseudonymized,
		&targetType, &targetID, &targetDisplay,
		&clientID, &ipAddress, &metadata, &item.CreatedAt,
	); err != nil {
		return ItemDTO{}, err
	}
	item.ActorID = nullableString(actorID)
	item.ActorEmail = nullableString(actorEmail)
	item.TargetType = nullableString(targetType)
	item.TargetID = nullableString(targetID)
	item.TargetDisplay = nullableString(targetDisplay)
	item.ClientID = nullableString(clientID)
	item.IPAddress = nullableString(ipAddress)
	item.Metadata = map[string]any{}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &item.Metadata); err != nil {
			return ItemDTO{}, err
		}
	}
	return item, nil
}

func nullableString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

func writeErr(w http.ResponseWriter, msg string, err error) {
	slog.Error(msg, "error", err)
	httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return xff[:i]
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Handler) maybeEmitViewed(ctx context.Context, tx pgx.Tx, r *http.Request) error {
	enabled, err := h.cfg.GetBool(ctx, h.pool, "audit_view_logging_enabled")
	if err != nil || !enabled {
		return nil
	}
	user, ok := h.currentUser(ctx)
	if !ok {
		return nil
	}
	token, ok := session.TokenFromContext(ctx)
	if !ok {
		return nil
	}
	sess, err := h.sessions.Get(ctx, token)
	if err != nil || sess == nil || sess.AuditViewedInSession {
		return nil
	}
	return h.audit.Emit(ctx, tx, Event{
		EventType:  "audit.viewed",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "audit_log",
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
	})
}

func (h *Handler) markViewedAfterCommit(ctx context.Context) {
	token, ok := session.TokenFromContext(ctx)
	if !ok {
		return
	}
	if err := h.sessions.MarkAuditViewed(ctx, token); err != nil {
		slog.Warn("audit: MarkAuditViewed failed; next request may re-emit audit.viewed", "error", err)
	}
}
