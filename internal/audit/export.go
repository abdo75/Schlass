package audit

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abdo75/Schlass/internal/audit/stream"
	"github.com/abdo75/Schlass/internal/httputil"
)

// exportManifest is written as manifest.json inside every export tarball.
// It carries enough chain metadata for an independent verifier to re-walk
// the exported segment without access to the full audit_logs table.
type exportManifest struct {
	ExportedAt     time.Time    `json:"exported_at"`
	TenantID       string       `json:"tenant_id"`
	SequenceRange  [2]int64     `json:"sequence_range"`
	RowHashAtStart string       `json:"row_hash_at_start"`
	RowHashAtEnd   string       `json:"row_hash_at_end"`
	AnchorProof    *anchorProof `json:"anchor_proof"`
	Format         string       `json:"format"`
}

type anchorProof struct {
	Backend    string    `json:"backend"`
	Ref        string    `json:"ref"`
	AnchoredAt time.Time `json:"anchored_at"`
	SequenceNo int64     `json:"sequence_no"`
}

// exportRow holds the chain fields for the manifest alongside the ItemDTO.
type exportRow struct {
	SequenceNo int64
	RowHash    []byte
	PrevHash   []byte
}

// exportRecord bundles chain metadata with the viewer-friendly ItemDTO.
type exportRecord struct {
	chain exportRow
	item  ItemDTO
}

// caepSignFn signs a CAEP claim map and returns the JWS string.
type caepSignFn func(claims map[string]any) (string, error)

func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Since      string   `json:"since"`
		Until      string   `json:"until"`
		View       string   `json:"view"`
		Actor      string   `json:"actor"`
		TargetType string   `json:"target_type"`
		TargetID   string   `json:"target_id"`
		EventTypes []string `json:"event_types"`
		Outcome    string   `json:"outcome"`
		Search     string   `json:"q"`
		Format     string   `json:"format"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
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
	values.Set("outcome", req.Outcome)
	values.Set("q", req.Search)
	if len(req.EventTypes) > 0 {
		values.Set("event_types", joinEventTypes(req.EventTypes))
	}
	q, err := parseListQuery(values)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	format := req.Format
	if format != "csv" && format != "jsonl" && format != "caep" {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "format must be csv, jsonl, or caep")
		return
	}

	ctx := r.Context()

	// For CAEP exports every row must be signed (REQ-AUD-052). Validate
	// signing availability before touching the DB so we can return a clean
	// 503 without having written any tar bytes.
	var signFn caepSignFn
	if format == "caep" {
		fn, signingErr := h.resolveCAEPSignFn(ctx)
		if signingErr != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, "SIGNING_UNAVAILABLE", "Signing key unavailable; retry later.")
			return
		}
		signFn = fn
	}

	user, ok := h.currentUser(ctx)
	if !ok {
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

	// Query includes sequence_no, row_hash, prev_hash for the manifest alongside
	// the view columns. Use a combined query so we only scan once.
	chainSQL := `SELECT a.sequence_no, a.row_hash, a.prev_hash, ` +
		// Strip leading SELECT from listSelectSQL (starts with newline+SELECT)
		trimSelectKeyword(listSelectSQL) +
		` WHERE ` + where + ` ORDER BY a.created_at DESC`
	rows, err := h.pool.Query(ctx, chainSQL, args...)
	if err != nil {
		writeErr(w, "audit.Export query", err)
		return
	}
	defer rows.Close()

	// Collect rows into memory (cap-bounded).
	var collected []exportRecord
	for rows.Next() {
		if capRows > 0 && len(collected) >= capRows {
			break
		}
		var cr exportRow
		var rowHashBytes, prevHashBytes []byte
		// We scan sequence_no, row_hash, prev_hash first, then the 14 listSelectSQL cols.
		var item ItemDTO
		var actorIDStr, actorEmail, targetType, targetID, targetDisplay, clientID, ipAddress nullableStr
		var metadata []byte
		if err := rows.Scan(
			&cr.SequenceNo, &rowHashBytes, &prevHashBytes,
			&item.ID, &item.EventType, &item.Outcome,
			&actorIDStr, &actorEmail, &item.ActorDisplay, &item.ActorPseudonymized,
			&targetType, &targetID, &targetDisplay,
			&clientID, &ipAddress, &metadata, &item.CreatedAt,
		); err != nil {
			writeErr(w, "audit.Export scan", err)
			return
		}
		cr.RowHash = rowHashBytes
		cr.PrevHash = prevHashBytes
		item.ActorID = nsPtr(actorIDStr)
		item.ActorEmail = nsPtr(actorEmail)
		item.TargetType = nsPtr(targetType)
		item.TargetID = nsPtr(targetID)
		item.TargetDisplay = nsPtr(targetDisplay)
		item.ClientID = nsPtr(clientID)
		item.IPAddress = nsPtr(ipAddress)
		item.Metadata = map[string]any{}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &item.Metadata)
		}
		collected = append(collected, exportRecord{chain: cr, item: item})
	}
	if err := rows.Err(); err != nil {
		writeErr(w, "audit.Export rows", err)
		return
	}

	// For CAEP format: run a separate SQL query that fetches the raw columns
	// ProjectCAEP actually needs (actor_type, reason_code, etc.). The viewer
	// DTO scan above does not carry these fields reliably.
	var caepEvents []stream.Event
	if format == "caep" {
		caepEvents, err = h.collectCAEPEvents(ctx, where, args, capRows)
		if err != nil {
			writeErr(w, "audit.Export caep query", err)
			return
		}
	}

	// Build manifest fields from collected rows (rows are DESC by created_at).
	// Lowest seq is last element; highest seq is first element.
	var (
		minSeq      int64
		maxSeq      int64
		hashAtStart string // prev_hash of lowest-seq row
		hashAtEnd   string // row_hash of highest-seq row
	)
	if len(collected) > 0 {
		// DESC order: first=highest seq, last=lowest seq.
		highIdx := 0
		lowIdx := len(collected) - 1
		for i, r := range collected {
			if r.chain.SequenceNo < collected[lowIdx].chain.SequenceNo {
				lowIdx = i
			}
			if r.chain.SequenceNo > collected[highIdx].chain.SequenceNo {
				highIdx = i
			}
		}
		minSeq = collected[lowIdx].chain.SequenceNo
		maxSeq = collected[highIdx].chain.SequenceNo
		hashAtStart = hex.EncodeToString(collected[lowIdx].chain.PrevHash)
		hashAtEnd = hex.EncodeToString(collected[highIdx].chain.RowHash)
	}

	// Look up smallest anchor with sequence_no >= maxSeq for this tenant.
	tenantID := SingleTenant
	var proof *anchorProof
	if maxSeq > 0 {
		var ap anchorProof
		err := h.pool.QueryRow(ctx,
			`SELECT backend, proof_ref, anchored_at, sequence_no
			   FROM audit_anchors
			  WHERE tenant_id = $1 AND sequence_no >= $2
			  ORDER BY sequence_no ASC
			  LIMIT 1`,
			tenantID, maxSeq,
		).Scan(&ap.Backend, &ap.Ref, &ap.AnchoredAt, &ap.SequenceNo)
		if err == nil {
			proof = &ap
		} else {
			slog.Warn("audit.Export: no anchor proof for range", "tenant_id", tenantID, "max_seq", maxSeq)
		}
	}

	manifest := exportManifest{
		ExportedAt:     time.Now().UTC(),
		TenantID:       tenantID.String(),
		SequenceRange:  [2]int64{minSeq, maxSeq},
		RowHashAtStart: hashAtStart,
		RowHashAtEnd:   hashAtEnd,
		AnchorProof:    proof,
		Format:         format,
	}

	ts := time.Now().UTC().Format("20060102-1504")
	filename := fmt.Sprintf("audit-log-%s.tar.gz", ts)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	// Build data file content in memory so we know its size for the tar header.
	dataFilename, dataBytes, err := buildDataFile(format, collected, caepEvents, signFn, h.issuer)
	if err != nil {
		// Headers already sent — log and bail.
		slog.Error("audit.Export: build data file", "error", err)
		return
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		slog.Error("audit.Export: marshal manifest", "error", err)
		return
	}

	for _, entry := range []struct {
		name string
		data []byte
	}{
		{dataFilename, dataBytes},
		{"manifest.json", manifestBytes},
	} {
		hdr := &tar.Header{
			Name:    entry.name,
			Mode:    0o644,
			Size:    int64(len(entry.data)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			slog.Error("audit.Export: tar header", "name", entry.name, "error", err)
			return
		}
		if _, err := tw.Write(entry.data); err != nil {
			slog.Error("audit.Export: tar write", "name", entry.name, "error", err)
			return
		}
	}
	if err := tw.Close(); err != nil {
		slog.Error("audit.Export: tar close", "error", err)
		return
	}
	if err := gz.Close(); err != nil {
		slog.Error("audit.Export: gzip close", "error", err)
		return
	}

	if err := h.emitExported(r, format, q, len(collected), truncated, proof, minSeq, maxSeq); err != nil {
		slog.Warn("audit.exported emit failed after export response", "error", err)
	}
}

// resolveCAEPSignFn fetches the active signing key, unwraps it, and returns
// a closure that signs CAEP claim maps. Returns an error if any required
// dependency is absent (empty issuer, nil key functions, or key fetch fails).
func (h *Handler) resolveCAEPSignFn(ctx context.Context) (caepSignFn, error) {
	if h.issuer == "" || h.fetchKey == nil || h.unwrapKey == nil || len(h.encryptionKey) == 0 {
		return nil, fmt.Errorf("caep signing not configured")
	}
	kid, encrypted, err := h.fetchKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("caep: fetch active key: %w", err)
	}
	privPEM, err := h.unwrapKey(encrypted, h.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("caep: unwrap key: %w", err)
	}
	kidCopy := kid
	privCopy := privPEM
	return func(claims map[string]any) (string, error) {
		return SignCAEP(claims, kidCopy, privCopy)
	}, nil
}

// collectCAEPEvents runs the raw-column SQL query and returns stream.Events
// suitable for ProjectCAEP. Uses scanEvent (which handles actor_type,
// reason_code, etc.) so the projection gets accurate field values.
// inet columns (client_ip_coarse, client_geo_coarse) are cast to text so
// pgx can scan them into *string without binary-format type errors.
func (h *Handler) collectCAEPEvents(ctx context.Context, where string, args []any, capRows int) ([]stream.Event, error) {
	caepSQL := `SELECT a.id, a.tenant_id, a.sequence_no, a.event_type, a.event_timestamp, a.outcome, a.reason_code,
	                   a.actor_type, a.actor_id, a.actor_session_id, a.target_type, a.target_id,
	                   a.source_service, a.client_ip_coarse::text, a.client_geo_coarse::text, a.client_ua_family,
	                   a.request_id, a.correlation_id, a.retention_bucket, a.metadata
	              FROM audit_logs a
	             WHERE ` + where + ` ORDER BY a.created_at DESC`
	rows, err := h.pool.Query(ctx, caepSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stream.Event
	for rows.Next() {
		if capRows > 0 && len(out) >= capRows {
			break
		}
		evt, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, evt)
	}
	return out, rows.Err()
}

// buildDataFile produces the tarball data file for the given format.
// For csv/jsonl it uses the already-collected exportRecord slice.
// For caep it uses pre-collected caepEvents (raw stream.Events) so
// ProjectCAEP gets accurate actor_type and reason_code fields.
func buildDataFile(
	format string,
	rows []exportRecord,
	caepEvents []stream.Event,
	signFn caepSignFn,
	issuer string,
) (filename string, data []byte, err error) {
	switch format {
	case "csv":
		var sb strings.Builder
		cw := csv.NewWriter(&sb)
		_ = cw.Write([]string{"id", "created_at", "event_type", "outcome", "actor_email", "actor_display", "target_type", "target_id", "target_display", "ip_address", "metadata_json"})
		for _, r := range rows {
			mj, _ := json.Marshal(r.item.Metadata)
			_ = cw.Write([]string{
				r.item.ID, r.item.CreatedAt.Format(time.RFC3339), r.item.EventType, r.item.Outcome,
				ptrStr(r.item.ActorEmail), r.item.ActorDisplay,
				ptrStr(r.item.TargetType), ptrStr(r.item.TargetID), ptrStr(r.item.TargetDisplay),
				ptrStr(r.item.IPAddress), string(mj),
			})
		}
		cw.Flush()
		return "audit-log.csv", []byte(sb.String()), nil

	case "jsonl":
		var sb strings.Builder
		enc := json.NewEncoder(&sb)
		for _, r := range rows {
			_ = enc.Encode(r.item)
		}
		return "audit-log.jsonl", []byte(sb.String()), nil

	case "caep":
		var sb strings.Builder
		for _, evt := range caepEvents {
			claims, _, ok, projErr := ProjectCAEP(evt, issuer)
			if projErr != nil {
				return "", nil, fmt.Errorf("caep projection %s: %w", evt.EventType, projErr)
			}
			if !ok {
				slog.Debug("audit.Export caep: skipping unmapped event", "event_type", evt.EventType)
				continue
			}
			jws, signErr := signFn(claims)
			if signErr != nil {
				return "", nil, fmt.Errorf("caep sign %s: %w", evt.EventType, signErr)
			}
			sb.WriteString(jws)
			sb.WriteByte('\n')
		}
		return "audit-log.set.jsonl", []byte(sb.String()), nil

	default:
		return "", nil, fmt.Errorf("unknown format %q", format)
	}
}

func (h *Handler) emitExported(r *http.Request, format string, q ListQuery, rowCount int, truncated bool, proof *anchorProof, minSeq, maxSeq int64) error {
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
	meta := map[string]any{
		"format":            format,
		"view":              q.View,
		"since":             q.Since.Format(time.RFC3339),
		"until":             q.Until.Format(time.RFC3339),
		"event_types_count": len(q.EventTypes),
		"row_count":         rowCount,
		"truncated":         truncated,
		"sequence_range":    fmt.Sprintf("[%d,%d]", minSeq, maxSeq),
	}
	if proof != nil {
		meta["anchor_proof_ref"] = proof.Ref
	}
	if err := h.audit.Emit(ctx, tx, Event{
		EventType:  "audit.exported",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "audit_log",
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   meta,
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

// trimSelectKeyword strips the leading "SELECT" keyword from a SQL snippet
// that starts with "\nSELECT " so it can be appended after a custom prefix.
func trimSelectKeyword(sql string) string {
	trimmed := strings.TrimSpace(sql)
	if strings.HasPrefix(trimmed, "SELECT") {
		return trimmed[len("SELECT"):]
	}
	return trimmed
}

// nullableStr wraps sql.NullString for the inline scanner in Export.
type nullableStr = nullStr

type nullStr struct {
	Valid  bool
	String string
}

func (n *nullStr) Scan(src any) error {
	if src == nil {
		n.Valid = false
		n.String = ""
		return nil
	}
	switch v := src.(type) {
	case string:
		n.Valid = true
		n.String = v
		return nil
	case []byte:
		n.Valid = true
		n.String = string(v)
		return nil
	}
	return fmt.Errorf("nullStr: unsupported type %T", src)
}

func nsPtr(n nullableStr) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}
