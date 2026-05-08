package audit

import (
	"archive/tar"
	"compress/gzip"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit/stream"
	"github.com/abdo75/Schlass/internal/httputil"
)

// exportManifest is written as manifest.json inside every export tarball.
// It carries enough chain metadata for an independent verifier to re-walk
// the exported segment without access to the full audit_logs table.
type exportManifest struct {
	ExportedAt      time.Time    `json:"exported_at"`
	TenantID        string       `json:"tenant_id"`
	SequenceRange   [2]int64     `json:"sequence_range"`
	RowHashAtStart  string       `json:"row_hash_at_start"`
	RowHashAtEnd    string       `json:"row_hash_at_end"`
	AnchorProof     *anchorProof `json:"anchor_proof"`
	Format          string       `json:"format"`
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
	dataFilename, dataBytes, err := buildDataFile(format, collected)
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

func buildDataFile(format string, rows []exportRecord) (filename string, data []byte, err error) {
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
		// ProjectCAEP requires a stream.Event. We build a minimal one from
		// the ItemDTO fields that are available in the export view.
		var sb strings.Builder
		for _, r := range rows {
			evt := itemToStreamEvent(r.item, r.chain.SequenceNo)
			claims, _, ok, projErr := ProjectCAEP(evt, "")
			if projErr != nil {
				return "", nil, fmt.Errorf("caep projection %s: %w", r.item.EventType, projErr)
			}
			if !ok {
				// No CAEP mapping — skip silently.
				slog.Debug("audit.Export caep: skipping unmapped event", "event_type", r.item.EventType)
				continue
			}
			line, mErr := json.Marshal(claims)
			if mErr != nil {
				return "", nil, fmt.Errorf("caep marshal %s: %w", r.item.EventType, mErr)
			}
			sb.Write(line)
			sb.WriteByte('\n')
		}
		return "audit-log.set.jsonl", []byte(sb.String()), nil

	default:
		return "", nil, fmt.Errorf("unknown format %q", format)
	}
}

// itemToStreamEvent builds a minimal stream.Event from an ItemDTO for CAEP
// projection. It only populates fields that ProjectCAEP actually uses.
func itemToStreamEvent(item ItemDTO, seqNo int64) stream.Event {
	e := stream.Event{
		SequenceNo:     seqNo,
		EventType:      item.EventType,
		EventTimestamp: item.CreatedAt,
		Outcome:        item.Outcome,
		ActorType:      "system",
		TargetType:     item.TargetType,
		TargetID:       item.TargetID,
	}
	if id, err := uuid.Parse(item.ID); err == nil {
		e.ID = id
	}
	if item.ActorID != nil {
		if id, err := uuid.Parse(*item.ActorID); err == nil {
			e.ActorID = &id
			e.ActorType = "user"
		}
	}
	return e
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
