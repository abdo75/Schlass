// Appendfile stores anchor proofs as JSONL on a local append-only path.
// Operators provide filesystem immutability, while this backend serialises
// writers with flock and verifies proofs by re-reading the recorded line.
package anchor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const AppendFileBackend = "appendfile"

type AppendFile struct {
	dir string
}

var _ Anchor = (*AppendFile)(nil)

func NewAppendFile(dir string) *AppendFile {
	return &AppendFile{dir: dir}
}

type appendFileRecord struct {
	TenantID   string `json:"tenant_id"`
	SequenceNo int64  `json:"sequence_no"`
	RowHash    string `json:"row_hash"`
	AnchoredAt string `json:"anchored_at"`
}

func (a *AppendFile) Submit(ctx context.Context, head ChainHead) (ProofRef, error) {
	if err := ctx.Err(); err != nil {
		return ProofRef{}, err
	}
	if a.dir == "" {
		return ProofRef{}, errors.New("appendfile anchor: path is required")
	}
	if err := os.MkdirAll(a.dir, 0o750); err != nil {
		return ProofRef{}, fmt.Errorf("appendfile anchor: mkdir: %w", err)
	}
	anchoredAt := head.AnchoredAt
	if anchoredAt.IsZero() {
		anchoredAt = time.Now().UTC()
	}
	path := filepath.Join(a.dir, "anchors-"+anchoredAt.Format("200601")+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // G302: plan requires operator-readable 0640 JSONL anchors.
	if err != nil {
		return ProofRef{}, fmt.Errorf("appendfile anchor: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := flock(f, syscall.LOCK_EX); err != nil {
		return ProofRef{}, err
	}
	defer func() { _ = flock(f, syscall.LOCK_UN) }()

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return ProofRef{}, fmt.Errorf("appendfile anchor: seek: %w", err)
	}
	rec := appendFileRecord{
		TenantID:   head.TenantID.String(),
		SequenceNo: head.SequenceNo,
		RowHash:    hex.EncodeToString(head.RowHash),
		AnchoredAt: anchoredAt.UTC().Format(time.RFC3339Nano),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return ProofRef{}, fmt.Errorf("appendfile anchor: marshal: %w", err)
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return ProofRef{}, fmt.Errorf("appendfile anchor: write: %w", err)
	}
	return ProofRef{Backend: AppendFileBackend, Ref: path + "#offset=" + strconv.FormatInt(offset, 10)}, nil
}

func (a *AppendFile) Verify(ctx context.Context, head ChainHead, proof ProofRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, offset, hasOffset, err := parseAppendFileRef(proof.Ref)
	if err != nil {
		return err
	}
	f, err := os.Open(path) //nolint:gosec // G304: proof refs are produced by this backend and stored server-side.
	if err != nil {
		return fmt.Errorf("appendfile anchor: verify open: %w", err)
	}
	defer func() { _ = f.Close() }()
	if hasOffset {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("appendfile anchor: verify seek: %w", err)
		}
		line, err := bufio.NewReader(f).ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("appendfile anchor: verify read: %w", err)
		}
		return verifyAppendFileLine(line, head)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := verifyAppendFileLine(scanner.Bytes(), head); err == nil {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("appendfile anchor: verify scan: %w", err)
	}
	return errors.New("appendfile anchor: matching proof not found")
}

func verifyAppendFileLine(line []byte, head ChainHead) error {
	line = bytes.TrimSpace(line)
	var rec appendFileRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return fmt.Errorf("appendfile anchor: verify unmarshal: %w", err)
	}
	if rec.TenantID != head.TenantID.String() || rec.SequenceNo != head.SequenceNo {
		return errors.New("appendfile anchor: tenant or sequence mismatch")
	}
	if rec.RowHash != hex.EncodeToString(head.RowHash) {
		return errors.New("appendfile anchor: row_hash mismatch")
	}
	return nil
}

func parseAppendFileRef(ref string) (string, int64, bool, error) {
	path, suffix, ok := strings.Cut(ref, "#offset=")
	if !ok {
		if ref == "" {
			return "", 0, false, errors.New("appendfile anchor: empty proof ref")
		}
		return ref, 0, false, nil
	}
	offset, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil || offset < 0 {
		return "", 0, false, errors.New("appendfile anchor: invalid proof offset")
	}
	return path, offset, true, nil
}

func flock(f *os.File, how int) error {
	if err := syscall.Flock(int(f.Fd()), how); err != nil { //nolint:gosec // G115: file descriptors fit syscall.Flock's int ABI on supported platforms.
		return fmt.Errorf("appendfile anchor: flock: %w", err)
	}
	return nil
}
