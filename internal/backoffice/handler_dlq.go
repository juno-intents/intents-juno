package backoffice

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/juno-intents/intents-juno/internal/dlq"
)

// handleDLQListProofs returns proof DLQ records with optional filtering.
func (s *Server) handleDLQListProofs(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DLQStore == nil {
		writeError(w, http.StatusServiceUnavailable, "dlq_store_not_configured")
		return
	}

	filter := parseDLQFilter(r)
	records, err := s.cfg.DLQStore.ListProofDLQ(r.Context(), filter)
	if err != nil {
		s.log.Error("list proof dlq", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		items = append(items, proofDLQToJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    items,
	})
}

// handleDLQListDeposits returns deposit batch DLQ records.
func (s *Server) handleDLQListDeposits(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DLQStore == nil {
		writeError(w, http.StatusServiceUnavailable, "dlq_store_not_configured")
		return
	}

	filter := parseDLQFilter(r)
	records, err := s.cfg.DLQStore.ListDepositBatchDLQ(r.Context(), filter)
	if err != nil {
		s.log.Error("list deposit batch dlq", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		items = append(items, depositBatchDLQToJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    items,
	})
}

// handleDLQListWithdrawals returns withdrawal batch DLQ records.
func (s *Server) handleDLQListWithdrawals(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DLQStore == nil {
		writeError(w, http.StatusServiceUnavailable, "dlq_store_not_configured")
		return
	}

	filter := parseDLQFilter(r)
	records, err := s.cfg.DLQStore.ListWithdrawalBatchDLQ(r.Context(), filter)
	if err != nil {
		s.log.Error("list withdrawal batch dlq", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		items = append(items, withdrawalBatchDLQToJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    items,
	})
}

// handleDLQAcknowledge marks a DLQ record as acknowledged.
func (s *Server) handleDLQAcknowledge(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DLQStore == nil {
		writeError(w, http.StatusServiceUnavailable, "dlq_store_not_configured")
		return
	}

	dlqType := r.PathValue("type")
	idHex := r.PathValue("id")

	tableName, ok := dlqTypeToTable(dlqType)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_dlq_type")
		return
	}

	idBytes, err := decodeHexID(idHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id")
		return
	}

	if err := s.cfg.DLQStore.Acknowledge(r.Context(), tableName, idBytes); err != nil {
		s.log.Error("acknowledge dlq", "table", tableName, "id", idHex, "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":      "v1",
		"acknowledged": true,
	})
}

// handleDLQCounts returns unacknowledged counts per DLQ category.
func (s *Server) handleDLQCounts(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DLQStore == nil {
		writeError(w, http.StatusServiceUnavailable, "dlq_store_not_configured")
		return
	}

	counts, err := s.cfg.DLQStore.CountUnacknowledged(r.Context())
	if err != nil {
		s.log.Error("count dlq", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data": map[string]any{
			"proofs":      counts.Proofs,
			"deposits":    counts.DepositBatches,
			"withdrawals": counts.WithdrawalBatches,
		},
	})
}

// parseDLQFilter extracts DLQ filter parameters from the query string.
func parseDLQFilter(r *http.Request) dlq.DLQFilter {
	q := r.URL.Query()
	filter := dlq.DLQFilter{
		Limit:  100,
		Offset: 0,
	}

	if ec := strings.TrimSpace(q.Get("error_code")); ec != "" {
		filter.ErrorCode = ec
	}
	if ack := strings.TrimSpace(q.Get("acknowledged")); ack != "" {
		val := ack == "true" || ack == "1"
		filter.Acknowledged = &val
	}
	if l := strings.TrimSpace(q.Get("limit")); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			filter.Limit = v
		}
	}
	if o := strings.TrimSpace(q.Get("offset")); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			filter.Offset = v
		}
	}
	return filter
}

// dlqTypeToTable maps URL path DLQ type to the database table name.
func dlqTypeToTable(t string) (string, bool) {
	switch t {
	case "proofs":
		return "proof_dlq", true
	case "deposits":
		return "deposit_batch_dlq", true
	case "withdrawals":
		return "withdrawal_batch_dlq", true
	default:
		return "", false
	}
}

// decodeHexID decodes a 0x-prefixed or plain hex string into bytes.
func decodeHexID(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

func proofDLQToJSON(rec dlq.ProofDLQRecord) map[string]any {
	m := map[string]any{
		"jobId":        hex32(rec.JobID),
		"pipeline":     rec.Pipeline,
		"imageId":      hex32(rec.ImageID),
		"state":        rec.State,
		"errorCode":    rec.ErrorCode,
		"errorMessage": rec.ErrorMessage,
		"attemptCount": rec.AttemptCount,
		"createdAt":    rec.CreatedAt.Format(time.RFC3339),
		"acknowledged": rec.Acknowledged,
	}
	if rec.AckAt != nil {
		m["ackAt"] = rec.AckAt.Format(time.RFC3339)
	}
	return m
}

func depositBatchDLQToJSON(rec dlq.DepositBatchDLQRecord) map[string]any {
	ids := make([]string, len(rec.DepositIDs))
	for i, id := range rec.DepositIDs {
		ids[i] = hex32(id)
	}
	m := map[string]any{
		"batchId":      hex32(rec.BatchID),
		"depositIds":   ids,
		"itemsCount":   rec.ItemsCount,
		"state":        rec.State,
		"failureStage": rec.FailureStage,
		"errorCode":    rec.ErrorCode,
		"errorMessage": rec.ErrorMessage,
		"attemptCount": rec.AttemptCount,
		"createdAt":    rec.CreatedAt.Format(time.RFC3339),
		"acknowledged": rec.Acknowledged,
	}
	if rec.AckAt != nil {
		m["ackAt"] = rec.AckAt.Format(time.RFC3339)
	}
	return m
}

func withdrawalBatchDLQToJSON(rec dlq.WithdrawalBatchDLQRecord) map[string]any {
	ids := make([]string, len(rec.WithdrawalIDs))
	for i, id := range rec.WithdrawalIDs {
		ids[i] = hex32(id)
	}
	m := map[string]any{
		"batchId":             hex32(rec.BatchID),
		"withdrawalIds":       ids,
		"itemsCount":          rec.ItemsCount,
		"state":               rec.State,
		"failureStage":        rec.FailureStage,
		"errorCode":           rec.ErrorCode,
		"errorMessage":        rec.ErrorMessage,
		"rebroadcastAttempts": rec.RebroadcastAttempts,
		"junoTxId":            rec.JunoTxID,
		"createdAt":           rec.CreatedAt.Format(time.RFC3339),
		"acknowledged":        rec.Acknowledged,
	}
	if rec.AckAt != nil {
		m["ackAt"] = rec.AckAt.Format(time.RFC3339)
	}
	return m
}
