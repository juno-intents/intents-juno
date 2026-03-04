package backoffice

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleRecentDeposits returns the most recent deposit jobs.
func (s *Server) handleRecentDeposits(w http.ResponseWriter, r *http.Request) {
	limit := parseIntParam(r, "limit", 20)
	if limit > 200 {
		limit = 200
	}

	rows, err := s.cfg.Pool.Query(r.Context(), `
		SELECT deposit_id, state, created_at, COALESCE(juno_height, 0),
		       base_recipient, tx_hash, amount
		FROM deposit_jobs
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		s.log.Error("query recent deposits", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer rows.Close()

	items := make([]map[string]any, 0)
	for rows.Next() {
		var depositID []byte
		var state int16
		var createdAt time.Time
		var junoHeight int64
		var baseRecipient []byte
		var txHash []byte
		var amount int64
		if err := rows.Scan(&depositID, &state, &createdAt, &junoHeight, &baseRecipient, &txHash, &amount); err != nil {
			s.log.Error("scan recent deposit", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		entry := map[string]any{
			"depositId":     "0x" + hex.EncodeToString(depositID),
			"state":         state,
			"createdAt":     createdAt.Format(time.RFC3339),
			"junoHeight":    junoHeight,
			"baseRecipient": "0x" + hex.EncodeToString(baseRecipient),
			"amount":        strconv.FormatInt(amount, 10),
		}
		if len(txHash) > 0 {
			entry["txHash"] = "0x" + hex.EncodeToString(txHash)
		}
		items = append(items, entry)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("iterate recent deposits", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    items,
	})
}

// handleRecentWithdrawals returns the most recent withdrawal requests.
func (s *Server) handleRecentWithdrawals(w http.ResponseWriter, r *http.Request) {
	limit := parseIntParam(r, "limit", 20)
	if limit > 200 {
		limit = 200
	}

	rows, err := s.cfg.Pool.Query(r.Context(), `
		SELECT wr.withdrawal_id, COALESCE(wr.claimed_by, ''), wr.created_at,
		       COALESCE(wr.base_block_number, 0),
		       wr.requester, wr.amount, wr.recipient_ua,
		       wb.juno_txid, wb.base_tx_hash
		FROM withdrawal_requests wr
		LEFT JOIN withdrawal_batch_items wbi ON wbi.withdrawal_id = wr.withdrawal_id
		LEFT JOIN withdrawal_batches wb ON wb.batch_id = wbi.batch_id
		ORDER BY wr.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		s.log.Error("query recent withdrawals", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer rows.Close()

	items := make([]map[string]any, 0)
	for rows.Next() {
		var withdrawalID []byte
		var state string
		var createdAt time.Time
		var baseBlockNumber int64
		var requester []byte
		var amount int64
		var recipientUA []byte
		var junoTxID *string
		var baseTxHash *string
		if err := rows.Scan(&withdrawalID, &state, &createdAt, &baseBlockNumber,
			&requester, &amount, &recipientUA, &junoTxID, &baseTxHash); err != nil {
			s.log.Error("scan recent withdrawal", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		entry := map[string]any{
			"withdrawalId":    "0x" + hex.EncodeToString(withdrawalID),
			"state":           state,
			"createdAt":       createdAt.Format(time.RFC3339),
			"baseBlockNumber": baseBlockNumber,
			"requester":       "0x" + hex.EncodeToString(requester),
			"amount":          strconv.FormatInt(amount, 10),
			"recipientUA":     "0x" + hex.EncodeToString(recipientUA),
		}
		if junoTxID != nil {
			entry["junoTxId"] = *junoTxID
		}
		if baseTxHash != nil {
			entry["baseTxHash"] = *baseTxHash
		}
		items = append(items, entry)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("iterate recent withdrawals", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    items,
	})
}

// handleStuckBatches returns deposit jobs and withdrawal batches that appear stuck.
// A record is considered stuck if it is in a non-terminal state and was last
// updated more than 30 minutes ago.
func (s *Server) handleStuckBatches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	threshold := time.Now().UTC().Add(-30 * time.Minute)

	// Stuck deposit jobs: state NOT IN (5=submitted, 6=finalized) and updated_at old.
	stuckDeposits, err := s.fetchStuckDeposits(ctx, threshold)
	if err != nil {
		s.log.Error("fetch stuck deposits", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	// Stuck withdrawal batches: state NOT IN (7=finalized) and updated_at old.
	stuckWithdrawals, err := s.fetchStuckWithdrawalBatches(ctx, threshold)
	if err != nil {
		s.log.Error("fetch stuck withdrawal batches", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":          "v1",
		"stuckDeposits":    stuckDeposits,
		"stuckWithdrawals": stuckWithdrawals,
		"thresholdMinutes": 30,
	})
}

func (s *Server) fetchStuckDeposits(ctx context.Context, threshold time.Time) ([]map[string]any, error) {
	rows, err := s.cfg.Pool.Query(ctx, `
		SELECT deposit_id, state, created_at, updated_at
		FROM deposit_jobs
		WHERE state NOT IN (5, 6)
		  AND updated_at < $1
		ORDER BY updated_at ASC
		LIMIT 100`, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]map[string]any, 0)
	for rows.Next() {
		var depositID []byte
		var state int16
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&depositID, &state, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"depositId": "0x" + hex.EncodeToString(depositID),
			"state":     state,
			"createdAt": createdAt.Format(time.RFC3339),
			"updatedAt": updatedAt.Format(time.RFC3339),
			"stuckFor":  fmt.Sprintf("%.0fm", time.Since(updatedAt).Minutes()),
		})
	}
	return items, rows.Err()
}

func (s *Server) fetchStuckWithdrawalBatches(ctx context.Context, threshold time.Time) ([]map[string]any, error) {
	rows, err := s.cfg.Pool.Query(ctx, `
		SELECT batch_id, state, created_at, updated_at
		FROM withdrawal_batches
		WHERE state NOT IN (7)
		  AND updated_at < $1
		ORDER BY updated_at ASC
		LIMIT 100`, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]map[string]any, 0)
	for rows.Next() {
		var batchID []byte
		var state int16
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&batchID, &state, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"batchId":   "0x" + hex.EncodeToString(batchID),
			"state":     state,
			"createdAt": createdAt.Format(time.RFC3339),
			"updatedAt": updatedAt.Format(time.RFC3339),
			"stuckFor":  fmt.Sprintf("%.0fm", time.Since(updatedAt).Minutes()),
		})
	}
	return items, rows.Err()
}

// handleServicesHealth polls each configured service healthz URL and returns
// the results.
func (s *Server) handleServicesHealth(w http.ResponseWriter, r *http.Request) {
	results := make([]map[string]any, 0, len(s.cfg.ServiceURLs))
	client := &http.Client{Timeout: 5 * time.Second}

	for _, u := range s.cfg.ServiceURLs {
		result := checkServiceHealth(r.Context(), client, u)
		results = append(results, result)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    results,
	})
}

// checkServiceHealth probes a single healthz endpoint and returns the result.
func checkServiceHealth(ctx context.Context, client *http.Client, url string) map[string]any {
	start := time.Now()
	result := map[string]any{
		"url":     url,
		"healthy": false,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result["error"] = err.Error()
		result["latencyMs"] = time.Since(start).Milliseconds()
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result["error"] = err.Error()
		result["latencyMs"] = time.Since(start).Milliseconds()
		return result
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse.
	_, _ = io.ReadAll(resp.Body)

	latency := time.Since(start).Milliseconds()
	result["latencyMs"] = latency

	if resp.StatusCode == http.StatusOK {
		result["healthy"] = true
	} else {
		result["error"] = fmt.Sprintf("status %d", resp.StatusCode)
	}

	return result
}

// handleOperatorStatus probes each configured operator gRPC endpoint via TLS
// and reports online/offline status with latency.
func (s *Server) handleOperatorStatus(w http.ResponseWriter, r *http.Request) {
	results := make([]map[string]any, 0, len(s.cfg.OperatorEndpoints))

	for _, op := range s.cfg.OperatorEndpoints {
		start := time.Now()
		online := false
		var errMsg string

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp",
			op.Endpoint,
			&tls.Config{InsecureSkipVerify: true}, //nolint:gosec // operator TLS probe only
		)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			errMsg = err.Error()
		} else {
			online = true
			_ = conn.Close()
		}

		entry := map[string]any{
			"address":   op.Address.Hex(),
			"endpoint":  op.Endpoint,
			"online":    online,
			"latencyMs": latency,
		}
		if errMsg != "" {
			entry["error"] = errMsg
		}
		results = append(results, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":   "v1",
		"operators": results,
	})
}

// parseIntParam extracts an integer query parameter with a default.
func parseIntParam(r *http.Request, name string, defaultVal int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}
