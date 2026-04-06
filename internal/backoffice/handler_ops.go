package backoffice

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func depositStateIsStuck(s int16) bool {
	return s < 6
}

type stuckRows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

// depositStateLabel maps deposit_jobs.state int16 to a human-readable label.
func depositStateLabel(s int16) string {
	switch s {
	case 0:
		return "unknown"
	case 1:
		return "seen"
	case 2:
		return "confirmed"
	case 3:
		return "proof_requested"
	case 4:
		return "proof_ready"
	case 5:
		return "submitted"
	case 6:
		return "finalized"
	case 7:
		return "rejected"
	default:
		return fmt.Sprintf("state_%d", s)
	}
}

// batchStateLabel maps withdrawal_batches.state int16 to a human-readable label.
func batchStateLabel(s int16) string {
	switch s {
	case 0:
		return "unknown"
	case 1:
		return "planned"
	case 2:
		return "signing"
	case 3:
		return "signed"
	case 4:
		return "broadcasted"
	case 5:
		return "juno_confirmed"
	case 6:
		return "confirmed"
	case 7:
		return "finalizing"
	case 8:
		return "finalized"
	default:
		return fmt.Sprintf("state_%d", s)
	}
}

// handleRecentDeposits returns the most recent deposit jobs.
func (s *Server) handleRecentDeposits(w http.ResponseWriter, r *http.Request) {
	limit := parseIntParam(r, "limit", 20)
	if limit > 200 {
		limit = 200
	}

	rows, err := s.cfg.Pool.Query(r.Context(), `
		SELECT deposit_id, state, created_at, COALESCE(juno_height, 0),
		       base_recipient, tx_hash, amount, rejection_reason
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
		var rejectionReason *string
		if err := rows.Scan(&depositID, &state, &createdAt, &junoHeight, &baseRecipient, &txHash, &amount, &rejectionReason); err != nil {
			s.log.Error("scan recent deposit", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		entry := map[string]any{
			"depositId":     "0x" + hex.EncodeToString(depositID),
			"state":         depositStateLabel(state),
			"createdAt":     createdAt.Format(time.RFC3339),
			"junoHeight":    junoHeight,
			"baseRecipient": "0x" + hex.EncodeToString(baseRecipient),
			"amount":        strconv.FormatInt(amount, 10),
		}
		if len(txHash) > 0 {
			entry["txHash"] = "0x" + hex.EncodeToString(txHash)
		}
		if rejectionReason != nil {
			entry["rejectionReason"] = *rejectionReason
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
		SELECT wr.withdrawal_id, wr.created_at,
		       COALESCE(wr.base_block_number, 0),
		       wr.requester, wr.amount, wr.recipient_ua,
		       wb.state, wb.juno_txid, wb.base_tx_hash
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
		var createdAt time.Time
		var baseBlockNumber int64
		var requester []byte
		var amount int64
		var recipientUA []byte
		var batchState *int16
		var junoTxID *string
		var baseTxHash *string
		if err := rows.Scan(&withdrawalID, &createdAt, &baseBlockNumber,
			&requester, &amount, &recipientUA, &batchState, &junoTxID, &baseTxHash); err != nil {
			s.log.Error("scan recent withdrawal", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		stateLabel := "requested"
		if batchState != nil {
			stateLabel = batchStateLabel(*batchState)
		}
		entry := map[string]any{
			"withdrawalId":    "0x" + hex.EncodeToString(withdrawalID),
			"state":           stateLabel,
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

	// Stuck deposit jobs: unresolved states (including submitted) with old updated_at.
	stuckDeposits, err := s.fetchStuckDeposits(ctx, threshold)
	if err != nil {
		s.log.Error("fetch stuck deposits", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	stuckSubmittedAttempts, err := s.fetchStuckSubmittedAttempts(ctx, threshold)
	if err != nil {
		s.log.Error("fetch stuck submitted attempts", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	stuckDeposits = append(stuckDeposits, stuckSubmittedAttempts...)

	// Stuck withdrawal batches: state NOT IN (8=finalized) and updated_at old.
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
		WHERE updated_at < $1
		ORDER BY updated_at ASC
		LIMIT 100`, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectStuckDepositRows(rows, threshold)
}

func (s *Server) fetchStuckSubmittedAttempts(ctx context.Context, threshold time.Time) ([]map[string]any, error) {
	rows, err := s.cfg.Pool.Query(ctx, `
		SELECT batch_id, owner, created_at, updated_at
		FROM deposit_batch_attempts
		WHERE updated_at < $1
		ORDER BY updated_at ASC
		LIMIT 100`, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectStuckSubmittedAttemptRows(rows, threshold)
}

func collectStuckDepositRows(rows stuckRows, threshold time.Time) ([]map[string]any, error) {
	items := make([]map[string]any, 0)
	for rows.Next() {
		var depositID []byte
		var state int16
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&depositID, &state, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if !depositStateIsStuck(state) || !updatedAt.Before(threshold) {
			continue
		}
		items = append(items, map[string]any{
			"kind":      "deposit",
			"depositId": "0x" + hex.EncodeToString(depositID),
			"state":     depositStateLabel(state),
			"createdAt": createdAt.Format(time.RFC3339),
			"updatedAt": updatedAt.Format(time.RFC3339),
			"stuckFor":  fmt.Sprintf("%.0fm", time.Since(updatedAt).Minutes()),
		})
	}
	return items, rows.Err()
}

func collectStuckSubmittedAttemptRows(rows stuckRows, threshold time.Time) ([]map[string]any, error) {
	items := make([]map[string]any, 0)
	for rows.Next() {
		var batchID []byte
		var owner string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&batchID, &owner, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if !updatedAt.Before(threshold) {
			continue
		}
		items = append(items, map[string]any{
			"kind":      "submitted_attempt",
			"batchId":   "0x" + hex.EncodeToString(batchID),
			"depositId": "0x" + hex.EncodeToString(batchID),
			"owner":     owner,
			"state":     "submitted_attempt",
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
		WHERE state NOT IN (8)
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
			"state":     batchStateLabel(state),
			"createdAt": createdAt.Format(time.RFC3339),
			"updatedAt": updatedAt.Format(time.RFC3339),
			"stuckFor":  fmt.Sprintf("%.0fm", time.Since(updatedAt).Minutes()),
		})
	}
	return items, rows.Err()
}

// handleServicesHealth polls each configured service healthz URL and built-in
// infrastructure probes (Postgres, Kafka, IPFS), returning all results.
func (s *Server) handleServicesHealth(w http.ResponseWriter, r *http.Request) {
	results := make([]map[string]any, 0, len(s.cfg.ServiceEntries)+4)
	client := &http.Client{Timeout: 5 * time.Second}

	for _, entry := range s.cfg.ServiceEntries {
		result := checkServiceHealth(r.Context(), client, entry.URL)
		result["label"] = entry.Label
		results = append(results, result)
	}

	// Built-in: Postgres
	results = append(results, s.probePostgres(r.Context()))

	// Built-in: Kafka brokers
	for _, broker := range s.cfg.KafkaBrokers {
		results = append(results, probeTCP("kafka", broker))
	}

	// Built-in: IPFS (API v0 requires POST)
	if s.cfg.IPFSApiURL != "" {
		results = append(results, probeIPFS(r.Context(), client, s.cfg.IPFSApiURL, s.cfg.IPFSApiBearerToken))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    results,
	})
}

// probeIPFS checks IPFS API connectivity using POST /api/v0/version.
func probeIPFS(ctx context.Context, client *http.Client, baseURL string, bearerToken string) map[string]any {
	start := time.Now()
	url := strings.TrimRight(baseURL, "/") + "/api/v0/version"
	result := map[string]any{
		"label":   "ipfs",
		"url":     url,
		"healthy": false,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		result["error"] = err.Error()
		result["latencyMs"] = time.Since(start).Milliseconds()
		return result
	}
	if token := strings.TrimSpace(bearerToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		result["error"] = err.Error()
		result["latencyMs"] = time.Since(start).Milliseconds()
		return result
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	result["latencyMs"] = time.Since(start).Milliseconds()
	if resp.StatusCode == http.StatusOK {
		result["healthy"] = true
	} else {
		result["error"] = fmt.Sprintf("status %d", resp.StatusCode)
	}
	return result
}

// probePostgres checks Postgres connectivity by pinging the pool.
func (s *Server) probePostgres(ctx context.Context) map[string]any {
	start := time.Now()
	err := s.cfg.Pool.Ping(ctx)
	latency := time.Since(start).Milliseconds()
	result := map[string]any{
		"label":     "postgres",
		"url":       "pgxpool",
		"healthy":   err == nil,
		"latencyMs": latency,
	}
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}

// probeTCP checks connectivity to a TCP address (used for Kafka brokers).
func probeTCP(label, addr string) map[string]any {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	latency := time.Since(start).Milliseconds()
	result := map[string]any{
		"label":     label,
		"url":       addr,
		"healthy":   err == nil,
		"latencyMs": latency,
	}
	if err != nil {
		result["error"] = err.Error()
	} else {
		_ = conn.Close()
	}
	return result
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

// handleOperatorStatus probes each configured operator signer health endpoint
// over HTTP and reports online/offline status with latency.
func (s *Server) handleOperatorStatus(w http.ResponseWriter, r *http.Request) {
	results := make([]map[string]any, 0, len(s.cfg.OperatorEndpoints))
	client := &http.Client{Timeout: 5 * time.Second}

	for _, op := range s.cfg.OperatorEndpoints {
		start := time.Now()
		online := false
		var errMsg string

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://"+op.Endpoint+"/healthz", nil)
		if err != nil {
			errMsg = err.Error()
		}
		latency := time.Since(start).Milliseconds()
		if err == nil {
			resp, reqErr := client.Do(req)
			latency = time.Since(start).Milliseconds()
			if reqErr != nil {
				errMsg = reqErr.Error()
			} else {
				defer resp.Body.Close()
				_, _ = io.ReadAll(resp.Body)
				if resp.StatusCode == http.StatusOK {
					online = true
				} else {
					errMsg = fmt.Sprintf("status %d", resp.StatusCode)
				}
			}
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
