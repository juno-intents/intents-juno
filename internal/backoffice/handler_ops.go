package backoffice

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
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
		SELECT deposit_id, state, created_at, COALESCE(juno_height, 0)
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
		if err := rows.Scan(&depositID, &state, &createdAt, &junoHeight); err != nil {
			s.log.Error("scan recent deposit", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		items = append(items, map[string]any{
			"depositId":  "0x" + hex.EncodeToString(depositID),
			"state":      state,
			"createdAt":  createdAt.Format(time.RFC3339),
			"junoHeight": junoHeight,
		})
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
		SELECT withdrawal_id, COALESCE(claimed_by, ''), created_at, COALESCE(base_block_number, 0)
		FROM withdrawal_requests
		ORDER BY created_at DESC
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
		if err := rows.Scan(&withdrawalID, &state, &createdAt, &baseBlockNumber); err != nil {
			s.log.Error("scan recent withdrawal", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		items = append(items, map[string]any{
			"withdrawalId":    "0x" + hex.EncodeToString(withdrawalID),
			"state":           state,
			"createdAt":       createdAt.Format(time.RFC3339),
			"baseBlockNumber": baseBlockNumber,
		})
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
