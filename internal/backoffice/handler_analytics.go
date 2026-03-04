package backoffice

import (
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// handleAnalyticsOverview returns aggregate deposit/withdrawal counts and volume.
func (s *Server) handleAnalyticsOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp := map[string]any{
		"version": "v1",
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)

	// Total counts.
	var totalDeposits, totalWithdrawals int64
	_ = s.cfg.Pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*),0) FROM deposit_jobs`).Scan(&totalDeposits)
	_ = s.cfg.Pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*),0) FROM withdrawal_requests`).Scan(&totalWithdrawals)
	resp["totalDeposits"] = totalDeposits
	resp["totalWithdrawals"] = totalWithdrawals

	// Today's counts.
	var depositsToday, withdrawalsToday int64
	_ = s.cfg.Pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*),0) FROM deposit_jobs WHERE created_at >= $1`, today).Scan(&depositsToday)
	_ = s.cfg.Pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*),0) FROM withdrawal_requests WHERE created_at >= $1`, today).Scan(&withdrawalsToday)
	resp["depositsToday"] = depositsToday
	resp["withdrawalsToday"] = withdrawalsToday

	// Volumes (finalized only). deposit_jobs.state=6 is StateFinalized.
	var depVol, wdVol int64
	_ = s.cfg.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0) FROM deposit_jobs WHERE state = 6`).Scan(&depVol)
	_ = s.cfg.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount),0) FROM withdrawal_requests`).Scan(&wdVol)
	resp["totalDepositVolume"] = zatToJunoString(depVol)
	resp["totalWithdrawalVolume"] = zatToJunoString(wdVol)

	// Active wJUNO supply.
	if s.cfg.WJunoAddress != (common.Address{}) {
		supply, err := erc20TotalSupply(ctx, s.cfg.BaseClient, s.cfg.WJunoAddress)
		if err != nil {
			s.log.Warn("analytics: wjuno supply", "err", err)
			resp["activeWjunoSupply"] = "0"
		} else {
			resp["activeWjunoSupply"] = zatToJunoString(supply.Int64())
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleBridgesOverTime returns deposit/withdrawal counts and volumes grouped by time period.
// Query params:
//   - period: day|week|month (default day)
//   - days: number of days to look back (default 30)
func (s *Server) handleBridgesOverTime(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	period := strings.TrimSpace(q.Get("period"))
	if period == "" {
		period = "day"
	}
	switch period {
	case "day", "week", "month":
	default:
		writeError(w, http.StatusBadRequest, "invalid_period")
		return
	}

	days := 30
	if d := strings.TrimSpace(q.Get("days")); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 && v <= 365 {
			days = v
		}
	}

	since := time.Now().UTC().AddDate(0, 0, -days)

	// Deposit counts/volumes by period.
	depRows, err := s.cfg.Pool.Query(ctx, `
		SELECT date_trunc($1, created_at) AS period,
		       COUNT(*) AS cnt,
		       COALESCE(SUM(amount), 0) AS vol
		FROM deposit_jobs
		WHERE created_at >= $2
		GROUP BY period
		ORDER BY period ASC`, period, since)
	if err != nil {
		s.log.Error("analytics: deposit bridges over time", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer depRows.Close()

	type periodEntry struct {
		depositCount  int64
		withdrawCount int64
		depositVol    int64
		withdrawVol   int64
	}
	periods := make(map[string]*periodEntry)
	var order []string

	for depRows.Next() {
		var p time.Time
		var cnt, vol int64
		if err := depRows.Scan(&p, &cnt, &vol); err != nil {
			s.log.Error("analytics: scan deposit period", "err", err)
			continue
		}
		key := p.Format("2006-01-02")
		entry := &periodEntry{depositCount: cnt, depositVol: vol}
		periods[key] = entry
		order = append(order, key)
	}
	if err := depRows.Err(); err != nil {
		s.log.Error("analytics: deposit rows err", "err", err)
	}

	// Withdrawal counts/volumes by period.
	wdRows, err := s.cfg.Pool.Query(ctx, `
		SELECT date_trunc($1, created_at) AS period,
		       COUNT(*) AS cnt,
		       COALESCE(SUM(amount), 0) AS vol
		FROM withdrawal_requests
		WHERE created_at >= $2
		GROUP BY period
		ORDER BY period ASC`, period, since)
	if err != nil {
		s.log.Error("analytics: withdrawal bridges over time", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer wdRows.Close()

	for wdRows.Next() {
		var p time.Time
		var cnt, vol int64
		if err := wdRows.Scan(&p, &cnt, &vol); err != nil {
			s.log.Error("analytics: scan withdrawal period", "err", err)
			continue
		}
		key := p.Format("2006-01-02")
		entry, ok := periods[key]
		if !ok {
			entry = &periodEntry{}
			periods[key] = entry
			order = append(order, key)
		}
		entry.withdrawCount = cnt
		entry.withdrawVol = vol
	}
	if err := wdRows.Err(); err != nil {
		s.log.Error("analytics: withdrawal rows err", "err", err)
	}

	// Build response array in order.
	items := make([]map[string]any, 0, len(order))
	for _, key := range order {
		entry := periods[key]
		items = append(items, map[string]any{
			"date":             key,
			"depositCount":     entry.depositCount,
			"withdrawalCount":  entry.withdrawCount,
			"depositVolume":    zatToJunoString(entry.depositVol),
			"withdrawalVolume": zatToJunoString(entry.withdrawVol),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    items,
	})
}

// handleOperatorRevenue returns accumulated, claimed, and pending fee data
// per operator by reading on-chain state from the FeeDistributor contract.
func (s *Server) handleOperatorRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	items := make([]map[string]any, 0, len(s.cfg.OperatorAddresses))

	for _, addr := range s.cfg.OperatorAddresses {
		entry := map[string]any{
			"operatorAddress": addr.Hex(),
		}

		// Get operator info from OperatorRegistry.
		if s.cfg.OperatorRegistryAddress != (common.Address{}) {
			feeRecip, weight, active, err := registryGetOperator(ctx, s.cfg.BaseClient, s.cfg.OperatorRegistryAddress, addr)
			if err != nil {
				s.log.Warn("analytics: get operator", "addr", addr.Hex(), "err", err)
			} else {
				entry["feeRecipient"] = feeRecip.Hex()
				entry["weight"] = weight.String()
				entry["active"] = active
			}
		}

		// Get pending fees from FeeDistributor.
		if s.cfg.FeeDistributorAddress != (common.Address{}) {
			pending, err := feeDistributorPendingReward(ctx, s.cfg.BaseClient, s.cfg.FeeDistributorAddress, addr)
			if err != nil {
				s.log.Warn("analytics: pending reward", "addr", addr.Hex(), "err", err)
				entry["pendingFees"] = "0"
				entry["pendingFeesFormatted"] = "0 JUNO"
			} else {
				entry["pendingFees"] = pending.String()
				entry["pendingFeesFormatted"] = formatBigJuno(pending)
			}

			// Accumulated and claimed require event log scanning which is
			// deferred to a future iteration. For now expose pending only.
			entry["accumulatedFees"] = "0"
			entry["accumulatedFeesFormatted"] = "0 JUNO"
			entry["claimedFees"] = "0"
			entry["claimedFeesFormatted"] = "0 JUNO"
		}

		items = append(items, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    items,
	})
}

// formatBigJuno converts a raw amount (8-decimal wJUNO/zatoshi) to a
// human-readable "X.YYYY JUNO" string.
func formatBigJuno(raw *big.Int) string {
	if raw == nil || raw.Sign() == 0 {
		return "0 JUNO"
	}
	divisor := big.NewInt(1_0000_0000)
	whole := new(big.Int)
	frac := new(big.Int)
	whole.DivMod(raw, divisor, frac)
	if frac.Sign() < 0 {
		frac.Abs(frac)
	}
	if frac.Sign() == 0 {
		return fmt.Sprintf("%s.0 JUNO", whole.String())
	}
	fracStr := fmt.Sprintf("%08d", frac.Int64())
	trimmed := strings.TrimRight(fracStr, "0")
	return fmt.Sprintf("%s.%s JUNO", whole.String(), trimmed)
}
