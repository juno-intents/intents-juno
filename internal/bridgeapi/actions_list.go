package bridgeapi

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/juno-intents/intents-juno/internal/deposit"
)

func (h *handler) handleListDeposits(w http.ResponseWriter, r *http.Request) {
	if h.depositLister == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"version": "v1",
			"error":   "list_deposits_not_available",
		})
		return
	}

	q := r.URL.Query()
	baseRecipient := strings.TrimSpace(q.Get("baseRecipient"))
	txHash := strings.TrimSpace(q.Get("txHash"))

	if baseRecipient == "" && txHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "missing_filter: provide baseRecipient or txHash",
		})
		return
	}

	limit, offset := parsePagination(q.Get("limit"), q.Get("offset"))

	if txHash != "" {
		id, err := parseHex32(txHash)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"version": "v1",
				"error":   "invalid_tx_hash",
			})
			return
		}
		job, err := h.depositLister.GetByTxHash(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"version": "v1",
				"error":   "internal",
			})
			return
		}
		if job == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"version": "v1",
				"data":    []any{},
				"total":   0,
				"limit":   limit,
				"offset":  offset,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version": "v1",
			"data":    []any{depositJobToMap(*job)},
			"total":   1,
			"limit":   limit,
			"offset":  offset,
		})
		return
	}

	addr, err := parseHex20(baseRecipient)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_base_recipient",
		})
		return
	}

	jobs, total, err := h.depositLister.ListByBaseRecipient(r.Context(), addr, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "internal",
		})
		return
	}

	data := make([]any, 0, len(jobs))
	for _, j := range jobs {
		data = append(data, depositJobToMap(j))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    data,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

func (h *handler) handleListWithdrawals(w http.ResponseWriter, r *http.Request) {
	if h.withdrawalLister == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"version": "v1",
			"error":   "list_withdrawals_not_available",
		})
		return
	}

	q := r.URL.Query()
	requester := strings.TrimSpace(q.Get("requester"))
	junoTxID := strings.TrimSpace(q.Get("junoTxId"))
	baseTxHash := strings.TrimSpace(q.Get("baseTxHash"))

	if requester == "" && junoTxID == "" && baseTxHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "missing_filter: provide requester, junoTxId, or baseTxHash",
		})
		return
	}

	limit, offset := parsePagination(q.Get("limit"), q.Get("offset"))

	if junoTxID != "" {
		statuses, err := h.withdrawalLister.GetByJunoTxID(r.Context(), junoTxID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"version": "v1",
				"error":   "internal",
			})
			return
		}
		writeListWithdrawals(w, statuses, len(statuses), limit, offset)
		return
	}

	if baseTxHash != "" {
		statuses, err := h.withdrawalLister.GetByBaseTxHash(r.Context(), baseTxHash)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"version": "v1",
				"error":   "internal",
			})
			return
		}
		writeListWithdrawals(w, statuses, len(statuses), limit, offset)
		return
	}

	addr, err := parseHex20(requester)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_requester",
		})
		return
	}

	statuses, total, err := h.withdrawalLister.ListByRequester(r.Context(), addr, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "internal",
		})
		return
	}
	writeListWithdrawals(w, statuses, total, limit, offset)
}

func writeListWithdrawals(w http.ResponseWriter, statuses []WithdrawalStatus, total, limit, offset int) {
	data := make([]any, 0, len(statuses))
	for _, st := range statuses {
		data = append(data, withdrawalStatusToMap(st))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    data,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

func depositJobToMap(j deposit.Job) map[string]any {
	txHash := ""
	if j.TxHash != ([32]byte{}) {
		txHash = "0x" + hex.EncodeToString(j.TxHash[:])
	}
	return map[string]any{
		"depositId":     "0x" + hex.EncodeToString(j.Deposit.DepositID[:]),
		"state":         j.State.String(),
		"amount":        strconv.FormatUint(j.Deposit.Amount, 10),
		"baseRecipient": "0x" + hex.EncodeToString(j.Deposit.BaseRecipient[:]),
		"txHash":        txHash,
	}
}

func withdrawalStatusToMap(st WithdrawalStatus) map[string]any {
	state := "requested"
	batchID := ""
	if st.BatchID != nil {
		state = st.BatchState.String()
		batchID = "0x" + hex.EncodeToString(st.BatchID[:])
	}
	return map[string]any{
		"withdrawalId": "0x" + hex.EncodeToString(st.Withdrawal.ID[:]),
		"state":        state,
		"amount":       strconv.FormatUint(st.Withdrawal.Amount, 10),
		"feeBps":       st.Withdrawal.FeeBps,
		"requester":    "0x" + hex.EncodeToString(st.Withdrawal.Requester[:]),
		"expiry":       st.Withdrawal.Expiry.UTC().Format(time.RFC3339),
		"batchId":      batchID,
		"junoTxId":     st.JunoTxID,
		"baseTxHash":   st.BaseTxHash,
	}
}

func parseHex20(s string) ([20]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 40 {
		return [20]byte{}, errInvalidLen
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [20]byte{}, err
	}
	var out [20]byte
	copy(out[:], b)
	return out, nil
}

var errInvalidLen = errorf("invalid length")

func errorf(msg string) error {
	return errorString(msg)
}

type errorString string

func (e errorString) Error() string { return string(e) }

func parsePagination(limitStr, offsetStr string) (int, int) {
	limit := 20
	offset := 0
	if v, err := strconv.Atoi(strings.TrimSpace(limitStr)); err == nil && v > 0 {
		limit = v
	}
	if limit > 100 {
		limit = 100
	}
	if v, err := strconv.Atoi(strings.TrimSpace(offsetStr)); err == nil && v >= 0 {
		offset = v
	}
	return limit, offset
}
