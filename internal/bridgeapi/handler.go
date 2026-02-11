package bridgeapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var ErrInvalidConfig = errors.New("bridgeapi: invalid config")

type Config struct {
	BaseChainID         uint32
	BridgeAddress       common.Address
	OWalletUA           string
	RefundWindowSeconds uint64
	NonceFn             func() (uint64, error)
}

type DepositReader interface {
	Get(ctx context.Context, depositID [32]byte) (deposit.Job, error)
}

type WithdrawalStatus struct {
	Withdrawal withdraw.Withdrawal
	BatchID    *[32]byte
	BatchState withdraw.BatchState
	JunoTxID   string
	BaseTxHash string
}

type WithdrawalReader interface {
	Get(ctx context.Context, withdrawalID [32]byte) (WithdrawalStatus, error)
}

func NewHandler(cfg Config, deposits DepositReader, withdrawals WithdrawalReader) (http.Handler, error) {
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: missing base chain id", ErrInvalidConfig)
	}
	if cfg.BridgeAddress == (common.Address{}) {
		return nil, fmt.Errorf("%w: missing bridge address", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.OWalletUA) == "" {
		return nil, fmt.Errorf("%w: missing owallet ua", ErrInvalidConfig)
	}
	if deposits == nil || withdrawals == nil {
		return nil, fmt.Errorf("%w: nil readers", ErrInvalidConfig)
	}
	if cfg.NonceFn == nil {
		cfg.NonceFn = randomNonce
	}

	h := &handler{
		cfg:         cfg,
		deposits:    deposits,
		withdrawals: withdrawals,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /v1/config", h.handleConfig)
	mux.HandleFunc("GET /v1/deposit-memo", h.handleDepositMemo)
	mux.HandleFunc("GET /v1/status/deposit/{depositId}", h.handleDepositStatus)
	mux.HandleFunc("GET /v1/status/withdrawal/{withdrawalId}", h.handleWithdrawalStatus)
	return mux, nil
}

type handler struct {
	cfg Config

	deposits    DepositReader
	withdrawals WithdrawalReader
}

func (h *handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *handler) handleConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":             "v1",
		"baseChainId":         h.cfg.BaseChainID,
		"bridgeAddress":       h.cfg.BridgeAddress.Hex(),
		"oWalletUA":           h.cfg.OWalletUA,
		"refundWindowSeconds": h.cfg.RefundWindowSeconds,
	})
}

func (h *handler) handleDepositMemo(w http.ResponseWriter, r *http.Request) {
	baseRecipientStr := strings.TrimSpace(r.URL.Query().Get("baseRecipient"))
	if !common.IsHexAddress(baseRecipientStr) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_base_recipient",
		})
		return
	}

	nonce, err := parseNonce(r.URL.Query().Get("nonce"), h.cfg.NonceFn)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_nonce",
		})
		return
	}

	var bridge [20]byte
	copy(bridge[:], h.cfg.BridgeAddress.Bytes())
	recipient := common.HexToAddress(baseRecipientStr)
	var recipient20 [20]byte
	copy(recipient20[:], recipient.Bytes())

	m := memo.DepositMemoV1{
		BaseChainID:   h.cfg.BaseChainID,
		BridgeAddr:    bridge,
		BaseRecipient: recipient20,
		Nonce:         nonce,
		Flags:         0,
	}
	encoded := m.Encode()

	writeJSON(w, http.StatusOK, map[string]any{
		"version":       "v1",
		"baseChainId":   h.cfg.BaseChainID,
		"bridgeAddress": h.cfg.BridgeAddress.Hex(),
		"oWalletUA":     h.cfg.OWalletUA,
		"baseRecipient": recipient.Hex(),
		"nonce":         strconv.FormatUint(nonce, 10),
		"memoHex":       hex.EncodeToString(encoded[:]),
		"memoBase64":    base64.StdEncoding.EncodeToString(encoded[:]),
	})
}

func (h *handler) handleDepositStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseHex32(r.PathValue("depositId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_deposit_id",
		})
		return
	}

	job, err := h.deposits.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, deposit.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"version":   "v1",
				"found":     false,
				"depositId": "0x" + hex.EncodeToString(id[:]),
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "internal",
		})
		return
	}

	txHash := ""
	if job.TxHash != ([32]byte{}) {
		txHash = "0x" + hex.EncodeToString(job.TxHash[:])
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":       "v1",
		"found":         true,
		"depositId":     "0x" + hex.EncodeToString(job.Deposit.DepositID[:]),
		"state":         job.State.String(),
		"amount":        strconv.FormatUint(job.Deposit.Amount, 10),
		"baseRecipient": "0x" + hex.EncodeToString(job.Deposit.BaseRecipient[:]),
		"txHash":        txHash,
	})
}

func (h *handler) handleWithdrawalStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseHex32(r.PathValue("withdrawalId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"version": "v1",
			"error":   "invalid_withdrawal_id",
		})
		return
	}

	st, err := h.withdrawals.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, withdraw.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"version":      "v1",
				"found":        false,
				"withdrawalId": "0x" + hex.EncodeToString(id[:]),
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"version": "v1",
			"error":   "internal",
		})
		return
	}

	state := "requested"
	batchID := ""
	if st.BatchID != nil {
		state = st.BatchState.String()
		batchID = "0x" + hex.EncodeToString(st.BatchID[:])
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":      "v1",
		"found":        true,
		"withdrawalId": "0x" + hex.EncodeToString(st.Withdrawal.ID[:]),
		"state":        state,
		"amount":       strconv.FormatUint(st.Withdrawal.Amount, 10),
		"feeBps":       st.Withdrawal.FeeBps,
		"requester":    "0x" + hex.EncodeToString(st.Withdrawal.Requester[:]),
		"expiry":       st.Withdrawal.Expiry.UTC().Format(time.RFC3339),
		"batchId":      batchID,
		"junoTxId":     st.JunoTxID,
		"baseTxHash":   st.BaseTxHash,
	})
}

func parseHex32(s string) ([32]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return [32]byte{}, fmt.Errorf("invalid length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func parseNonce(s string, fallback func() (uint64, error)) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback()
	}
	return strconv.ParseUint(s, 0, 64)
}

func randomNonce() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
