package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/juno-intents/intents-juno/internal/eth"
)

type Sender interface {
	SendAndWaitMined(ctx context.Context, req eth.TxRequest) (eth.SendResult, error)
}

type Config struct {
	// AuthToken enables bearer-token auth on every request when set.
	AuthToken string

	// MaxBodyBytes limits request sizes to prevent memory DoS. Defaults to 1 MiB.
	MaxBodyBytes int64

	// MaxWaitSeconds bounds per-request execution time (server-side). Defaults to 300s.
	MaxWaitSeconds int
}

func NewHandler(sender Sender, cfg Config) http.Handler {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxWaitSeconds <= 0 {
		cfg.MaxWaitSeconds = 300
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("POST /v1/send", func(w http.ResponseWriter, r *http.Request) {
		if cfg.AuthToken != "" && !checkBearer(r.Header.Get("Authorization"), cfg.AuthToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var req sendRequest
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}

		// Reject trailing garbage.
		if dec.More() {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}

		if !common.IsHexAddress(req.To) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_to"})
			return
		}
		to := common.HexToAddress(req.To)

		var data []byte
		if req.Data != "" {
			b, err := hexutil.Decode(req.Data)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_data"})
				return
			}
			data = b
		}

		value := big.NewInt(0)
		if req.ValueWei != "" {
			v, ok := new(big.Int).SetString(req.ValueWei, 10)
			if !ok || v.Sign() < 0 {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_value_wei"})
				return
			}
			value = v
		}

		timeout := time.Duration(cfg.MaxWaitSeconds) * time.Second
		if req.TimeoutSeconds > 0 {
			rt := time.Duration(req.TimeoutSeconds) * time.Second
			if rt < timeout {
				timeout = rt
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		res, err := sender.SendAndWaitMined(ctx, eth.TxRequest{
			To:       to,
			Data:     data,
			Value:    value,
			GasLimit: req.GasLimit,
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": "timeout"})
				return
			}
			if errors.Is(err, context.Canceled) {
				writeJSON(w, http.StatusRequestTimeout, map[string]any{"error": "canceled"})
				return
			}
			// Avoid leaking internal details by default.
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal"})
			return
		}

		out := sendResponse{
			From:         res.From.Hex(),
			Nonce:        res.Nonce,
			TxHash:       res.TxHash.Hex(),
			Replacements: res.Replacements,
		}
		if res.Receipt != nil {
			out.Receipt = &receiptResponse{
				Status: res.Receipt.Status,
			}
			if res.Receipt.BlockNumber != nil {
				out.Receipt.BlockNumber = res.Receipt.BlockNumber.String()
			}
			if res.Receipt.GasUsed != 0 {
				out.Receipt.GasUsed = res.Receipt.GasUsed
			}
		}

		writeJSON(w, http.StatusOK, out)
	})

	return mux
}

type sendRequest struct {
	To             string `json:"to"`
	Data           string `json:"data,omitempty"`
	ValueWei       string `json:"value_wei,omitempty"`
	GasLimit       uint64 `json:"gas_limit,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type sendResponse struct {
	From         string           `json:"from"`
	Nonce        uint64           `json:"nonce"`
	TxHash       string           `json:"tx_hash"`
	Replacements int              `json:"replacements"`
	Receipt      *receiptResponse `json:"receipt,omitempty"`
}

type receiptResponse struct {
	Status      uint64 `json:"status"`
	BlockNumber string `json:"block_number,omitempty"`
	GasUsed     uint64 `json:"gas_used,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func checkBearer(header string, wantToken string) bool {
	// Conservative parsing: exact "Bearer <token>" with single space.
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return got == wantToken
}
