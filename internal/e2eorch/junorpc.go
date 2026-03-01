package e2eorch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// SendJunoDeposit sends a shielded Juno transaction via z_sendmany and polls
// z_getoperationstatus until the operation completes, returning the txid.
func SendJunoDeposit(ctx context.Context, cfg E2EConfig, memoHex string) (string, error) {
	client := &junoRPCClient{
		url:  cfg.JunoRPCURL,
		user: cfg.JunoRPCUser,
		pass: cfg.JunoRPCPass,
		hc:   &http.Client{Timeout: 30 * time.Second},
	}

	// z_sendmany expects a decimal ZEC value; DepositAmountZat is in zatoshis.
	amountZEC := float64(cfg.DepositAmountZat) / 1e8

	recipients := []map[string]any{{
		"address": cfg.OWalletUA,
		"amount":  amountZEC,
		"memo":    memoHex,
	}}

	var opid string
	if err := client.call(ctx, "z_sendmany", []any{cfg.JunoFunderSourceAddress, recipients, 1, 0.0}, &opid); err != nil {
		return "", fmt.Errorf("e2eorch: z_sendmany: %w", err)
	}
	if opid == "" {
		return "", fmt.Errorf("e2eorch: z_sendmany returned empty opid")
	}

	// Poll z_getoperationstatus until the operation finishes.
	err := PollUntil(ctx, 10*time.Minute, 2*time.Second, func(ctx context.Context) (bool, string, error) {
		type opStatus struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Result struct {
				TxID string `json:"txid"`
			} `json:"result"`
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		var statuses []opStatus
		if err := client.call(ctx, "z_getoperationstatus", []any{[]string{opid}}, &statuses); err != nil {
			return false, "rpc error", fmt.Errorf("e2eorch: z_getoperationstatus: %w", err)
		}
		if len(statuses) == 0 {
			return false, "waiting for operation", nil
		}
		st := statuses[0]
		switch st.Status {
		case "success":
			if st.Result.TxID == "" {
				return false, "success (no txid)", fmt.Errorf("e2eorch: operation succeeded but txid is empty")
			}
			opid = st.Result.TxID // stash the txid via closure
			return true, "success", nil
		case "failed":
			return false, "failed", fmt.Errorf("e2eorch: z_sendmany operation failed: code=%d msg=%s", st.Error.Code, st.Error.Message)
		case "executing":
			return false, "executing", nil
		case "queued":
			return false, "queued", nil
		default:
			return false, st.Status, nil
		}
	})
	if err != nil {
		return "", fmt.Errorf("e2eorch: poll z_sendmany operation: %w", err)
	}
	// After PollUntil succeeds, opid has been overwritten with the txid.
	return opid, nil
}

// junoRPCClient is a minimal JSON-RPC client for junocashd.
type junoRPCClient struct {
	url    string
	user   string
	pass   string
	hc     *http.Client
	nextID atomic.Uint64
}

type jrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type jrpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *junoRPCClient) call(ctx context.Context, method string, params []any, out any) error {
	id := c.nextID.Add(1)
	body, err := json.Marshal(jrpcRequest{
		JSONRPC: "1.0",
		ID:      fmt.Sprintf("%d", id),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("marshal rpc request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build rpc request: %w", err)
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("rpc http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return fmt.Errorf("read rpc response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("rpc http status %d: %s", resp.StatusCode, msg)
	}

	var rr jrpcResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return fmt.Errorf("unmarshal rpc response: %w", err)
	}
	if rr.Error != nil {
		return fmt.Errorf("rpc error code %d: %s", rr.Error.Code, rr.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(rr.Result, out)
}
