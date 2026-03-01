package backoffice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// handleFunds returns all fund data in one response: operator balances,
// prover funds, bridge wJUNO balance, and MPC wallet balance.
func (s *Server) handleFunds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp := map[string]any{
		"version": "v1",
	}

	// Operator balances.
	operators, err := s.fetchOperatorBalances(ctx)
	if err != nil {
		s.log.Error("fetch operator balances", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	resp["operators"] = operators

	// Prover (SP1 requestor) balance.
	if s.cfg.SP1RequestorAddress != (common.Address{}) {
		prover, proverErr := s.fetchAddressBalance(ctx, s.cfg.SP1RequestorAddress, s.cfg.ProverFundsMinWei)
		if proverErr != nil {
			s.log.Error("fetch prover balance", "err", proverErr)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		resp["prover"] = prover
	}

	// Bridge wJUNO balance (ERC20 balanceOf).
	if s.cfg.WJunoAddress != (common.Address{}) && s.cfg.BridgeAddress != (common.Address{}) {
		balance, balErr := erc20BalanceOf(ctx, s.cfg.BaseClient, s.cfg.WJunoAddress, s.cfg.BridgeAddress)
		if balErr != nil {
			s.log.Error("fetch bridge wjuno balance", "err", balErr)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		resp["bridge"] = map[string]any{
			"wjunoBalanceRaw":       balance.String(),
			"wjunoBalanceFormatted": zatToJunoString(balance.Int64()),
		}
	}

	// MPC wallet balance (Juno RPC z_gettotalbalance).
	if s.cfg.JunoRPCURL != "" {
		mpcBalance, mpcErr := s.fetchJunoMPCBalance(ctx)
		if mpcErr != nil {
			s.log.Warn("fetch juno mpc balance", "err", mpcErr)
			resp["mpcWallet"] = map[string]any{
				"error": mpcErr.Error(),
			}
		} else {
			resp["mpcWallet"] = mpcBalance
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// fetchOperatorBalances queries ETH balance for each configured operator address.
func (s *Server) fetchOperatorBalances(ctx context.Context) ([]map[string]any, error) {
	results := make([]map[string]any, 0, len(s.cfg.OperatorAddresses))
	for _, addr := range s.cfg.OperatorAddresses {
		entry, err := s.fetchAddressBalance(ctx, addr, s.cfg.OperatorGasMinWei)
		if err != nil {
			return nil, fmt.Errorf("operator %s: %w", addr.Hex(), err)
		}
		results = append(results, entry)
	}
	return results, nil
}

// fetchAddressBalance returns the ETH balance for a single address along with threshold info.
func (s *Server) fetchAddressBalance(ctx context.Context, addr common.Address, minWei *big.Int) (map[string]any, error) {
	balance, err := s.cfg.BaseClient.BalanceAt(ctx, addr, nil)
	if err != nil {
		return nil, err
	}
	belowThreshold := false
	if minWei != nil && minWei.Sign() > 0 {
		belowThreshold = balance.Cmp(minWei) < 0
	}
	return map[string]any{
		"address":        addr.Hex(),
		"balanceWei":     balance.String(),
		"balanceEth":     weiToEthString(balance),
		"belowThreshold": belowThreshold,
	}, nil
}

// fetchJunoMPCBalance calls z_gettotalbalance on the Juno RPC to retrieve the
// MPC wallet balance. Uses raw JSON-RPC.
func (s *Server) fetchJunoMPCBalance(ctx context.Context) (map[string]any, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "1.0",
		"id":      "backoffice",
		"method":  "z_gettotalbalance",
		"params":  []any{0},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.JunoRPCURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create rpc request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if s.cfg.JunoRPCUser != "" || s.cfg.JunoRPCPass != "" {
		httpReq.SetBasicAuth(s.cfg.JunoRPCUser, s.cfg.JunoRPCPass)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("juno rpc call: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rpc response: %w", err)
	}

	var rpcResp struct {
		Result struct {
			Transparent string `json:"transparent"`
			Private     string `json:"private"`
			Total       string `json:"total"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("decode rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return map[string]any{
		"transparent": rpcResp.Result.Transparent,
		"private":     rpcResp.Result.Private,
		"total":       rpcResp.Result.Total,
	}, nil
}
