package backoffice

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
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

	// Prover (SP1 requestor) balance. Queries the Succinct prover network via
	// gRPC if SP1RPCURL is configured, otherwise falls back to BaseClient.
	if s.cfg.SP1RequestorAddress != (common.Address{}) {
		if s.cfg.SP1RPCURL != "" {
			credits, proverErr := fetchSP1Balance(ctx, s.cfg.SP1RPCURL, s.cfg.SP1RequestorAddress)
			if proverErr != nil {
				s.log.Warn("fetch sp1 prover balance", "err", proverErr)
				resp["prover"] = map[string]any{
					"address": s.cfg.SP1RequestorAddress.Hex(),
					"error":   proverErr.Error(),
				}
			} else {
				creditsBig, ok := new(big.Int).SetString(credits, 10)
			if !ok {
				creditsBig = new(big.Int)
			}
			resp["prover"] = map[string]any{
				"address":          s.cfg.SP1RequestorAddress.Hex(),
				"creditsRaw":       credits,
				"creditsFormatted": weiToEthString(creditsBig),
				"network":          "succinct",
			}
			}
		} else {
			prover, proverErr := s.fetchAddressBalance(ctx, s.cfg.SP1RequestorAddress, s.cfg.ProverFundsMinWei)
			if proverErr != nil {
				s.log.Warn("fetch prover balance", "err", proverErr)
				resp["prover"] = map[string]any{
					"address": s.cfg.SP1RequestorAddress.Hex(),
					"error":   proverErr.Error(),
				}
			} else {
				resp["prover"] = prover
			}
		}
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
	return s.fetchAddressBalanceWith(ctx, s.cfg.BaseClient, addr, minWei)
}

// fetchAddressBalanceWith is like fetchAddressBalance but accepts an explicit ethclient.
func (s *Server) fetchAddressBalanceWith(ctx context.Context, client *ethclient.Client, addr common.Address, minWei *big.Int) (map[string]any, error) {
	balance, err := client.BalanceAt(ctx, addr, nil)
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

// fetchSP1Balance queries the Succinct prover network for the SP1 requestor's
// credit balance using a raw gRPC call (HTTP/2 POST with hand-rolled protobuf).
// No external gRPC or protobuf dependencies are needed.
func fetchSP1Balance(ctx context.Context, rpcURL string, addr common.Address) (string, error) {
	// Build protobuf for GetBalanceRequest{bytes address = 1}.
	// Field 1, wire type 2 (length-delimited): tag byte = (1<<3)|2 = 0x0a.
	addrBytes := addr.Bytes() // 20 bytes
	proto := make([]byte, 0, 2+len(addrBytes))
	proto = append(proto, 0x0a, byte(len(addrBytes)))
	proto = append(proto, addrBytes...)

	// Wrap in gRPC frame: 1 byte compression flag + 4 bytes big-endian length + message.
	frame := make([]byte, 5+len(proto))
	frame[0] = 0 // no compression
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(proto)))
	copy(frame[5:], proto)

	// Ensure HTTPS scheme.
	u := rpcURL
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	u = strings.TrimRight(u, "/") + "/network.ProverNetwork/GetBalance"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(frame))
	if err != nil {
		return "", fmt.Errorf("create grpc request: %w", err)
	}
	req.Header.Set("Content-Type", "application/grpc")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("grpc call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read grpc response: %w", err)
	}

	// Check HTTP status.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("grpc http status %d", resp.StatusCode)
	}

	// Check gRPC status from trailers (HTTP/2 delivers trailers natively).
	if gs := resp.Trailer.Get("Grpc-Status"); gs != "" && gs != "0" {
		gm := resp.Trailer.Get("Grpc-Message")
		return "", fmt.Errorf("grpc status %s: %s", gs, gm)
	}

	// Parse gRPC frame: 1 byte flag + 4 bytes message length + message.
	if len(body) < 5 {
		return "", fmt.Errorf("grpc response too short: %d bytes", len(body))
	}
	msgLen := binary.BigEndian.Uint32(body[1:5])
	if uint32(len(body)) < 5+msgLen {
		return "", fmt.Errorf("grpc message truncated: have %d, need %d", len(body)-5, msgLen)
	}
	msg := body[5 : 5+msgLen]

	// Parse protobuf GetBalanceResponse{string amount = 1}.
	credits, err := extractProtoString(msg, 1)
	if err != nil {
		return "", fmt.Errorf("decode GetBalanceResponse: %w", err)
	}
	return credits, nil
}

// extractProtoString extracts a length-delimited (string/bytes) field by
// field number from a simple protobuf message. Only handles wire types 0
// (varint) and 2 (length-delimited), which is sufficient for the Succinct API.
func extractProtoString(buf []byte, fieldNum uint8) (string, error) {
	for i := 0; i < len(buf); {
		tag := buf[i]
		i++
		fnum := tag >> 3
		wtype := tag & 0x07

		switch wtype {
		case 2: // length-delimited
			length, newI := decodeVarint(buf, i)
			i = newI
			if fnum == fieldNum {
				end := i + int(length)
				if end > len(buf) {
					return "", fmt.Errorf("truncated value for field %d", fieldNum)
				}
				return string(buf[i:end]), nil
			}
			i += int(length)
		case 0: // varint — skip
			_, i = decodeVarint(buf, i)
		default:
			return "", fmt.Errorf("unsupported wire type %d at offset %d", wtype, i-1)
		}
	}
	return "", fmt.Errorf("field %d not found", fieldNum)
}

// decodeVarint reads a protobuf varint from buf starting at position i.
func decodeVarint(buf []byte, i int) (uint64, int) {
	var val uint64
	var shift uint
	for i < len(buf) {
		b := buf[i]
		i++
		val |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return val, i
		}
		shift += 7
	}
	return val, i
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
