package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	"github.com/juno-intents/intents-juno/internal/witnessextract"
)

const (
	defaultScanBearerTokenEnv = "JUNO_SCAN_BEARER_TOKEN"
	defaultRPCUserEnv         = "JUNO_RPC_USER"
	defaultRPCPassEnv         = "JUNO_RPC_PASS"
)

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: juno-witness-extract <deposit|withdraw> [flags]")
	}

	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "deposit":
		return runDeposit(args[1:], stdout)
	case "withdraw":
		return runWithdraw(args[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q (expected deposit or withdraw)", args[0])
	}
}

type commonFlags struct {
	ScanURL            string
	WalletID           string
	ScanBearerTokenEnv string
	RPCURL             string
	RPCUserEnv         string
	RPCPassEnv         string
	TxID               string
	ActionIndex        uint
	AnchorHeight       int64
	OutputWitnessFile  string
}

func addCommonFlags(fs *flag.FlagSet, cfg *commonFlags) {
	fs.StringVar(&cfg.ScanURL, "juno-scan-url", "", "juno-scan base URL (required)")
	fs.StringVar(&cfg.WalletID, "wallet-id", "", "juno-scan wallet id (required)")
	fs.StringVar(&cfg.ScanBearerTokenEnv, "juno-scan-bearer-token-env", defaultScanBearerTokenEnv, "env var name containing optional juno-scan bearer token")
	fs.StringVar(&cfg.RPCURL, "juno-rpc-url", "", "junocashd JSON-RPC URL (required)")
	fs.StringVar(&cfg.RPCUserEnv, "juno-rpc-user-env", defaultRPCUserEnv, "env var name containing junocashd RPC username")
	fs.StringVar(&cfg.RPCPassEnv, "juno-rpc-pass-env", defaultRPCPassEnv, "env var name containing junocashd RPC password")
	fs.StringVar(&cfg.TxID, "txid", "", "juno txid for the witness note (required)")
	fs.UintVar(&cfg.ActionIndex, "action-index", 0, "orchard action index inside tx")
	fs.Int64Var(&cfg.AnchorHeight, "anchor-height", -1, "optional witness anchor height (default: current scan tip)")
	fs.StringVar(&cfg.OutputWitnessFile, "output-witness-item-file", "", "output path for binary witness item (required)")
}

func validateCommonFlags(cfg commonFlags) error {
	if strings.TrimSpace(cfg.ScanURL) == "" {
		return errors.New("--juno-scan-url is required")
	}
	if strings.TrimSpace(cfg.WalletID) == "" {
		return errors.New("--wallet-id is required")
	}
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return errors.New("--juno-rpc-url is required")
	}
	if strings.TrimSpace(cfg.TxID) == "" {
		return errors.New("--txid is required")
	}
	if strings.TrimSpace(cfg.OutputWitnessFile) == "" {
		return errors.New("--output-witness-item-file is required")
	}
	return nil
}

func runDeposit(args []string, stdout io.Writer) error {
	var cfg commonFlags
	fs := flag.NewFlagSet("deposit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addCommonFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateCommonFlags(cfg); err != nil {
		return err
	}

	builder, jrpc, err := newBuilder(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var anchor *int64
	if cfg.AnchorHeight >= 0 {
		anchor = &cfg.AnchorHeight
	}
	res, err := builder.BuildDeposit(ctx, witnessextract.DepositRequest{
		WalletID:     cfg.WalletID,
		TxID:         cfg.TxID,
		ActionIndex:  uint32(cfg.ActionIndex),
		AnchorHeight: anchor,
	})
	if err != nil {
		return err
	}
	anchorBlockHash, err := anchorBlockHashAtHeight(ctx, jrpc, res.AnchorHeight)
	if err != nil {
		return err
	}
	if err := writeWitnessFile(cfg.OutputWitnessFile, res.WitnessItem); err != nil {
		return err
	}

	out := map[string]any{
		"mode":                "deposit",
		"txid":                strings.ToLower(strings.TrimPrefix(strings.TrimSpace(cfg.TxID), "0x")),
		"action_index":        cfg.ActionIndex,
		"position":            res.Position,
		"anchor_height":       res.AnchorHeight,
		"anchor_block_hash":   anchorBlockHash,
		"final_orchard_root":  res.FinalOrchardRoot.Hex(),
		"witness_item_hex":    hexutil.Encode(res.WitnessItem),
		"witness_item_output": cfg.OutputWitnessFile,
	}
	return writeJSON(stdout, out)
}

func runWithdraw(args []string, stdout io.Writer) error {
	var cfg commonFlags
	var withdrawalIDHex string
	var recipientRawHex string

	fs := flag.NewFlagSet("withdraw", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addCommonFlags(fs, &cfg)
	fs.StringVar(&withdrawalIDHex, "withdrawal-id-hex", "", "withdrawal id (32-byte hex, required)")
	fs.StringVar(&recipientRawHex, "recipient-raw-address-hex", "", "recipient raw Orchard address bytes (43-byte hex, required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateCommonFlags(cfg); err != nil {
		return err
	}
	if strings.TrimSpace(withdrawalIDHex) == "" {
		return errors.New("--withdrawal-id-hex is required")
	}
	if strings.TrimSpace(recipientRawHex) == "" {
		return errors.New("--recipient-raw-address-hex is required")
	}
	withdrawalIDBytes, err := parseFixedHex(withdrawalIDHex, 32)
	if err != nil {
		return fmt.Errorf("parse --withdrawal-id-hex: %w", err)
	}
	recipientRawBytes, err := parseFixedHex(recipientRawHex, 43)
	if err != nil {
		return fmt.Errorf("parse --recipient-raw-address-hex: %w", err)
	}
	var withdrawalID [32]byte
	copy(withdrawalID[:], withdrawalIDBytes)
	var recipientRaw [43]byte
	copy(recipientRaw[:], recipientRawBytes)

	builder, jrpc, err := newBuilder(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var anchor *int64
	if cfg.AnchorHeight >= 0 {
		anchor = &cfg.AnchorHeight
	}
	res, err := builder.BuildWithdraw(ctx, witnessextract.WithdrawRequest{
		WalletID:            cfg.WalletID,
		TxID:                cfg.TxID,
		ActionIndex:         uint32(cfg.ActionIndex),
		AnchorHeight:        anchor,
		WithdrawalID:        withdrawalID,
		RecipientRawAddress: recipientRaw,
	})
	if err != nil {
		return err
	}
	anchorBlockHash, err := anchorBlockHashAtHeight(ctx, jrpc, res.AnchorHeight)
	if err != nil {
		return err
	}
	if err := writeWitnessFile(cfg.OutputWitnessFile, res.WitnessItem); err != nil {
		return err
	}

	out := map[string]any{
		"mode":                     "withdraw",
		"txid":                     strings.ToLower(strings.TrimPrefix(strings.TrimSpace(cfg.TxID), "0x")),
		"action_index":             cfg.ActionIndex,
		"position":                 res.Position,
		"anchor_height":            res.AnchorHeight,
		"anchor_block_hash":        anchorBlockHash,
		"final_orchard_root":       res.FinalOrchardRoot.Hex(),
		"withdrawal_id":            hexutil.Encode(withdrawalID[:]),
		"recipient_raw_address":    hexutil.Encode(recipientRaw[:]),
		"witness_item_hex":         hexutil.Encode(res.WitnessItem),
		"witness_item_output_file": cfg.OutputWitnessFile,
	}
	return writeJSON(stdout, out)
}

func newBuilder(cfg commonFlags) (*witnessextract.Builder, *junorpc.Client, error) {
	rpcUser := os.Getenv(strings.TrimSpace(cfg.RPCUserEnv))
	rpcPass := os.Getenv(strings.TrimSpace(cfg.RPCPassEnv))
	if strings.TrimSpace(rpcUser) == "" || strings.TrimSpace(rpcPass) == "" {
		return nil, nil, fmt.Errorf("missing junocashd RPC credentials in env %s/%s", cfg.RPCUserEnv, cfg.RPCPassEnv)
	}
	jrpc, err := junorpc.New(cfg.RPCURL, rpcUser, rpcPass)
	if err != nil {
		return nil, nil, err
	}
	bearerToken := os.Getenv(strings.TrimSpace(cfg.ScanBearerTokenEnv))
	scan := &scanHTTPClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.ScanURL), "/"),
		bearer:  strings.TrimSpace(bearerToken),
		hc:      &http.Client{Timeout: 15 * time.Second},
	}
	return witnessextract.New(scan, jrpc), jrpc, nil
}

func anchorBlockHashAtHeight(ctx context.Context, jrpc *junorpc.Client, anchorHeight int64) (string, error) {
	if jrpc == nil {
		return "", errors.New("nil junocashd rpc client")
	}
	if anchorHeight < 0 {
		return "", fmt.Errorf("invalid anchor height %d", anchorHeight)
	}
	blockHash, err := jrpc.GetBlockHash(ctx, uint64(anchorHeight))
	if err != nil {
		return "", fmt.Errorf("get block hash at anchor height %d: %w", anchorHeight, err)
	}
	return blockHash.Hex(), nil
}

func writeWitnessFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func parseFixedHex(raw string, wantLen int) ([]byte, error) {
	v := strings.TrimSpace(raw)
	if !strings.HasPrefix(v, "0x") && !strings.HasPrefix(v, "0X") {
		v = "0x" + v
	}
	b, err := hexutil.Decode(v)
	if err != nil {
		return nil, err
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("hex length mismatch: got=%d want=%d", len(b), wantLen)
	}
	return b, nil
}

type scanHTTPClient struct {
	baseURL string
	bearer  string
	hc      *http.Client
}

func (c *scanHTTPClient) ListWalletIDs(ctx context.Context) ([]string, error) {
	if c == nil || c.hc == nil {
		return nil, errors.New("scan client is nil")
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("scan client base URL is empty")
	}

	body, status, err := c.do(ctx, http.MethodGet, c.baseURL+"/v1/wallets", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("juno-scan list wallets status=%d body=%s", status, strings.TrimSpace(string(body)))
	}

	var resp struct {
		Wallets []json.RawMessage `json:"wallets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode juno-scan list wallets: %w", err)
	}

	out := make([]string, 0, len(resp.Wallets))
	seen := make(map[string]struct{}, len(resp.Wallets))
	for _, raw := range resp.Wallets {
		id := ""
		if err := json.Unmarshal(raw, &id); err == nil {
			id = strings.TrimSpace(id)
		} else {
			var item struct {
				WalletID string `json:"wallet_id"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				continue
			}
			id = strings.TrimSpace(item.WalletID)
		}
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func (c *scanHTTPClient) ListWalletNotes(ctx context.Context, walletID string) ([]witnessextract.WalletNote, error) {
	if c == nil || c.hc == nil {
		return nil, errors.New("scan client is nil")
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("scan client base URL is empty")
	}
	wallet := strings.TrimSpace(walletID)
	if wallet == "" {
		return nil, errors.New("wallet id is empty")
	}

	cursor := ""
	seen := map[string]struct{}{}
	out := make([]witnessextract.WalletNote, 0, 1024)
	for {
		path := c.baseURL + "/v1/wallets/" + url.PathEscape(wallet) + "/notes?limit=1000"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		body, status, err := c.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("juno-scan list notes status=%d body=%s", status, strings.TrimSpace(string(body)))
		}

		var resp struct {
			Notes []struct {
				TxID        string `json:"txid"`
				ActionIndex int32  `json:"action_index"`
				Position    *int64 `json:"position,omitempty"`
			} `json:"notes"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode juno-scan list notes: %w", err)
		}
		for _, n := range resp.Notes {
			out = append(out, witnessextract.WalletNote{
				TxID:        n.TxID,
				ActionIndex: n.ActionIndex,
				Position:    n.Position,
			})
		}

		next := strings.TrimSpace(resp.NextCursor)
		if next == "" {
			break
		}
		if _, ok := seen[next]; ok {
			return nil, errors.New("juno-scan list notes cursor did not advance")
		}
		seen[next] = struct{}{}
		cursor = next
	}
	return out, nil
}

func (c *scanHTTPClient) OrchardWitness(ctx context.Context, anchorHeight *int64, positions []uint32) (witnessextract.WitnessResponse, error) {
	if c == nil || c.hc == nil {
		return witnessextract.WitnessResponse{}, errors.New("scan client is nil")
	}
	reqBody := map[string]any{
		"positions": positions,
	}
	if anchorHeight != nil {
		reqBody["anchor_height"] = *anchorHeight
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return witnessextract.WitnessResponse{}, err
	}

	body, status, err := c.do(ctx, http.MethodPost, c.baseURL+"/v1/orchard/witness", raw)
	if err != nil {
		return witnessextract.WitnessResponse{}, err
	}
	if status != http.StatusOK {
		return witnessextract.WitnessResponse{}, fmt.Errorf("juno-scan orchard witness status=%d body=%s", status, strings.TrimSpace(string(body)))
	}

	var resp struct {
		AnchorHeight int64 `json:"anchor_height"`
		Root         string
		Paths        []struct {
			Position uint32   `json:"position"`
			AuthPath []string `json:"auth_path"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return witnessextract.WitnessResponse{}, fmt.Errorf("decode juno-scan orchard witness: %w", err)
	}

	out := witnessextract.WitnessResponse{
		AnchorHeight: resp.AnchorHeight,
		Root:         resp.Root,
		Paths:        make([]witnessextract.WitnessPath, 0, len(resp.Paths)),
	}
	for _, p := range resp.Paths {
		out.Paths = append(out.Paths, witnessextract.WitnessPath{
			Position: p.Position,
			AuthPath: append([]string(nil), p.AuthPath...),
		})
	}
	return out, nil
}

func (c *scanHTTPClient) do(ctx context.Context, method, endpoint string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, 0, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, 0, err
	}
	return respBody, resp.StatusCode, nil
}

func parseActionIndex(raw string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}
