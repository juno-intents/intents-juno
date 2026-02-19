package junorpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

var (
	ErrInvalidConfig    = errors.New("junorpc: invalid config")
	ErrRPC              = errors.New("junorpc: rpc error")
	ErrResponseTooLarge = errors.New("junorpc: response too large")
	ErrTxNotFound       = errors.New("junorpc: transaction not found")
)

type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string {
	if e == nil {
		return "junorpc: nil rpc error"
	}
	return fmt.Sprintf("junorpc: rpc error code %d: %s", e.Code, e.Message)
}

func (e *RPCError) Unwrap() error { return ErrRPC }

type Option func(*Client) error

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) error {
		if hc == nil {
			return fmt.Errorf("%w: nil http client", ErrInvalidConfig)
		}
		c.hc = hc
		return nil
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return fmt.Errorf("%w: timeout must be > 0", ErrInvalidConfig)
		}
		if c.hc == nil {
			c.hc = &http.Client{}
		}
		c.hc.Timeout = d
		return nil
	}
}

func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) error {
		if n <= 0 {
			return fmt.Errorf("%w: max response bytes must be > 0", ErrInvalidConfig)
		}
		c.maxRespBytes = n
		return nil
	}
}

type Client struct {
	url          string
	user         string
	pass         string
	hc           *http.Client
	maxRespBytes int64
	nextID       atomic.Uint64
}

func New(url, user, pass string, opts ...Option) (*Client, error) {
	if url == "" {
		return nil, fmt.Errorf("%w: missing url", ErrInvalidConfig)
	}
	if user == "" || pass == "" {
		return nil, fmt.Errorf("%w: missing rpc credentials", ErrInvalidConfig)
	}
	c := &Client{
		url:          url,
		user:         user,
		pass:         pass,
		hc:           &http.Client{Timeout: 10 * time.Second},
		maxRespBytes: 5 << 20, // 5 MiB
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
	ID     string          `json:"id"`
}

type BlockChainInfo struct {
	Blocks uint64 `json:"blocks"`
}

type Block struct {
	Hash             common.Hash
	Height           uint64
	FinalOrchardRoot common.Hash
}

type RawTransaction struct {
	TxID          string
	Confirmations int64
}

type OrchardAction struct {
	Nullifier     [32]byte
	RK            [32]byte
	CMX           [32]byte
	EphemeralKey  [32]byte
	EncCiphertext [580]byte
	OutCiphertext [80]byte
	CV            [32]byte
}

func (c *Client) GetBlockChainInfo(ctx context.Context) (BlockChainInfo, error) {
	var out BlockChainInfo
	if err := c.call(ctx, "getblockchaininfo", nil, &out); err != nil {
		return BlockChainInfo{}, err
	}
	return out, nil
}

func (c *Client) GetBlockHash(ctx context.Context, height uint64) (common.Hash, error) {
	var s string
	if err := c.call(ctx, "getblockhash", []any{height}, &s); err != nil {
		return common.Hash{}, err
	}
	h, err := parseHash32(s)
	if err != nil {
		return common.Hash{}, fmt.Errorf("junorpc: parse getblockhash result: %w", err)
	}
	return h, nil
}

func (c *Client) GetBlock(ctx context.Context, blockHash common.Hash) (Block, error) {
	type blockResult struct {
		Hash             string `json:"hash"`
		Height           uint64 `json:"height"`
		FinalOrchardRoot string `json:"finalorchardroot"`
	}
	var res blockResult
	if err := c.call(ctx, "getblock", []any{strings.TrimPrefix(blockHash.Hex(), "0x"), 1}, &res); err != nil {
		return Block{}, err
	}
	h, err := parseHash32(res.Hash)
	if err != nil {
		return Block{}, fmt.Errorf("junorpc: parse block hash: %w", err)
	}
	root, err := parseHash32(res.FinalOrchardRoot)
	if err != nil {
		return Block{}, fmt.Errorf("junorpc: parse finalorchardroot: %w", err)
	}
	return Block{
		Hash:             h,
		Height:           res.Height,
		FinalOrchardRoot: root,
	}, nil
}

func (c *Client) SendRawTransaction(ctx context.Context, rawTx []byte) (string, error) {
	if len(rawTx) == 0 {
		return "", fmt.Errorf("%w: empty raw tx", ErrInvalidConfig)
	}
	var txid string
	if err := c.call(ctx, "sendrawtransaction", []any{hex.EncodeToString(rawTx)}, &txid); err != nil {
		return "", err
	}
	h, err := parseHash32(txid)
	if err != nil {
		return "", fmt.Errorf("junorpc: parse sendrawtransaction result: %w", err)
	}
	return strings.TrimPrefix(h.Hex(), "0x"), nil
}

func (c *Client) GetRawTransaction(ctx context.Context, txid string) (RawTransaction, error) {
	type rawTxResult struct {
		TxID          string `json:"txid"`
		Confirmations int64  `json:"confirmations"`
	}
	var res rawTxResult
	err := c.call(ctx, "getrawtransaction", []any{strings.TrimPrefix(strings.TrimSpace(txid), "0x"), true}, &res)
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) && rpcErr.Code == -5 {
			return RawTransaction{}, ErrTxNotFound
		}
		return RawTransaction{}, err
	}
	if res.TxID == "" {
		res.TxID = txid
	}
	h, err := parseHash32(res.TxID)
	if err != nil {
		return RawTransaction{}, fmt.Errorf("junorpc: parse getrawtransaction txid: %w", err)
	}
	return RawTransaction{
		TxID:          strings.TrimPrefix(h.Hex(), "0x"),
		Confirmations: res.Confirmations,
	}, nil
}

func (c *Client) GetOrchardAction(ctx context.Context, txid string, actionIndex uint32) (OrchardAction, error) {
	var out OrchardAction
	txHash, err := parseHash32(strings.TrimPrefix(strings.TrimSpace(txid), "0x"))
	if err != nil {
		return out, fmt.Errorf("junorpc: parse txid: %w", err)
	}

	var rawHex string
	if err := c.call(ctx, "getrawtransaction", []any{strings.TrimPrefix(txHash.Hex(), "0x"), false}, &rawHex); err != nil {
		return out, err
	}
	rawHex = strings.TrimSpace(rawHex)
	if rawHex == "" {
		return out, errors.New("junorpc: empty raw transaction hex")
	}

	type decodedRawTx struct {
		Orchard struct {
			Actions []struct {
				Nullifier     string `json:"nullifier"`
				RK            string `json:"rk"`
				CMX           string `json:"cmx"`
				EphemeralKey  string `json:"ephemeralKey"`
				EncCiphertext string `json:"encCiphertext"`
				OutCiphertext string `json:"outCiphertext"`
				CV            string `json:"cv"`
			} `json:"actions"`
		} `json:"orchard"`
	}
	var decoded decodedRawTx
	if err := c.call(ctx, "decoderawtransaction", []any{rawHex}, &decoded); err != nil {
		return out, err
	}
	if int(actionIndex) >= len(decoded.Orchard.Actions) {
		return out, fmt.Errorf("junorpc: orchard action index out of range: index=%d count=%d", actionIndex, len(decoded.Orchard.Actions))
	}
	action := decoded.Orchard.Actions[actionIndex]

	if err := decodeFixedHexInto("nullifier", action.Nullifier, out.Nullifier[:]); err != nil {
		return out, err
	}
	if err := decodeFixedHexInto("rk", action.RK, out.RK[:]); err != nil {
		return out, err
	}
	if err := decodeFixedHexInto("cmx", action.CMX, out.CMX[:]); err != nil {
		return out, err
	}
	if err := decodeFixedHexInto("ephemeralKey", action.EphemeralKey, out.EphemeralKey[:]); err != nil {
		return out, err
	}
	if err := decodeFixedHexInto("encCiphertext", action.EncCiphertext, out.EncCiphertext[:]); err != nil {
		return out, err
	}
	if err := decodeFixedHexInto("outCiphertext", action.OutCiphertext, out.OutCiphertext[:]); err != nil {
		return out, err
	}
	if err := decodeFixedHexInto("cv", action.CV, out.CV[:]); err != nil {
		return out, err
	}

	return out, nil
}

func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	id := c.nextID.Add(1)
	reqBody, err := json.Marshal(rpcRequest{
		JSONRPC: "1.0",
		ID:      fmt.Sprintf("%d", id),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("junorpc: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("junorpc: build request: %w", err)
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("junorpc: http do: %w", err)
	}
	defer resp.Body.Close()

	body, err := readAllLimited(resp.Body, c.maxRespBytes)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		// Sanitize: do not include any request body (could contain sensitive params in future).
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("junorpc: http status %d: %s", resp.StatusCode, msg)
	}

	var rr rpcResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return fmt.Errorf("junorpc: unmarshal response: %w", err)
	}
	if rr.Error != nil {
		return &RPCError{
			Code:    rr.Error.Code,
			Message: rr.Error.Message,
		}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(rr.Result, out); err != nil {
		return fmt.Errorf("junorpc: unmarshal result: %w", err)
	}
	return nil
}

func readAllLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("junorpc: read response: %w", err)
	}
	if int64(len(b)) > maxBytes {
		return nil, ErrResponseTooLarge
	}
	return b, nil
}

func parseHash32(s string) (common.Hash, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return common.Hash{}, fmt.Errorf("expected 32-byte hex, got len %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode hex: %w", err)
	}
	var out common.Hash
	copy(out[:], b)
	return out, nil
}

func decodeFixedHexInto(field, raw string, out []byte) error {
	normalized := strings.TrimSpace(raw)
	normalized = strings.TrimPrefix(normalized, "0x")
	normalized = strings.TrimPrefix(normalized, "0X")
	if len(normalized) != len(out)*2 {
		return fmt.Errorf("junorpc: invalid %s length: got=%d want=%d", field, len(normalized), len(out)*2)
	}
	b, err := hex.DecodeString(normalized)
	if err != nil {
		return fmt.Errorf("junorpc: invalid %s hex: %w", field, err)
	}
	copy(out, b)
	return nil
}
