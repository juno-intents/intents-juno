package junoscanhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juno-intents/intents-juno/internal/witnessextract"
)

type Client struct {
	baseURL string
	bearer  string
	hc      *http.Client
}

func New(baseURL, bearerToken string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		bearer:  strings.TrimSpace(bearerToken),
		hc:      &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) ListWalletIDs(ctx context.Context) ([]string, error) {
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

func (c *Client) ListWalletNotes(ctx context.Context, walletID string) ([]witnessextract.WalletNote, error) {
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
				ValueZat    uint64 `json:"value_zat"`
				MemoHex     string `json:"memo_hex,omitempty"`
				Height      int64  `json:"height"`
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
				ValueZat:    n.ValueZat,
				MemoHex:     n.MemoHex,
				Height:      n.Height,
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

func (c *Client) OrchardWitness(ctx context.Context, anchorHeight *int64, positions []uint32) (witnessextract.WitnessResponse, error) {
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

func (c *Client) do(ctx context.Context, method, endpoint string, body []byte) ([]byte, int, error) {
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
