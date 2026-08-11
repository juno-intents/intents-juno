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
	"strconv"
	"strings"
	"time"

	"github.com/juno-intents/intents-juno/internal/witnessextract"
)

type Client struct {
	baseURL string
	bearer  string
	hc      *http.Client
	wait    func(context.Context, time.Duration) error
}

const (
	defaultHTTPTimeout           = 15 * time.Second
	defaultWitnessBusyRetryDelay = time.Second
)

func New(baseURL, bearerToken string) *Client {
	return NewWithTimeout(baseURL, bearerToken, defaultHTTPTimeout)
}

func NewWithTimeout(baseURL, bearerToken string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		bearer:  strings.TrimSpace(bearerToken),
		hc:      &http.Client{Timeout: timeout},
		wait:    waitForRetry,
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
		path := c.baseURL + "/v1/wallets/" + url.PathEscape(wallet) + "/notes?limit=1000&direction=incoming"
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
				Direction   string `json:"direction,omitempty"`
			} `json:"notes"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode juno-scan list notes: %w", err)
		}
		for _, n := range resp.Notes {
			if direction := strings.TrimSpace(n.Direction); direction != "" && !strings.EqualFold(direction, "incoming") {
				continue
			}
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

	var body []byte
	for {
		var status int
		var headers http.Header
		body, status, headers, err = c.doWithHeaders(ctx, http.MethodPost, c.baseURL+"/v1/orchard/witness", raw)
		if err != nil {
			return witnessextract.WitnessResponse{}, err
		}
		if status == http.StatusOK {
			break
		}
		if status != http.StatusServiceUnavailable || strings.TrimSpace(string(body)) != "witness busy" {
			return witnessextract.WitnessResponse{}, fmt.Errorf("juno-scan orchard witness status=%d body=%s", status, strings.TrimSpace(string(body)))
		}

		wait := c.wait
		if wait == nil {
			wait = waitForRetry
		}
		if err := wait(ctx, retryAfterDelay(headers.Get("Retry-After"), time.Now())); err != nil {
			return witnessextract.WitnessResponse{}, fmt.Errorf("wait to retry juno-scan orchard witness: %w", err)
		}
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
	respBody, status, _, err := c.doWithHeaders(ctx, method, endpoint, body)
	return respBody, status, err
}

func (c *Client) doWithHeaders(ctx context.Context, method, endpoint string, body []byte) ([]byte, int, http.Header, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, 0, nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, 0, nil, err
	}
	return respBody, resp.StatusCode, resp.Header.Clone(), nil
}

func retryAfterDelay(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if _, err := strconv.ParseUint(value, 10, 63); err == nil {
		if delay, err := time.ParseDuration(value + "s"); err == nil {
			return delay
		}
	}
	if retryAt, err := http.ParseTime(value); err == nil {
		if delay := retryAt.Sub(now); delay > 0 {
			return delay
		}
		return 0
	}
	return defaultWitnessBusyRetryDelay
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
