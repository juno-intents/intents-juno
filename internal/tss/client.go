package tss

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
)

var (
	ErrInvalidConfig = errors.New("tss: invalid config")
	ErrRPC           = errors.New("tss: rpc error")
)

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

// WithInsecureHTTP allows using plain HTTP. This is dangerous for signing traffic and should only be
// used for local development.
func WithInsecureHTTP() Option {
	return func(c *Client) error {
		c.allowInsecureHTTP = true
		return nil
	}
}

type Client struct {
	baseURL string
	hc      *http.Client

	maxRespBytes int64

	allowInsecureHTTP bool
}

func NewClient(baseURL string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("%w: missing base url", ErrInvalidConfig)
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse base url: %v", ErrInvalidConfig, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: base url must be http(s)", ErrInvalidConfig)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: base url missing host", ErrInvalidConfig)
	}

	c := &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		hc:           &http.Client{Timeout: 10 * time.Second},
		maxRespBytes: 1 << 20, // 1 MiB
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if u.Scheme == "http" && !c.allowInsecureHTTP {
		return nil, fmt.Errorf("%w: insecure http not allowed", ErrInvalidConfig)
	}

	return c, nil
}

func (c *Client) Sign(ctx context.Context, batchID [32]byte, txPlan []byte) ([]byte, error) {
	reqBody, err := json.Marshal(SignRequest{
		Version:   SignRequestVersion,
		SessionID: FormatSessionID(batchID),
		TxPlan:    txPlan,
	})
	if err != nil {
		return nil, fmt.Errorf("tss: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+SignPathV1, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("tss: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tss: http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := readAllLimited(resp.Body, c.maxRespBytes)
		var eb struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &eb)
		msg := strings.TrimSpace(eb.Error)
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: status %d: %s", ErrRPC, resp.StatusCode, msg)
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, c.maxRespBytes))
	dec.DisallowUnknownFields()

	var out SignResponse
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("tss: decode response: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("tss: decode response: trailing data")
	}

	if out.Version != SignResponseVersion {
		return nil, fmt.Errorf("tss: unexpected response version: %q", out.Version)
	}
	if out.SessionID != FormatSessionID(batchID) {
		return nil, fmt.Errorf("tss: mismatched session id")
	}
	if len(out.SignedTx) == 0 {
		return nil, fmt.Errorf("tss: empty signed tx")
	}

	return out.SignedTx, nil
}

func readAllLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: maxBytes must be > 0", ErrInvalidConfig)
	}
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("tss: response too large")
	}
	return b, nil
}
