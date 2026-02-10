package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var ErrInvalidClientConfig = errors.New("httpapi: invalid client config")

type ClientOption func(*Client) error

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) error {
		if hc == nil {
			return fmt.Errorf("%w: nil http client", ErrInvalidClientConfig)
		}
		c.hc = hc
		return nil
	}
}

func WithMaxResponseBytes(n int64) ClientOption {
	return func(c *Client) error {
		if n <= 0 {
			return fmt.Errorf("%w: max response bytes must be > 0", ErrInvalidClientConfig)
		}
		c.maxRespBytes = n
		return nil
	}
}

type Client struct {
	baseURL      *url.URL
	authToken    string
	hc           *http.Client
	maxRespBytes int64
}

func NewClient(baseURL string, authToken string, opts ...ClientOption) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("%w: missing base url", ErrInvalidClientConfig)
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse base url: %v", ErrInvalidClientConfig, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrInvalidClientConfig, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrInvalidClientConfig)
	}

	c := &Client{
		baseURL:      u,
		authToken:    authToken,
		hc:           &http.Client{Timeout: 5 * time.Minute},
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
	return c, nil
}

func (c *Client) Send(ctx context.Context, req SendRequest) (SendResponse, error) {
	if c == nil || c.baseURL == nil || c.hc == nil {
		return SendResponse{}, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}

	u := *c.baseURL
	u.Path = joinPath(u.Path, "/v1/send")

	b, err := json.Marshal(req)
	if err != nil {
		return SendResponse{}, fmt.Errorf("httpapi: marshal request: %w", err)
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(b))
	if err != nil {
		return SendResponse{}, fmt.Errorf("httpapi: build request: %w", err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if c.authToken != "" {
		r.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.hc.Do(r)
	if err != nil {
		return SendResponse{}, fmt.Errorf("httpapi: http do: %w", err)
	}
	defer resp.Body.Close()

	body, err := readAllLimited(resp.Body, c.maxRespBytes)
	if err != nil {
		return SendResponse{}, err
	}

	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		} else {
			var er struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(body, &er) == nil && er.Error != "" {
				msg = er.Error
			}
		}
		return SendResponse{}, fmt.Errorf("httpapi: status %d: %s", resp.StatusCode, msg)
	}

	var out SendResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return SendResponse{}, fmt.Errorf("httpapi: unmarshal response: %w", err)
	}
	return out, nil
}

func joinPath(basePath string, suffix string) string {
	// path.Join cleans up redundant slashes, but preserves a leading slash.
	if basePath == "" {
		basePath = "/"
	}
	return path.Join(basePath, suffix)
}

func readAllLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("httpapi: read response: %w", err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("httpapi: response too large")
	}
	return b, nil
}

