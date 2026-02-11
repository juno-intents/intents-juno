package checkpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultIPFSTimeout = 15 * time.Second

type HTTPIPFSConfig struct {
	APIURL     string
	HTTPClient *http.Client
}

type HTTPIPFSPinner struct {
	apiURL string
	client *http.Client
}

func NewHTTPIPFSPinner(cfg HTTPIPFSConfig) (*HTTPIPFSPinner, error) {
	apiURL := strings.TrimSpace(cfg.APIURL)
	if apiURL == "" {
		return nil, fmt.Errorf("%w: ipfs api url is required", ErrInvalidPersistenceConfig)
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%w: invalid ipfs api url", ErrInvalidPersistenceConfig)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultIPFSTimeout}
	}
	return &HTTPIPFSPinner{apiURL: strings.TrimRight(apiURL, "/"), client: client}, nil
}

func (p *HTTPIPFSPinner) PinJSON(ctx context.Context, payload []byte) (string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "checkpoint-package.json")
	if err != nil {
		return "", fmt.Errorf("checkpoint/ipfs: build multipart: %w", err)
	}
	if _, err := part.Write(payload); err != nil {
		return "", fmt.Errorf("checkpoint/ipfs: write multipart payload: %w", err)
	}
	if err := mw.Close(); err != nil {
		return "", fmt.Errorf("checkpoint/ipfs: close multipart: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiURL+"/api/v0/add?pin=true", &body)
	if err != nil {
		return "", fmt.Errorf("checkpoint/ipfs: build request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("checkpoint/ipfs: add: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("checkpoint/ipfs: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("checkpoint/ipfs: add failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Hash string `json:"Hash"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("checkpoint/ipfs: parse response: %w", err)
	}
	if strings.TrimSpace(out.Hash) == "" {
		return "", fmt.Errorf("checkpoint/ipfs: empty cid in response")
	}
	return out.Hash, nil
}

var _ IPFSPinner = (*HTTPIPFSPinner)(nil)
