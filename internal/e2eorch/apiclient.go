package e2eorch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxRetries     = 8
	retryBackoff   = 3 * time.Second
	requestTimeout = 30 * time.Second
)

// BridgeAPIClient is an HTTP client for the bridge-api service.
// All methods include retry logic for transient failures (5xx, network errors).
type BridgeAPIClient struct {
	baseURL string
	client  *http.Client
}

// NewBridgeAPIClient creates a new client pointing at the given bridge-api base URL.
func NewBridgeAPIClient(baseURL string) *BridgeAPIClient {
	return &BridgeAPIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: requestTimeout,
		},
	}
}

// WaitHealthy polls GET /healthz until a 200 response is received or the
// context is cancelled.
func (c *BridgeAPIClient) WaitHealthy(ctx context.Context) error {
	return PollUntil(ctx, 5*time.Minute, 3*time.Second, func(ctx context.Context) (bool, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
		if err != nil {
			return false, "creating request", fmt.Errorf("build healthz request: %w", err)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return false, "waiting (network error)", nil // transient, keep polling
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode == http.StatusOK {
			return true, "healthy", nil
		}
		return false, fmt.Sprintf("waiting (status %d)", resp.StatusCode), nil
	})
}

// GetConfig calls GET /v1/config and returns the parsed response.
func (c *BridgeAPIClient) GetConfig(ctx context.Context) (*BridgeConfigResponse, error) {
	var out BridgeConfigResponse
	if err := c.doGetJSON(ctx, "/v1/config", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetDepositMemo calls GET /v1/deposit-memo?baseRecipient=<addr>.
func (c *BridgeAPIClient) GetDepositMemo(ctx context.Context, baseRecipient string) (*DepositMemoResponse, error) {
	params := url.Values{}
	params.Set("baseRecipient", baseRecipient)
	var out DepositMemoResponse
	if err := c.doGetJSON(ctx, "/v1/deposit-memo?"+params.Encode(), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SubmitDeposit calls POST /v1/deposits/submit.
func (c *BridgeAPIClient) SubmitDeposit(ctx context.Context, req DepositSubmitRequest) (*DepositSubmitResponse, error) {
	var out DepositSubmitResponse
	if err := c.doPostJSON(ctx, "/v1/deposits/submit", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetDepositStatus calls GET /v1/status/deposit/{depositId}.
func (c *BridgeAPIClient) GetDepositStatus(ctx context.Context, depositID string) (*DepositStatusResponse, error) {
	var out DepositStatusResponse
	if err := c.doGetJSON(ctx, "/v1/status/deposit/"+url.PathEscape(depositID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RequestWithdrawal calls POST /v1/withdrawals/request.
func (c *BridgeAPIClient) RequestWithdrawal(ctx context.Context, req WithdrawalRequestRequest) (*WithdrawalRequestResponse, error) {
	var out WithdrawalRequestResponse
	if err := c.doPostJSON(ctx, "/v1/withdrawals/request", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetWithdrawalStatus calls GET /v1/status/withdrawal/{withdrawalId}.
func (c *BridgeAPIClient) GetWithdrawalStatus(ctx context.Context, withdrawalID string) (*WithdrawalStatusResponse, error) {
	var out WithdrawalStatusResponse
	if err := c.doGetJSON(ctx, "/v1/status/withdrawal/"+url.PathEscape(withdrawalID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// doGetJSON performs a GET request with retry logic and decodes the JSON response.
func (c *BridgeAPIClient) doGetJSON(ctx context.Context, path string, out any) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("[apiclient] retry %d/%d for GET %s", attempt, maxRetries, path)
			select {
			case <-ctx.Done():
				return fmt.Errorf("GET %s: context cancelled during retry: %w", path, ctx.Err())
			case <-time.After(retryBackoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
		if err != nil {
			return fmt.Errorf("GET %s: build request: %w", path, err)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("GET %s: %w", path, err)
			continue // network error, retry
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("GET %s: read body: %w", path, readErr)
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("GET %s: server error %d: %s", path, resp.StatusCode, truncate(body, 200))
			continue // 5xx, retry
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: unexpected status %d: %s", path, resp.StatusCode, truncate(body, 200))
		}

		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("GET %s: decode JSON: %w", path, err)
		}
		return nil
	}
	return fmt.Errorf("GET %s: exhausted %d retries: %w", path, maxRetries, lastErr)
}

// doPostJSON performs a POST request with retry logic and decodes the JSON response.
func (c *BridgeAPIClient) doPostJSON(ctx context.Context, path string, reqBody any, out any) error {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("POST %s: marshal body: %w", path, err)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("[apiclient] retry %d/%d for POST %s", attempt, maxRetries, path)
			select {
			case <-ctx.Done():
				return fmt.Errorf("POST %s: context cancelled during retry: %w", path, ctx.Err())
			case <-time.After(retryBackoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("POST %s: build request: %w", path, err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("POST %s: %w", path, err)
			continue // network error, retry
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("POST %s: read body: %w", path, readErr)
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("POST %s: server error %d: %s", path, resp.StatusCode, truncate(body, 200))
			continue // 5xx, retry
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("POST %s: unexpected status %d: %s", path, resp.StatusCode, truncate(body, 200))
		}

		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("POST %s: decode JSON: %w", path, err)
		}
		return nil
	}
	return fmt.Errorf("POST %s: exhausted %d retries: %w", path, maxRetries, lastErr)
}

// truncate returns the first n bytes of b as a string, appending "..." if truncated.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
