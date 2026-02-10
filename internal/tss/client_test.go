package tss

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClient_Sign_SendsExpectedRequestAndParsesResponse(t *testing.T) {
	t.Parallel()

	batchID := seq32(0x10)
	txPlan := []byte("plan-v1")
	wantSigned := []byte("signed")

	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.URL.Path != SignPathV1 {
			t.Fatalf("path = %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		_ = r.Body.Close()

		var req SignRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.Version != SignRequestVersion {
			t.Fatalf("req version = %q", req.Version)
		}
		if req.SessionID != FormatSessionID(batchID) {
			t.Fatalf("req session id = %q", req.SessionID)
		}
		if !bytes.Equal(req.TxPlan, txPlan) {
			t.Fatalf("req txPlan mismatch")
		}

		respBody, _ := json.Marshal(SignResponse{
			Version:   SignResponseVersion,
			SessionID: FormatSessionID(batchID),
			SignedTx:  wantSigned,
		})

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	})

	hc := &http.Client{Transport: rt, Timeout: 2 * time.Second}
	c, err := NewClient("https://tss.local", WithHTTPClient(hc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := c.Sign(context.Background(), batchID, txPlan)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(got, wantSigned) {
		t.Fatalf("signed tx mismatch: got=%q want=%q", string(got), string(wantSigned))
	}
}

func TestClient_Sign_RejectsMismatchedSessionID(t *testing.T) {
	t.Parallel()

	batchID := seq32(0x20)
	txPlan := []byte("plan-v1")

	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		respBody, _ := json.Marshal(SignResponse{
			Version:   SignResponseVersion,
			SessionID: FormatSessionID(seq32(0x21)),
			SignedTx:  []byte("signed"),
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	})

	hc := &http.Client{Transport: rt, Timeout: 2 * time.Second}
	c, err := NewClient("https://tss.local", WithHTTPClient(hc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := c.Sign(context.Background(), batchID, txPlan); err == nil {
		t.Fatalf("expected error")
	}
}

func TestClient_Sign_ReturnsErrorOnNon200(t *testing.T) {
	t.Parallel()

	batchID := seq32(0x30)
	txPlan := []byte("plan-v1")

	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusConflict,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"error":"session_conflict"}`))),
		}, nil
	})

	hc := &http.Client{Transport: rt, Timeout: 2 * time.Second}
	c, err := NewClient("https://tss.local", WithHTTPClient(hc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := c.Sign(context.Background(), batchID, txPlan); err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewClient_RejectsInsecureHTTPByDefault(t *testing.T) {
	t.Parallel()

	if _, err := NewClient("http://tss.local"); err == nil {
		t.Fatalf("expected error")
	}
}
