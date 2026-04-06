package backoffice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestProbeIPFS_UsesBearerTokenWhenConfigured(t *testing.T) {
	t.Parallel()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"Version":"0.1.0"}`)
	}))
	defer srv.Close()

	result := probeIPFS(context.Background(), srv.Client(), srv.URL, "secret-token")
	if healthy, ok := result["healthy"].(bool); !ok || !healthy {
		t.Fatalf("healthy = %#v, want true", result["healthy"])
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, "Bearer secret-token")
	}
}

func TestDepositStateIsStuckIncludesSubmitted(t *testing.T) {
	t.Parallel()

	if !depositStateIsStuck(5) {
		t.Fatalf("expected submitted deposits to be considered stuck when stale")
	}
	if depositStateIsStuck(6) {
		t.Fatalf("expected finalized deposits to be excluded from stuck view")
	}
	if depositStateIsStuck(7) {
		t.Fatalf("expected rejected deposits to be excluded from stuck view")
	}
}

func TestCollectStuckDepositsIncludesSubmittedAttempts(t *testing.T) {
	t.Parallel()

	threshold := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	depositUpdatedAt := threshold.Add(-31 * time.Minute)
	attemptUpdatedAt := threshold.Add(-45 * time.Minute)

	rows := &fakeStuckRows{
		pos: -1,
		rows: [][]any{
			{
				[]byte{0x01, 0x02},
				int16(5),
				threshold.Add(-2 * time.Hour),
				depositUpdatedAt,
			},
			{
				[]byte{0xff, 0xee},
				int16(6),
				threshold.Add(-2 * time.Hour),
				depositUpdatedAt,
			},
		},
	}
	gotDeposits, err := collectStuckDepositRows(rows, threshold)
	if err != nil {
		t.Fatalf("collectStuckDepositRows: %v", err)
	}
	if len(gotDeposits) != 1 {
		t.Fatalf("stuck deposits len = %d, want 1", len(gotDeposits))
	}
	if gotDeposits[0]["depositId"] != "0x0102" {
		t.Fatalf("depositId = %v, want 0x0102", gotDeposits[0]["depositId"])
	}
	if gotDeposits[0]["kind"] != "deposit" {
		t.Fatalf("kind = %v, want deposit", gotDeposits[0]["kind"])
	}

	attemptRows := &fakeStuckRows{
		pos: -1,
		rows: [][]any{
			{
				[]byte{0xaa, 0xbb},
				"owner-a",
				threshold.Add(-4 * time.Hour),
				attemptUpdatedAt,
			},
			{
				[]byte{0xcc, 0xdd},
				"owner-b",
				threshold.Add(-4 * time.Hour),
				threshold.Add(10 * time.Minute),
			},
		},
	}
	gotAttempts, err := collectStuckSubmittedAttemptRows(attemptRows, threshold)
	if err != nil {
		t.Fatalf("collectStuckSubmittedAttemptRows: %v", err)
	}
	if len(gotAttempts) != 1 {
		t.Fatalf("stuck attempts len = %d, want 1", len(gotAttempts))
	}
	if gotAttempts[0]["batchId"] != "0xaabb" {
		t.Fatalf("batchId = %v, want 0xaabb", gotAttempts[0]["batchId"])
	}
	if gotAttempts[0]["kind"] != "submitted_attempt" {
		t.Fatalf("kind = %v, want submitted_attempt", gotAttempts[0]["kind"])
	}
	if gotAttempts[0]["owner"] != "owner-a" {
		t.Fatalf("owner = %v, want owner-a", gotAttempts[0]["owner"])
	}
}

func TestHandleOperatorStatusUsesHTTPHealthEndpoint(t *testing.T) {
	t.Parallel()

	operatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	signerAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("path = %q, want /healthz", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	defer signerAPI.Close()

	endpointURL, err := url.Parse(signerAPI.URL)
	if err != nil {
		t.Fatalf("parse signer api url: %v", err)
	}

	s := &Server{
		cfg: ServerConfig{
			OperatorEndpoints: []OperatorEndpoint{{
				Address:  operatorAddr,
				Endpoint: endpointURL.Host,
			}},
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ops/operators/status", nil)
	s.handleOperatorStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Operators []struct {
			Address string `json:"address"`
			Online  bool   `json:"online"`
			Error   string `json:"error"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Operators) != 1 {
		t.Fatalf("operators len = %d, want 1", len(body.Operators))
	}
	if body.Operators[0].Address != operatorAddr.Hex() {
		t.Fatalf("address = %q, want %q", body.Operators[0].Address, operatorAddr.Hex())
	}
	if !body.Operators[0].Online {
		t.Fatalf("online = false, want true (error=%q)", body.Operators[0].Error)
	}
	if body.Operators[0].Error != "" {
		t.Fatalf("error = %q, want empty", body.Operators[0].Error)
	}
}

type fakeStuckRows struct {
	rows [][]any
	pos  int
	err  error
}

func (r *fakeStuckRows) Next() bool {
	if r == nil {
		return false
	}
	r.pos++
	return r.pos < len(r.rows)
}

func (r *fakeStuckRows) Scan(dest ...any) error {
	if r.pos < 0 || r.pos >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.pos]
	if len(dest) != len(row) {
		return io.ErrUnexpectedEOF
	}
	for i := range dest {
		switch dst := dest[i].(type) {
		case *[]byte:
			switch v := row[i].(type) {
			case []byte:
				*dst = append([]byte(nil), v...)
			default:
				return io.ErrUnexpectedEOF
			}
		case *int16:
			v, ok := row[i].(int16)
			if !ok {
				return io.ErrUnexpectedEOF
			}
			*dst = v
		case *time.Time:
			v, ok := row[i].(time.Time)
			if !ok {
				return io.ErrUnexpectedEOF
			}
			*dst = v
		case *string:
			v, ok := row[i].(string)
			if !ok {
				return io.ErrUnexpectedEOF
			}
			*dst = v
		default:
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (r *fakeStuckRows) Close()     {}
func (r *fakeStuckRows) Err() error { return r.err }
