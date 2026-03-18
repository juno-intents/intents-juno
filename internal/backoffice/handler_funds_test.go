package backoffice

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juno-intents/intents-juno/internal/emf"
)

type metricCapture struct {
	calls [][]emf.Metric
}

func (m *metricCapture) Emit(metrics ...emf.Metric) error {
	cloned := append([]emf.Metric(nil), metrics...)
	m.calls = append(m.calls, cloned)
	return nil
}

func TestExtractProtoString(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		fieldNum uint8
		want     string
		wantErr  bool
	}{
		{
			name:     "simple field 1",
			buf:      []byte{0x0a, 0x05, 'h', 'e', 'l', 'l', 'o'},
			fieldNum: 1,
			want:     "hello",
		},
		{
			name:     "field 1 after varint field 2",
			buf:      append([]byte{0x10, 0x2a}, []byte{0x0a, 0x03, 'f', 'o', 'o'}...), // field 2 varint 42, then field 1 string "foo"
			fieldNum: 1,
			want:     "foo",
		},
		{
			name:     "field not found",
			buf:      []byte{0x12, 0x03, 'a', 'b', 'c'}, // field 2 string "abc"
			fieldNum: 1,
			wantErr:  true,
		},
		{
			name:     "empty buffer",
			buf:      []byte{},
			fieldNum: 1,
			wantErr:  true,
		},
		{
			name:     "credits format",
			buf:      []byte{0x0a, 0x07, '1', '0', '0', '0', '0', '0', '0'},
			fieldNum: 1,
			want:     "1000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractProtoString(tt.buf, tt.fieldNum)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeVarint(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want uint64
		endI int
	}{
		{name: "single byte", buf: []byte{0x14}, want: 20, endI: 1},
		{name: "zero", buf: []byte{0x00}, want: 0, endI: 1},
		{name: "127", buf: []byte{0x7f}, want: 127, endI: 1},
		{name: "128 (two bytes)", buf: []byte{0x80, 0x01}, want: 128, endI: 2},
		{name: "300 (two bytes)", buf: []byte{0xac, 0x02}, want: 300, endI: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, endI := decodeVarint(tt.buf, 0)
			if val != tt.want {
				t.Errorf("value: got %d, want %d", val, tt.want)
			}
			if endI != tt.endI {
				t.Errorf("endI: got %d, want %d", endI, tt.endI)
			}
		})
	}
}

func TestFetchSP1Balance_ProtobufEncoding(t *testing.T) {
	// Verify that the protobuf encoding for GetBalanceRequest is correct.
	// GetBalanceRequest{bytes address = 1} for a known address.
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	addrBytes := addr.Bytes()

	// Build proto the same way fetchSP1Balance does.
	proto := make([]byte, 0, 2+len(addrBytes))
	proto = append(proto, 0x0a, byte(len(addrBytes)))
	proto = append(proto, addrBytes...)

	// Verify structure: tag 0x0a (field 1, wire type 2), length 20, then 20 address bytes.
	if len(proto) != 22 {
		t.Fatalf("proto length: got %d, want 22", len(proto))
	}
	if proto[0] != 0x0a {
		t.Errorf("tag byte: got 0x%02x, want 0x0a", proto[0])
	}
	if proto[1] != 20 {
		t.Errorf("length byte: got %d, want 20", proto[1])
	}

	// Build gRPC frame.
	frame := make([]byte, 5+len(proto))
	frame[0] = 0 // no compression
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(proto)))
	copy(frame[5:], proto)

	if len(frame) != 27 {
		t.Fatalf("frame length: got %d, want 27", len(frame))
	}
	if frame[0] != 0 {
		t.Error("compression flag should be 0")
	}
	msgLen := binary.BigEndian.Uint32(frame[1:5])
	if msgLen != 22 {
		t.Errorf("frame message length: got %d, want 22", msgLen)
	}

	// Verify we can decode the response format.
	// Simulate GetBalanceResponse{string amount = 1} = "500000"
	respProto := []byte{0x0a, 0x06, '5', '0', '0', '0', '0', '0'}
	credits, err := extractProtoString(respProto, 1)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if credits != "500000" {
		t.Errorf("credits: got %q, want %q", credits, "500000")
	}
}

func TestFundsBalanceAddressesPrefersBaseRelayerSigners(t *testing.T) {
	operatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	relayerAddr := common.HexToAddress("0xd68c28f414b210a6c519d05159014378a5b8bc0f")
	s := &Server{
		cfg: ServerConfig{
			OperatorAddresses:          []common.Address{operatorAddr},
			BaseRelayerSignerAddresses: []common.Address{relayerAddr},
		},
	}

	got := s.fundsBalanceAddresses()
	if len(got) != 1 || got[0] != relayerAddr {
		t.Fatalf("fundsBalanceAddresses = %v, want [%s]", got, relayerAddr.Hex())
	}
}

func TestFundsBalanceAddressesFallsBackToOperatorAddresses(t *testing.T) {
	operatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	s := &Server{
		cfg: ServerConfig{
			OperatorAddresses: []common.Address{operatorAddr},
		},
	}

	got := s.fundsBalanceAddresses()
	if len(got) != 1 || got[0] != operatorAddr {
		t.Fatalf("fundsBalanceAddresses = %v, want [%s]", got, operatorAddr.Hex())
	}
}

func TestHandleFundsUsesBaseRelayerSignerAddresses(t *testing.T) {
	operatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	relayerAddr := common.HexToAddress("0xd68c28f414b210a6c519d05159014378a5b8bc0f")

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		if req.Method != "eth_getBalance" {
			t.Fatalf("unexpected method: %s", req.Method)
		}
		var addrHex string
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params[0], &addrHex); err != nil {
				t.Fatalf("decode balance address: %v", err)
			}
		}
		addr := common.HexToAddress(addrHex)
		result := "0x0"
		if addr == relayerAddr {
			result = "0x38d7ea4c68000"
		}
		if addr == operatorAddr {
			result = "0x1"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		}); err != nil {
			t.Fatalf("encode rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	client, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer client.Close()

	s := &Server{
		cfg: ServerConfig{
			BaseClient:                 client,
			OperatorAddresses:          []common.Address{operatorAddr},
			BaseRelayerSignerAddresses: []common.Address{relayerAddr},
			BaseRelayerFundsMinWei:     big.NewInt(250_000_000_000_000),
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Operators []struct {
			Address        string `json:"address"`
			BalanceWei     string `json:"balanceWei"`
			BelowThreshold bool   `json:"belowThreshold"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(body.Operators) != 1 {
		t.Fatalf("operators len = %d, want 1", len(body.Operators))
	}
	if got := body.Operators[0].Address; got != relayerAddr.Hex() {
		t.Fatalf("address = %s, want %s", got, relayerAddr.Hex())
	}
	if got := body.Operators[0].BalanceWei; got != "1000000000000000" {
		t.Fatalf("balanceWei = %s, want %s", got, "1000000000000000")
	}
	if body.Operators[0].BelowThreshold {
		t.Fatalf("belowThreshold = true, want false")
	}
}

func TestHandleFundsEmitsWalletThresholdMetric(t *testing.T) {
	relayerAddr := common.HexToAddress("0xd68c28f414b210a6c519d05159014378a5b8bc0f")
	metrics := &metricCapture{}

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  "0x1",
		}); err != nil {
			t.Fatalf("encode rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	client, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer client.Close()

	s := &Server{
		cfg: ServerConfig{
			BaseClient:                 client,
			BaseRelayerSignerAddresses: []common.Address{relayerAddr},
			BaseRelayerFundsMinWei:     big.NewInt(2),
			MetricsEmitter:             metrics,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if len(metrics.calls) != 1 {
		t.Fatalf("metric calls = %d, want 1", len(metrics.calls))
	}
	found := false
	for _, metric := range metrics.calls[0] {
		if metric.Name == "WalletBalanceBelowThreshold" {
			found = true
			if metric.Value != 1 {
				t.Fatalf("WalletBalanceBelowThreshold = %v, want 1", metric.Value)
			}
		}
	}
	if !found {
		t.Fatalf("WalletBalanceBelowThreshold metric not emitted")
	}
}

func TestHandleFundsIncludesConfiguredMPCWalletAddress(t *testing.T) {
	junoRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"transparent": "0.00000000",
				"private":     "12.34000000",
				"total":       "12.34000000",
			},
			"error": nil,
		}); err != nil {
			t.Fatalf("encode juno rpc response: %v", err)
		}
	}))
	defer junoRPC.Close()

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "0x0",
		}); err != nil {
			t.Fatalf("encode eth rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	baseClient, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer baseClient.Close()

	s := &Server{
		cfg: ServerConfig{
			BaseClient: baseClient,
			JunoRPCURL: junoRPC.URL,
			OWalletUA:  "u1examplempcwallet",
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		MPCWallet struct {
			Address string `json:"address"`
			Total   string `json:"total"`
		} `json:"mpcWallet"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.MPCWallet.Address != "u1examplempcwallet" {
		t.Fatalf("mpc address = %q, want %q", body.MPCWallet.Address, "u1examplempcwallet")
	}
	if body.MPCWallet.Total != "12.34000000" {
		t.Fatalf("mpc total = %q, want %q", body.MPCWallet.Total, "12.34000000")
	}
}

func TestHandleFundsIncludesConfiguredMPCWalletAddressWithoutJunoRPC(t *testing.T) {
	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "0x0",
		}); err != nil {
			t.Fatalf("encode eth rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	baseClient, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer baseClient.Close()

	s := &Server{
		cfg: ServerConfig{
			BaseClient: baseClient,
			OWalletUA:  "u1examplempcwallet",
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		MPCWallet struct {
			Address string `json:"address"`
			Error   string `json:"error"`
		} `json:"mpcWallet"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.MPCWallet.Address != "u1examplempcwallet" {
		t.Fatalf("mpc address = %q, want %q", body.MPCWallet.Address, "u1examplempcwallet")
	}
	if body.MPCWallet.Error != "Juno RPC not configured on app host" {
		t.Fatalf("mpc error = %q, want %q", body.MPCWallet.Error, "Juno RPC not configured on app host")
	}
}

func TestHandleFundsFallsBackAcrossConfiguredJunoRPCURLs(t *testing.T) {
	junoRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"transparent": "0.00000000",
				"private":     "12.34000000",
				"total":       "12.34000000",
			},
			"error": nil,
		}); err != nil {
			t.Fatalf("encode juno rpc response: %v", err)
		}
	}))
	defer junoRPC.Close()

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "0x0",
		}); err != nil {
			t.Fatalf("encode eth rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	baseClient, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer baseClient.Close()

	s := &Server{
		cfg: ServerConfig{
			BaseClient:  baseClient,
			JunoRPCURLs: []string{"http://127.0.0.1:1", junoRPC.URL},
			OWalletUA:   "u1examplempcwallet",
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		MPCWallet struct {
			Address string `json:"address"`
			Total   string `json:"total"`
		} `json:"mpcWallet"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.MPCWallet.Address != "u1examplempcwallet" {
		t.Fatalf("mpc address = %q, want %q", body.MPCWallet.Address, "u1examplempcwallet")
	}
	if body.MPCWallet.Total != "12.34000000" {
		t.Fatalf("mpc total = %q, want %q", body.MPCWallet.Total, "12.34000000")
	}
}

func TestHandleFundsIncludesProverPlaceholderWhenUnconfigured(t *testing.T) {
	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "0x0",
		}); err != nil {
			t.Fatalf("encode eth rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	baseClient, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer baseClient.Close()

	s := &Server{
		cfg: ServerConfig{
			BaseClient: baseClient,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Prover struct {
			Error   string `json:"error"`
			Network string `json:"network"`
		} `json:"prover"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Prover.Error != "SP1 requestor not configured on app host" {
		t.Fatalf("prover error = %q, want %q", body.Prover.Error, "SP1 requestor not configured on app host")
	}
	if body.Prover.Network != "succinct" {
		t.Fatalf("prover network = %q, want %q", body.Prover.Network, "succinct")
	}
}

func TestHandleFundsMarksSuccinctNetworkOnProverError(t *testing.T) {
	sp1RPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer sp1RPC.Close()

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "0x0",
		}); err != nil {
			t.Fatalf("encode eth rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	baseClient, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer baseClient.Close()

	requestor := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	s := &Server{
		cfg: ServerConfig{
			BaseClient:          baseClient,
			SP1RPCURL:           sp1RPC.URL,
			SP1RequestorAddress: requestor,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Prover struct {
			Address string `json:"address"`
			Error   string `json:"error"`
			Network string `json:"network"`
		} `json:"prover"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Prover.Address != requestor.Hex() {
		t.Fatalf("prover address = %q, want %q", body.Prover.Address, requestor.Hex())
	}
	if body.Prover.Network != "succinct" {
		t.Fatalf("prover network = %q, want %q", body.Prover.Network, "succinct")
	}
	if body.Prover.Error != "grpc http status 500" {
		t.Fatalf("prover error = %q, want %q", body.Prover.Error, "grpc http status 500")
	}
}

func TestHandleFundsIncludesMPCPlaceholderWhenUnconfigured(t *testing.T) {
	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "0x0",
		}); err != nil {
			t.Fatalf("encode eth rpc response: %v", err)
		}
	}))
	defer rpcServer.Close()

	baseClient, err := ethclient.Dial(rpcServer.URL)
	if err != nil {
		t.Fatalf("dial eth rpc: %v", err)
	}
	defer baseClient.Close()

	s := &Server{
		cfg: ServerConfig{
			BaseClient: baseClient,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/funds", nil)
	s.handleFunds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		MPCWallet struct {
			Error string `json:"error"`
		} `json:"mpcWallet"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.MPCWallet.Error != "MPC wallet address not configured on app host" {
		t.Fatalf("mpc error = %q, want %q", body.MPCWallet.Error, "MPC wallet address not configured on app host")
	}
}
