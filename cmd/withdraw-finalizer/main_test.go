package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/juno-intents/intents-juno/internal/junorpc"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/withdrawfinalizer"
	"github.com/juno-intents/intents-juno/internal/witnessextract"
)

func TestValidateWithdrawWitnessExtractorConfig_DisabledAllowsEmpty(t *testing.T) {
	t.Parallel()

	if err := validateWithdrawWitnessExtractorConfig(withdrawWitnessExtractorConfig{}); err != nil {
		t.Fatalf("validateWithdrawWitnessExtractorConfig: %v", err)
	}
}

func TestValidateWithdrawWitnessExtractorConfig_EnabledRequiresFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       withdrawWitnessExtractorConfig
		wantError string
	}{
		{
			name: "missing scan url",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				WalletID:   "wallet-1",
				RPCURL:     "http://127.0.0.1:8232",
				RPCUserEnv: "JUNO_RPC_USER",
				RPCPassEnv: "JUNO_RPC_PASS",
			},
			wantError: "--juno-scan-url is required",
		},
		{
			name: "missing wallet id",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				ScanURL:    "http://127.0.0.1:8080",
				RPCURL:     "http://127.0.0.1:8232",
				RPCUserEnv: "JUNO_RPC_USER",
				RPCPassEnv: "JUNO_RPC_PASS",
			},
			wantError: "--juno-scan-wallet-id is required",
		},
		{
			name: "missing rpc url",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				ScanURL:    "http://127.0.0.1:8080",
				WalletID:   "wallet-1",
				RPCUserEnv: "JUNO_RPC_USER",
				RPCPassEnv: "JUNO_RPC_PASS",
			},
			wantError: "--juno-rpc-url is required",
		},
		{
			name: "missing rpc user env",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:  true,
				ScanURL:  "http://127.0.0.1:8080",
				WalletID: "wallet-1",
				RPCURL:   "http://127.0.0.1:8232",
			},
			wantError: "--juno-rpc-user-env is required",
		},
		{
			name: "missing rpc pass env",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				ScanURL:    "http://127.0.0.1:8080",
				WalletID:   "wallet-1",
				RPCURL:     "http://127.0.0.1:8232",
				RPCUserEnv: "JUNO_RPC_USER",
			},
			wantError: "--juno-rpc-pass-env is required",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateWithdrawWitnessExtractorConfig(tc.cfg)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error: got %q want substring %q", err.Error(), tc.wantError)
			}
		})
	}
}

func TestNewWithdrawWitnessExtractor_RequiresRPCCredentials(t *testing.T) {
	cfg := withdrawWitnessExtractorConfig{
		Enabled:       true,
		ScanURL:       "http://127.0.0.1:8080",
		WalletID:      "wallet-1",
		ScanBearerEnv: "JUNO_SCAN_BEARER_TOKEN",
		RPCURL:        "http://127.0.0.1:8232",
		RPCUserEnv:    "JUNO_RPC_USER",
		RPCPassEnv:    "JUNO_RPC_PASS",
	}
	t.Setenv("JUNO_RPC_USER", "")
	t.Setenv("JUNO_RPC_PASS", "")

	_, err := newWithdrawWitnessExtractor(cfg)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "missing junocashd RPC credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithdrawWitnessExtractor_ExtractUsesTxHashActionAnchorAndIdentity(t *testing.T) {
	t.Parallel()

	scan := &stubWitnessScanClient{
		notes: []witnessextract.WalletNote{
			{
				TxID:        strings.Repeat("ab", 32),
				ActionIndex: 2,
				Position:    ptrInt64(7),
			},
		},
		witness: witnessextract.WitnessResponse{
			AnchorHeight: 321,
			Root:         "0x" + strings.Repeat("cd", 32),
			Paths: []witnessextract.WitnessPath{
				{
					Position: 7,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubWitnessRPCClient{
		action: testRPCAction(),
	}
	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(scan, rpc),
	}

	var withdrawalID [32]byte
	for i := range withdrawalID {
		withdrawalID[i] = byte(i + 1)
	}
	recipientRaw := bytes.Repeat([]byte{0x7a}, 43)
	anchorHeight := int64(321)

	got, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:       strings.Repeat("ab", 32),
		ActionIndex:  2,
		AnchorHeight: &anchorHeight,
		WithdrawalID: withdrawalID,
		RecipientUA:  recipientRaw,
	})
	if err != nil {
		t.Fatalf("ExtractWithdrawWitness: %v", err)
	}
	if len(got) != proverinput.WithdrawWitnessItemLen {
		t.Fatalf("witness item len: got %d want %d", len(got), proverinput.WithdrawWitnessItemLen)
	}
	if !bytes.Equal(got[:32], withdrawalID[:]) {
		t.Fatalf("withdrawal id prefix mismatch")
	}
	if !bytes.Equal(got[32:32+43], recipientRaw) {
		t.Fatalf("recipient raw prefix mismatch")
	}
	if gotWallet := scan.gotWalletID; gotWallet != "wallet-1" {
		t.Fatalf("wallet id: got %q want %q", gotWallet, "wallet-1")
	}
	if scan.gotAnchorHeight == nil || *scan.gotAnchorHeight != anchorHeight {
		t.Fatalf("anchor height: got %v want %d", scan.gotAnchorHeight, anchorHeight)
	}
	if gotTxID, wantTxID := rpc.gotTxID, strings.Repeat("ab", 32); gotTxID != wantTxID {
		t.Fatalf("txid: got %q want %q", gotTxID, wantTxID)
	}
	if got, want := rpc.gotActionIndex, uint32(2); got != want {
		t.Fatalf("action index: got %d want %d", got, want)
	}
}

func TestWithdrawWitnessExtractor_ExtractRejectsInvalidRecipientUALength(t *testing.T) {
	t.Parallel()

	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(&stubWitnessScanClient{}, &stubWitnessRPCClient{}),
	}
	_, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:       strings.Repeat("ab", 32),
		ActionIndex:  0,
		WithdrawalID: [32]byte{},
		RecipientUA:  []byte{0x01},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "recipient ua must be 43 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type stubWitnessScanClient struct {
	notes           []witnessextract.WalletNote
	witness         witnessextract.WitnessResponse
	gotWalletID     string
	gotAnchorHeight *int64
}

func (s *stubWitnessScanClient) ListWalletNotes(_ context.Context, walletID string) ([]witnessextract.WalletNote, error) {
	s.gotWalletID = walletID
	return append([]witnessextract.WalletNote(nil), s.notes...), nil
}

func (s *stubWitnessScanClient) OrchardWitness(_ context.Context, anchorHeight *int64, _ []uint32) (witnessextract.WitnessResponse, error) {
	if anchorHeight != nil {
		v := *anchorHeight
		s.gotAnchorHeight = &v
	}
	return s.witness, nil
}

type stubWitnessRPCClient struct {
	action         junorpc.OrchardAction
	gotTxID        string
	gotActionIndex uint32
}

func (s *stubWitnessRPCClient) GetOrchardAction(_ context.Context, txid string, actionIndex uint32) (junorpc.OrchardAction, error) {
	s.gotTxID = txid
	s.gotActionIndex = actionIndex
	return s.action, nil
}

func testRPCAction() junorpc.OrchardAction {
	var out junorpc.OrchardAction
	out.Nullifier[0] = 0x01
	out.RK[0] = 0x02
	out.CMX[0] = 0x03
	out.EphemeralKey[0] = 0x04
	out.EncCiphertext[0] = 0x05
	out.OutCiphertext[0] = 0x06
	out.CV[0] = 0x07
	return out
}

func testAuthPathHex() []string {
	out := make([]string, 32)
	for i := 0; i < 32; i++ {
		chunk := make([]byte, 32)
		chunk[0] = byte(i + 1)
		out[i] = "0x" + bytesToHex(chunk)
	}
	return out
}

func bytesToHex(in []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(in)*2)
	for i, b := range in {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}

func ptrInt64(v int64) *int64 {
	return &v
}
