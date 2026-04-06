package depositscanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/depositrelayer"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/witnessextract"
)

var (
	testBridge  = common.HexToAddress("0x1111111111111111111111111111111111111111")
	testChainID = uint32(84532)
)

func testMemoHex(recipient common.Address, nonce uint64) string {
	var bridge20 [20]byte
	copy(bridge20[:], testBridge.Bytes())
	var rec20 [20]byte
	copy(rec20[:], recipient.Bytes())
	m := memo.DepositMemoV1{
		BaseChainID:   testChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: rec20,
		Nonce:         nonce,
	}
	encoded := m.Encode()
	return hex.EncodeToString(encoded[:])
}

func testASCIIHexWrappedMemoHex(recipient common.Address, nonce uint64) string {
	raw := common.Hex2Bytes(testMemoHex(recipient, nonce))
	inner := hex.EncodeToString(bytes.TrimRight(raw, "\x00"))
	padded := make([]byte, memo.MemoLen)
	copy(padded, []byte(inner))
	return hex.EncodeToString(padded)
}

type stubScan struct {
	notes       []witnessextract.WalletNote
	notesErr    error
	wallets     []string
	witnessResp witnessextract.WitnessResponse
	witnessErr  error
}

func (s *stubScan) ListWalletNotes(_ context.Context, _ string) ([]witnessextract.WalletNote, error) {
	return s.notes, s.notesErr
}

func (s *stubScan) ListWalletIDs(_ context.Context) ([]string, error) {
	return s.wallets, nil
}

func (s *stubScan) OrchardWitness(_ context.Context, _ *int64, _ []uint32) (witnessextract.WitnessResponse, error) {
	return s.witnessResp, s.witnessErr
}

type stubRPC struct {
	action       junorpc.OrchardAction
	actionErr    error
	blockHashes  map[uint64]common.Hash
	blockHashErr error
}

func (s *stubRPC) GetOrchardAction(_ context.Context, _ string, _ uint32) (junorpc.OrchardAction, error) {
	return s.action, s.actionErr
}

func (s *stubRPC) GetBlockHash(_ context.Context, height uint64) (common.Hash, error) {
	if s.blockHashErr != nil {
		return common.Hash{}, s.blockHashErr
	}
	h, ok := s.blockHashes[height]
	if !ok {
		return common.Hash{}, errors.New("block hash not found")
	}
	return h, nil
}

type stubIngester struct {
	events []depositrelayer.DepositEvent
	err    error
}

func (s *stubIngester) IngestDeposit(_ context.Context, ev depositrelayer.DepositEvent) error {
	s.events = append(s.events, ev)
	return s.err
}

func makeAuthPath() []string {
	out := make([]string, 32)
	for i := range out {
		out[i] = strings.Repeat("00", 32)
	}
	return out
}

func makeWitnessResponse(position uint32) witnessextract.WitnessResponse {
	return witnessextract.WitnessResponse{
		AnchorHeight: 100,
		Root:         strings.Repeat("00", 32),
		Paths: []witnessextract.WitnessPath{
			{Position: position, AuthPath: makeAuthPath()},
		},
	}
}

func testNote(txid string, actionIndex int32, position int64, valueZat uint64, memoHex string) witnessextract.WalletNote {
	pos := position
	return witnessextract.WalletNote{
		TxID:        txid,
		ActionIndex: actionIndex,
		Position:    &pos,
		ValueZat:    valueZat,
		MemoHex:     memoHex,
	}
}

func testConfig() Config {
	return Config{
		WalletID:     "test-wallet",
		PollInterval: 100 * time.Millisecond,
		BaseChainID:  testChainID,
		BridgeAddr:   testBridge,
	}
}

func TestScanner_ValidDeposit(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")
	memoHex := testMemoHex(recipient, 1)
	txid := strings.Repeat("aa", 32)
	var pos int64 = 5

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, Height: 77, ValueZat: 100000, MemoHex: memoHex},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{
		blockHashes: map[uint64]common.Hash{
			77: common.HexToHash("0x77"),
		},
	}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.poll(ctx)

	if len(ingester.events) != 1 {
		t.Fatalf("expected 1 ingested event, got %d", len(ingester.events))
	}
	ev := ingester.events[0]
	if ev.Amount != 100000 {
		t.Fatalf("amount: got=%d want=100000", ev.Amount)
	}
	if ev.JunoHeight != 77 {
		t.Fatalf("juno height: got=%d want=77", ev.JunoHeight)
	}
	if len(ev.Memo) != memo.MemoLen {
		t.Fatalf("memo length: got=%d want=%d", len(ev.Memo), memo.MemoLen)
	}
	if len(ev.ProofWitnessItem) != proverinput.DepositWitnessItemLen {
		t.Fatalf("witness item length: got=%d want=%d", len(ev.ProofWitnessItem), proverinput.DepositWitnessItemLen)
	}
	leafIndex := binary.LittleEndian.Uint32(ev.ProofWitnessItem[0:4])
	if leafIndex != uint32(pos) {
		t.Fatalf("leaf index: got=%d want=%d", leafIndex, pos)
	}
}

func TestScanner_ASCIIHexWrappedMemo_ValidDeposit(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x2121212121212121212121212121212121212121")
	memoHex := testASCIIHexWrappedMemoHex(recipient, 9)
	txid := strings.Repeat("ac", 32)
	var pos int64 = 15

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, Height: 88, ValueZat: 123456, MemoHex: memoHex},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{
		blockHashes: map[uint64]common.Hash{
			88: common.HexToHash("0x88"),
		},
	}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)

	if len(ingester.events) != 1 {
		t.Fatalf("expected 1 ingested event, got %d", len(ingester.events))
	}
	ev := ingester.events[0]
	if ev.Amount != 123456 {
		t.Fatalf("amount: got=%d want=123456", ev.Amount)
	}
	if ev.JunoHeight != 88 {
		t.Fatalf("juno height: got=%d want=88", ev.JunoHeight)
	}
	if len(ev.Memo) != memo.MemoLen {
		t.Fatalf("memo length: got=%d want=%d", len(ev.Memo), memo.MemoLen)
	}
}

func TestScanner_InvalidMemo_Skipped(t *testing.T) {
	t.Parallel()

	txid := strings.Repeat("bb", 32)
	var pos int64 = 3
	// Wrong magic — not a valid deposit memo.
	badMemo := strings.Repeat("00", 512)

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 50000, MemoHex: badMemo},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)

	if len(ingester.events) != 0 {
		t.Fatalf("expected 0 ingested events for invalid memo, got %d", len(ingester.events))
	}
	// Should be marked as seen.
	key := noteKey(txid, 0)
	if _, ok := s.seen[key]; !ok {
		t.Fatalf("invalid memo note should be marked seen")
	}
}

func TestScanner_NoMemo_Skipped(t *testing.T) {
	t.Parallel()

	txid := strings.Repeat("cc", 32)
	var pos int64 = 1

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 10000, MemoHex: ""},
		},
	}
	rpc := &stubRPC{}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)

	if len(ingester.events) != 0 {
		t.Fatalf("expected 0 ingested events for no-memo note, got %d", len(ingester.events))
	}
	key := noteKey(txid, 0)
	if _, ok := s.seen[key]; !ok {
		t.Fatalf("no-memo note should be marked seen")
	}
}

func TestScanner_Duplicate_NotReprocessed(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	memoHex := testMemoHex(recipient, 2)
	txid := strings.Repeat("dd", 32)
	var pos int64 = 7

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 200000, MemoHex: memoHex},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)
	s.poll(ctx)

	if len(ingester.events) != 1 {
		t.Fatalf("expected exactly 1 ingested event after 2 polls, got %d", len(ingester.events))
	}
}

func TestScanner_WitnessBuildFailure_RetriedNextPoll(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x4444444444444444444444444444444444444444")
	memoHex := testMemoHex(recipient, 3)
	txid := strings.Repeat("ee", 32)
	var pos int64 = 9

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 300000, MemoHex: memoHex},
		},
		witnessErr: errors.New("network timeout"),
	}
	rpc := &stubRPC{}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	// First poll: witness request fails — should NOT be marked seen.
	s.poll(ctx)
	if len(ingester.events) != 0 {
		t.Fatalf("expected 0 events after failed witness, got %d", len(ingester.events))
	}
	key := noteKey(txid, 0)
	if _, ok := s.seen[key]; ok {
		t.Fatalf("note should not be marked seen after transient error")
	}

	// Fix the witness and retry.
	scan.witnessErr = nil
	scan.witnessResp = makeWitnessResponse(uint32(pos))
	s.poll(ctx)
	if len(ingester.events) != 1 {
		t.Fatalf("expected 1 event after retry, got %d", len(ingester.events))
	}
}

func TestScanner_PermanentIngestError_MarkedSeen(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x5555555555555555555555555555555555555555")
	memoHex := testMemoHex(recipient, 4)
	txid := strings.Repeat("ff", 32)
	var pos int64 = 11

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 400000, MemoHex: memoHex},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{}
	ingester := &stubIngester{
		err: depositrelayer.ErrInvalidEvent,
	}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)

	key := noteKey(txid, 0)
	if _, ok := s.seen[key]; !ok {
		t.Fatalf("note should be marked seen after permanent ingest error")
	}
}

func TestScanner_WrongChainMemo_Skipped(t *testing.T) {
	t.Parallel()

	// Build a memo with wrong chain ID.
	var bridge20 [20]byte
	copy(bridge20[:], testBridge.Bytes())
	m := memo.DepositMemoV1{
		BaseChainID:   99999, // wrong chain
		BridgeAddr:    bridge20,
		BaseRecipient: [20]byte{0x22},
		Nonce:         1,
	}
	encoded := m.Encode()
	wrongChainMemo := hex.EncodeToString(encoded[:])

	txid := strings.Repeat("ab", 32)
	var pos int64 = 2

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 50000, MemoHex: wrongChainMemo},
		},
	}
	rpc := &stubRPC{}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)

	if len(ingester.events) != 0 {
		t.Fatalf("expected 0 events for wrong-chain memo, got %d", len(ingester.events))
	}
}

func TestScanner_ListNotesError_NoProcessing(t *testing.T) {
	t.Parallel()

	scan := &stubScan{
		notesErr: errors.New("connection refused"),
	}
	rpc := &stubRPC{}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)

	if len(ingester.events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(ingester.events))
	}
}

func TestScanner_ReorgClearsSeenEntriesAtForkHeight(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x6666666666666666666666666666666666666666")
	memoHex := testMemoHex(recipient, 5)
	txid := strings.Repeat("12", 32)
	var pos int64 = 13

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 600000, MemoHex: memoHex, Height: 100},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{
		blockHashes: map[uint64]common.Hash{
			100: common.HexToHash("0x100"),
		},
	}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	s.poll(ctx)
	if len(ingester.events) != 1 {
		t.Fatalf("expected 1 event after first poll, got %d", len(ingester.events))
	}

	scan.notes = []witnessextract.WalletNote{
		{TxID: txid, ActionIndex: 0, Position: &pos, ValueZat: 700000, MemoHex: memoHex, Height: 100},
	}
	rpc.blockHashes[100] = common.HexToHash("0x200")

	s.poll(ctx)
	if len(ingester.events) != 2 {
		t.Fatalf("expected note to be replayed after reorg, got %d events", len(ingester.events))
	}
	if got := ingester.events[1].Amount; got != 700000 {
		t.Fatalf("replayed event amount: got=%d want=700000", got)
	}
}
