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
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/depositrelayer"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proofclient"
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
	notes        []witnessextract.WalletNote
	notesErr     error
	wallets      []string
	witnessResp  witnessextract.WitnessResponse
	witnessErr   error
	witnessCalls int
}

func (s *stubScan) ListWalletNotes(_ context.Context, _ string) ([]witnessextract.WalletNote, error) {
	return s.notes, s.notesErr
}

func (s *stubScan) ListWalletIDs(_ context.Context) ([]string, error) {
	return s.wallets, nil
}

func (s *stubScan) OrchardWitness(_ context.Context, _ *int64, _ []uint32) (witnessextract.WitnessResponse, error) {
	s.witnessCalls++
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
	events            []depositrelayer.DepositEvent
	err               error
	sourceEventExists bool
	sourceEventJob    deposit.Job
	sourceEventErr    error
	sourceEventChecks []deposit.SourceEvent
}

func (s *stubIngester) IngestDeposit(_ context.Context, ev depositrelayer.DepositEvent) error {
	s.events = append(s.events, ev)
	return s.err
}

func (s *stubIngester) GetDepositBySourceEvent(_ context.Context, source deposit.SourceEvent) (deposit.Job, error) {
	s.sourceEventChecks = append(s.sourceEventChecks, source)
	if s.sourceEventErr != nil {
		return deposit.Job{}, s.sourceEventErr
	}
	if !s.sourceEventExists {
		return deposit.Job{}, deposit.ErrNotFound
	}
	return s.sourceEventJob, nil
}

type unusedDepositSender struct{}

func (unusedDepositSender) Send(context.Context, httpapi.SendRequest) (httpapi.SendResponse, error) {
	return httpapi.SendResponse{}, errors.New("unexpected deposit send")
}

type unusedDepositProver struct{}

func (unusedDepositProver) RequestProof(context.Context, proofclient.Request) (proofclient.Result, error) {
	return proofclient.Result{}, errors.New("unexpected deposit proof request")
}

func newDurableTestRelayer(t *testing.T, store *deposit.MemoryStore) *depositrelayer.Relayer {
	t.Helper()

	relayer, err := depositrelayer.New(depositrelayer.Config{
		BaseChainID:       testChainID,
		BridgeAddress:     testBridge,
		OWalletIVKBytes:   make([]byte, 64),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000001")},
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            time.Minute,
		DedupeMax:         10,
	}, store, unusedDepositSender{}, unusedDepositProver{}, nil)
	if err != nil {
		t.Fatalf("depositrelayer.New: %v", err)
	}
	return relayer
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

func TestScanner_ValidDeposit_EmitsSourceEvent(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x2727272727272727272727272727272727272727")
	memoHex := testMemoHex(recipient, 7)
	txid := strings.Repeat("ab", 32)
	var pos int64 = 6

	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 2, Position: &pos, Height: 91, ValueZat: 424242, MemoHex: memoHex},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{
		blockHashes: map[uint64]common.Hash{
			91: common.HexToHash("0x91"),
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
	if ev.SourceEvent == nil {
		t.Fatalf("expected source event metadata")
	}
	if ev.SourceEvent.ChainID != uint64(testChainID) {
		t.Fatalf("source event chain id: got=%d want=%d", ev.SourceEvent.ChainID, testChainID)
	}
	if got, want := common.BytesToHash(ev.SourceEvent.TxHash[:]), common.HexToHash("0x"+txid); got != want {
		t.Fatalf("source event tx hash: got=%s want=%s", got.Hex(), want.Hex())
	}
	if ev.SourceEvent.LogIndex != 2 {
		t.Fatalf("source event log index: got=%d want=2", ev.SourceEvent.LogIndex)
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

func TestScanner_RestartSkipsDurableSourceEventBeforeWitness(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x3737373737373737373737373737373737373737")
	txid := strings.Repeat("d7", 32)
	var pos int64 = 17
	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 3, Position: &pos, Height: 97, ValueZat: 700000, MemoHex: testMemoHex(recipient, 17)},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	rpc := &stubRPC{blockHashes: map[uint64]common.Hash{97: common.HexToHash("0x97")}}
	var recipient20 [20]byte
	copy(recipient20[:], recipient.Bytes())
	ingester := &stubIngester{
		sourceEventExists: true,
		sourceEventJob: deposit.Job{
			State: deposit.StateSeen,
			Deposit: deposit.Deposit{
				LeafIndex:        uint64(pos),
				Amount:           700000,
				BaseRecipient:    recipient20,
				ProofWitnessItem: make([]byte, proverinput.DepositWitnessItemLen),
				JunoHeight:       97,
			},
		},
	}

	s, err := New(testConfig(), scan, rpc, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.poll(context.Background())

	if got := scan.witnessCalls; got != 0 {
		t.Fatalf("witness calls: got=%d want=0", got)
	}
	if got := len(ingester.events); got != 0 {
		t.Fatalf("ingested events: got=%d want=0", got)
	}
	if got := len(ingester.sourceEventChecks); got != 1 {
		t.Fatalf("source event checks: got=%d want=1", got)
	}
	if got := ingester.sourceEventChecks[0]; got.ChainID != uint64(testChainID) || got.TxHash != common.HexToHash("0x"+txid) || got.LogIndex != 3 {
		t.Fatalf("source event check mismatch: got=%+v", got)
	}
	if _, ok := s.seen[noteKey(txid, 3)]; !ok {
		t.Fatalf("durable source event should be marked seen in memory")
	}
}

func TestScanner_NewSourceEventBuildsAndIngests(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x3838383838383838383838383838383838383838")
	txid := strings.Repeat("d8", 32)
	var pos int64 = 18
	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 4, Position: &pos, ValueZat: 800000, MemoHex: testMemoHex(recipient, 18)},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	ingester := &stubIngester{}

	s, err := New(testConfig(), scan, &stubRPC{}, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.poll(context.Background())

	if got := len(ingester.sourceEventChecks); got != 1 {
		t.Fatalf("source event checks: got=%d want=1", got)
	}
	if got := scan.witnessCalls; got != 1 {
		t.Fatalf("witness calls: got=%d want=1", got)
	}
	if got := len(ingester.events); got != 1 {
		t.Fatalf("ingested events: got=%d want=1", got)
	}
}

func TestScanner_SourceEventLookupFailureRetriesWithoutWitness(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x3939393939393939393939393939393939393939")
	txid := strings.Repeat("d9", 32)
	var pos int64 = 19
	scan := &stubScan{
		notes: []witnessextract.WalletNote{
			{TxID: txid, ActionIndex: 5, Position: &pos, ValueZat: 900000, MemoHex: testMemoHex(recipient, 19)},
		},
		witnessResp: makeWitnessResponse(uint32(pos)),
	}
	ingester := &stubIngester{sourceEventErr: errors.New("store unavailable")}

	s, err := New(testConfig(), scan, &stubRPC{}, ingester, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.poll(context.Background())

	if got := scan.witnessCalls; got != 0 {
		t.Fatalf("witness calls after lookup failure: got=%d want=0", got)
	}
	if got := len(ingester.events); got != 0 {
		t.Fatalf("ingested events after lookup failure: got=%d want=0", got)
	}
	if _, ok := s.seen[noteKey(txid, 5)]; ok {
		t.Fatalf("lookup failure must remain retryable")
	}

	ingester.sourceEventErr = nil
	s.poll(context.Background())
	if got := scan.witnessCalls; got != 1 {
		t.Fatalf("witness calls after retry: got=%d want=1", got)
	}
	if got := len(ingester.events); got != 1 {
		t.Fatalf("ingested events after retry: got=%d want=1", got)
	}
}

func TestScanner_RestartUsesDurableSourceMetadataBeforeWitness(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x4040404040404040404040404040404040404040")
	txid := strings.Repeat("e0", 32)
	var position int64 = 20
	note := witnessextract.WalletNote{
		TxID:        txid,
		ActionIndex: 6,
		Position:    &position,
		Height:      100,
		ValueZat:    1_000_000,
		MemoHex:     testMemoHex(recipient, 20),
	}
	store := deposit.NewMemoryStore()
	relayer := newDurableTestRelayer(t, store)

	firstScan := &stubScan{notes: []witnessextract.WalletNote{note}, witnessResp: makeWitnessResponse(uint32(position))}
	first, err := New(
		testConfig(),
		firstScan,
		&stubRPC{blockHashes: map[uint64]common.Hash{100: common.HexToHash("0x100")}},
		relayer,
		slog.Default(),
	)
	if err != nil {
		t.Fatalf("New first scanner: %v", err)
	}
	first.poll(context.Background())
	if got := firstScan.witnessCalls; got != 1 {
		t.Fatalf("first scanner witness calls: got=%d want=1", got)
	}

	secondScan := &stubScan{
		notes:      []witnessextract.WalletNote{note},
		witnessErr: errors.New("historical durable note must not request a witness"),
	}
	second, err := New(
		testConfig(),
		secondScan,
		&stubRPC{blockHashes: map[uint64]common.Hash{100: common.HexToHash("0x100")}},
		relayer,
		slog.Default(),
	)
	if err != nil {
		t.Fatalf("New second scanner: %v", err)
	}
	second.poll(context.Background())
	if got := secondScan.witnessCalls; got != 0 {
		t.Fatalf("restart witness calls: got=%d want=0", got)
	}
}

func TestScanner_DurableSourceReorgMetadataDoesNotSkip(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x4141414141414141414141414141414141414141")
	txid := strings.Repeat("e1", 32)
	tests := []struct {
		name         string
		mutate       func(*witnessextract.WalletNote)
		wantSeen     bool
		wantHeight   int64
		wantPosition uint64
	}{
		{
			name: "height changed",
			mutate: func(note *witnessextract.WalletNote) {
				note.Height = 101
			},
			wantSeen:     true,
			wantHeight:   101,
			wantPosition: 21,
		},
		{
			name: "position changed",
			mutate: func(note *witnessextract.WalletNote) {
				position := int64(22)
				note.Position = &position
			},
			wantSeen:     false,
			wantHeight:   100,
			wantPosition: 21,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var initialPosition int64 = 21
			initialNote := witnessextract.WalletNote{
				TxID:        txid,
				ActionIndex: 7,
				Position:    &initialPosition,
				Height:      100,
				ValueZat:    1_100_000,
				MemoHex:     testMemoHex(recipient, 21),
			}
			store := deposit.NewMemoryStore()
			relayer := newDurableTestRelayer(t, store)
			seedScan := &stubScan{notes: []witnessextract.WalletNote{initialNote}, witnessResp: makeWitnessResponse(uint32(initialPosition))}
			seed, err := New(
				testConfig(),
				seedScan,
				&stubRPC{blockHashes: map[uint64]common.Hash{100: common.HexToHash("0x100")}},
				relayer,
				slog.Default(),
			)
			if err != nil {
				t.Fatalf("New seed scanner: %v", err)
			}
			seed.poll(context.Background())
			if got := seedScan.witnessCalls; got != 1 {
				t.Fatalf("seed witness calls: got=%d want=1", got)
			}

			reorgNote := initialNote
			tc.mutate(&reorgNote)
			reorgPosition := uint32(*reorgNote.Position)
			reorgScan := &stubScan{notes: []witnessextract.WalletNote{reorgNote}, witnessResp: makeWitnessResponse(reorgPosition)}
			restarted, err := New(
				testConfig(),
				reorgScan,
				&stubRPC{blockHashes: map[uint64]common.Hash{uint64(reorgNote.Height): common.HexToHash("0x101")}},
				relayer,
				slog.Default(),
			)
			if err != nil {
				t.Fatalf("New restarted scanner: %v", err)
			}
			restarted.poll(context.Background())

			if got := reorgScan.witnessCalls; got != 1 {
				t.Fatalf("reorg witness calls: got=%d want=1", got)
			}
			_, seen := restarted.seen[noteKey(reorgNote.TxID, reorgNote.ActionIndex)]
			if seen != tc.wantSeen {
				t.Fatalf("reorg seen=%v want=%v", seen, tc.wantSeen)
			}
			jobs, err := store.ListByState(context.Background(), deposit.StateSeen, 10)
			if err != nil {
				t.Fatalf("ListByState: %v", err)
			}
			if got := len(jobs); got != 1 {
				t.Fatalf("durable jobs: got=%d want=1", got)
			}
			if got := jobs[0].Deposit.JunoHeight; got != tc.wantHeight {
				t.Fatalf("durable height: got=%d want=%d", got, tc.wantHeight)
			}
			if got := jobs[0].Deposit.LeafIndex; got != tc.wantPosition {
				t.Fatalf("durable position: got=%d want=%d", got, tc.wantPosition)
			}
		})
	}
}

func TestScanner_IncompleteDurableWitnessIsRebuilt(t *testing.T) {
	t.Parallel()

	recipient := common.HexToAddress("0x4242424242424242424242424242424242424242")
	txid := strings.Repeat("e2", 32)
	var position int64 = 23
	note := witnessextract.WalletNote{
		TxID:        txid,
		ActionIndex: 8,
		Position:    &position,
		Height:      102,
		ValueZat:    1_200_000,
		MemoHex:     testMemoHex(recipient, 22),
	}

	captureScan := &stubScan{notes: []witnessextract.WalletNote{note}, witnessResp: makeWitnessResponse(uint32(position))}
	captureIngester := &stubIngester{}
	capture, err := New(
		testConfig(),
		captureScan,
		&stubRPC{blockHashes: map[uint64]common.Hash{102: common.HexToHash("0x102")}},
		captureIngester,
		slog.Default(),
	)
	if err != nil {
		t.Fatalf("New capture scanner: %v", err)
	}
	capture.poll(context.Background())
	if got := len(captureIngester.events); got != 1 {
		t.Fatalf("captured events: got=%d want=1", got)
	}
	ev := captureIngester.events[0]
	depositID, err := idempotency.DepositIDV1([32]byte(ev.Commitment), ev.LeafIndex)
	if err != nil {
		t.Fatalf("DepositIDV1: %v", err)
	}
	var recipient20 [20]byte
	copy(recipient20[:], recipient.Bytes())
	store := deposit.NewMemoryStore()
	if _, _, err := store.UpsertSeen(context.Background(), deposit.Deposit{
		DepositID:     depositID,
		Commitment:    [32]byte(ev.Commitment),
		LeafIndex:     ev.LeafIndex,
		Amount:        ev.Amount,
		BaseRecipient: recipient20,
		SourceEvent:   ev.SourceEvent,
		JunoHeight:    ev.JunoHeight,
	}); err != nil {
		t.Fatalf("seed incomplete durable deposit: %v", err)
	}

	rebuildScan := &stubScan{notes: []witnessextract.WalletNote{note}, witnessResp: makeWitnessResponse(uint32(position))}
	rebuild, err := New(
		testConfig(),
		rebuildScan,
		&stubRPC{blockHashes: map[uint64]common.Hash{102: common.HexToHash("0x102")}},
		newDurableTestRelayer(t, store),
		slog.Default(),
	)
	if err != nil {
		t.Fatalf("New rebuild scanner: %v", err)
	}
	rebuild.poll(context.Background())
	if got := rebuildScan.witnessCalls; got != 1 {
		t.Fatalf("rebuild witness calls: got=%d want=1", got)
	}
	job, err := store.Get(context.Background(), depositID)
	if err != nil {
		t.Fatalf("Get rebuilt deposit: %v", err)
	}
	if got := len(job.Deposit.ProofWitnessItem); got != proverinput.DepositWitnessItemLen {
		t.Fatalf("rebuilt witness length: got=%d want=%d", got, proverinput.DepositWitnessItemLen)
	}
}

func TestDurableSourceMatchesNote(t *testing.T) {
	t.Parallel()

	var position int64 = 24
	recipient := [20]byte{0x24}
	note := witnessextract.WalletNote{Position: &position, Height: 103, ValueZat: 1_300_000}
	parsedMemo := memo.DepositMemoV1{BaseRecipient: recipient}
	baseJob := deposit.Job{
		State: deposit.StateSeen,
		Deposit: deposit.Deposit{
			LeafIndex:        24,
			Amount:           1_300_000,
			BaseRecipient:    recipient,
			ProofWitnessItem: make([]byte, proverinput.DepositWitnessItemLen),
			JunoHeight:       103,
		},
	}

	tests := []struct {
		name string
		edit func(*deposit.Job, *witnessextract.WalletNote, *memo.DepositMemoV1)
		want bool
	}{
		{name: "stable seen", want: true},
		{name: "height mismatch", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) { job.Deposit.JunoHeight-- }},
		{name: "position mismatch", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) { job.Deposit.LeafIndex-- }},
		{name: "position absent", edit: func(_ *deposit.Job, note *witnessextract.WalletNote, _ *memo.DepositMemoV1) { note.Position = nil }},
		{name: "position negative", edit: func(_ *deposit.Job, note *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			position := int64(-1)
			note.Position = &position
		}},
		{name: "amount mismatch", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) { job.Deposit.Amount-- }},
		{name: "recipient mismatch", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.Deposit.BaseRecipient[0]++
		}},
		{name: "seen witness absent", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.Deposit.ProofWitnessItem = nil
		}},
		{name: "seen witness incomplete", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.Deposit.ProofWitnessItem = []byte{0x01}
		}},
		{name: "proof requested witness absent", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.State = deposit.StateProofRequested
			job.Deposit.ProofWitnessItem = nil
		}, want: true},
		{name: "finalized witness absent", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.State = deposit.StateFinalized
			job.Deposit.ProofWitnessItem = nil
		}, want: true},
		{name: "rejected witness absent", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.State = deposit.StateRejected
			job.Deposit.ProofWitnessItem = nil
		}, want: true},
		{name: "unknown state", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.State = deposit.StateUnknown
		}},
		{name: "invalid high state", edit: func(job *deposit.Job, _ *witnessextract.WalletNote, _ *memo.DepositMemoV1) {
			job.State = deposit.StateRejected + 1
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			job := baseJob
			job.Deposit.ProofWitnessItem = append([]byte(nil), baseJob.Deposit.ProofWitnessItem...)
			candidateNote := note
			candidateMemo := parsedMemo
			if tc.edit != nil {
				tc.edit(&job, &candidateNote, &candidateMemo)
			}
			if got := durableSourceMatchesNote(job, candidateNote, candidateMemo); got != tc.want {
				t.Fatalf("durableSourceMatchesNote=%v want=%v", got, tc.want)
			}
		})
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
