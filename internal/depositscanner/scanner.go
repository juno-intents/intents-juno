package depositscanner

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/depositevent"
	"github.com/juno-intents/intents-juno/internal/depositrelayer"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/witnessextract"
)

type Config struct {
	WalletID     string
	PollInterval time.Duration
	BaseChainID  uint32
	BridgeAddr   common.Address
}

type DepositIngester interface {
	IngestDeposit(ctx context.Context, ev depositrelayer.DepositEvent) error
}

type Scanner struct {
	cfg         Config
	scan        witnessextract.ScanClient
	rpc         witnessextract.RPCClient
	ingest      DepositIngester
	log         *slog.Logger
	builder     *witnessextract.Builder
	seen        map[string]struct{}
	seenHeights map[string]int64
	blockHashes map[int64]common.Hash
}

type blockHashGetter interface {
	GetBlockHash(ctx context.Context, height uint64) (common.Hash, error)
}

func New(cfg Config, scan witnessextract.ScanClient, rpc witnessextract.RPCClient, ingest DepositIngester, log *slog.Logger) (*Scanner, error) {
	if strings.TrimSpace(cfg.WalletID) == "" {
		return nil, errors.New("depositscanner: wallet id is required")
	}
	if cfg.PollInterval <= 0 {
		return nil, errors.New("depositscanner: poll interval must be > 0")
	}
	if cfg.BaseChainID == 0 {
		return nil, errors.New("depositscanner: base chain id is required")
	}
	if cfg.BridgeAddr == (common.Address{}) {
		return nil, errors.New("depositscanner: bridge address is required")
	}
	if scan == nil {
		return nil, errors.New("depositscanner: scan client is required")
	}
	if rpc == nil {
		return nil, errors.New("depositscanner: rpc client is required")
	}
	if ingest == nil {
		return nil, errors.New("depositscanner: deposit ingester is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Scanner{
		cfg:         cfg,
		scan:        scan,
		rpc:         rpc,
		ingest:      ingest,
		log:         log,
		builder:     witnessextract.New(scan, rpc),
		seen:        make(map[string]struct{}),
		seenHeights: make(map[string]int64),
		blockHashes: make(map[int64]common.Hash),
	}, nil
}

func (s *Scanner) Run(ctx context.Context) error {
	s.log.Info("deposit scanner started",
		"walletID", s.cfg.WalletID,
		"pollInterval", s.cfg.PollInterval,
		"baseChainID", s.cfg.BaseChainID,
		"bridge", s.cfg.BridgeAddr,
	)
	t := time.NewTicker(s.cfg.PollInterval)
	defer t.Stop()

	// Run once immediately on startup.
	s.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			s.log.Info("deposit scanner stopped", "reason", ctx.Err())
			return ctx.Err()
		case <-t.C:
			s.poll(ctx)
		}
	}
}

func noteKey(txid string, actionIndex int32) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(txid), "0x")) + ":" + fmt.Sprintf("%d", actionIndex)
}

func (s *Scanner) poll(ctx context.Context) {
	notes, err := s.scan.ListWalletNotes(ctx, s.cfg.WalletID)
	if err != nil {
		s.log.Error("deposit scanner: list wallet notes", "err", err)
		return
	}
	s.reconcileReorg(ctx, notes)

	var bridgeAddr20 [20]byte
	copy(bridgeAddr20[:], s.cfg.BridgeAddr.Bytes())

	for _, note := range notes {
		if ctx.Err() != nil {
			return
		}

		key := noteKey(note.TxID, note.ActionIndex)
		if _, ok := s.seen[key]; ok {
			continue
		}

		if strings.TrimSpace(note.MemoHex) == "" {
			s.markSeen(key, note.Height)
			continue
		}

		memoBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(note.MemoHex), "0x"))
		if err != nil {
			s.log.Warn("deposit scanner: decode memo hex", "key", key, "err", err)
			s.markSeen(key, note.Height)
			continue
		}

		_, memoErr := memo.ParseDepositMemoV1(memoBytes, s.cfg.BaseChainID, bridgeAddr20)
		if memoErr != nil {
			// Not a valid deposit for our domain — skip permanently.
			s.markSeen(key, note.Height)
			continue
		}

		if err := s.processNote(ctx, note, memoBytes); err != nil {
			if isPermanent(err) {
				s.log.Warn("deposit scanner: permanent error, skipping note", "key", key, "err", err)
				s.markSeen(key, note.Height)
			} else {
				s.log.Error("deposit scanner: transient error, will retry", "key", key, "err", err)
			}
			continue
		}

		s.markSeen(key, note.Height)
	}
}

func (s *Scanner) reconcileReorg(ctx context.Context, notes []witnessextract.WalletNote) {
	getter, ok := s.rpc.(blockHashGetter)
	if !ok {
		return
	}

	currentHashes := make(map[int64]common.Hash)
	forkHeight := int64(0)
	for _, note := range notes {
		if note.Height <= 0 {
			continue
		}
		if _, seen := currentHashes[note.Height]; seen {
			continue
		}
		hash, err := getter.GetBlockHash(ctx, uint64(note.Height))
		if err != nil {
			s.log.Error("deposit scanner: get block hash", "height", note.Height, "err", err)
			return
		}
		currentHashes[note.Height] = hash
		if prev, seen := s.blockHashes[note.Height]; seen && prev != hash {
			if forkHeight == 0 || note.Height < forkHeight {
				forkHeight = note.Height
			}
		}
	}

	if forkHeight > 0 {
		for key, height := range s.seenHeights {
			if height >= forkHeight {
				delete(s.seen, key)
				delete(s.seenHeights, key)
			}
		}
		for height := range s.blockHashes {
			if height >= forkHeight {
				delete(s.blockHashes, height)
			}
		}
		s.log.Warn("deposit scanner: detected juno reorg, rewinding seen notes", "fork_height", forkHeight)
	}

	for height, hash := range currentHashes {
		s.blockHashes[height] = hash
	}
}

func (s *Scanner) markSeen(key string, height int64) {
	s.seen[key] = struct{}{}
	s.seenHeights[key] = height
}

func (s *Scanner) processNote(ctx context.Context, note witnessextract.WalletNote, memoBytes []byte) error {
	actionIndex := uint32(note.ActionIndex)
	if note.ActionIndex < 0 {
		return fmt.Errorf("invalid action index %d", note.ActionIndex)
	}

	res, err := s.builder.BuildDeposit(ctx, witnessextract.DepositRequest{
		WalletID:    s.cfg.WalletID,
		TxID:        note.TxID,
		ActionIndex: actionIndex,
	})
	if err != nil {
		return fmt.Errorf("build witness: %w", err)
	}

	cm, leafIndex, err := depositevent.ParseWitnessItem(res.WitnessItem)
	if err != nil {
		return fmt.Errorf("parse witness item: %w", err)
	}

	return s.ingest.IngestDeposit(ctx, depositrelayer.DepositEvent{
		Commitment:       cm,
		LeafIndex:        leafIndex,
		Amount:           note.ValueZat,
		JunoHeight:       note.Height,
		Memo:             memoBytes,
		ProofWitnessItem: res.WitnessItem,
	})
}

func isPermanent(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, depositrelayer.ErrInvalidEvent) {
		return true
	}
	if errors.Is(err, witnessextract.ErrInvalidConfig) {
		return true
	}
	return false
}
