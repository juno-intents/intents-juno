package checkpoint

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	ErrInvalidAggregatorConfig = errors.New("checkpoint: invalid aggregator config")
	ErrUnknownOperator         = errors.New("checkpoint: unknown operator")
	ErrOperatorMismatch        = errors.New("checkpoint: operator mismatch")
	ErrDigestMismatch          = errors.New("checkpoint: digest mismatch")
	ErrBadCheckpointDomain     = errors.New("checkpoint: bad checkpoint domain")
)

type AggregatorConfig struct {
	BaseChainID    uint64
	BridgeContract common.Address

	Operators []common.Address
	Threshold int

	// MaxOpen bounds how many distinct checkpoint digests can be tracked concurrently.
	// This is a DOS safety limit; 0 uses the default (4).
	MaxOpen int

	// MaxEmitted bounds the number of emitted digests remembered for dedupe. 0 uses the default (128).
	MaxEmitted int

	Now func() time.Time
}

// CheckpointPackageV1 is a threshold set of signatures for a single checkpoint digest.
//
// Signatures are sorted by Signer address ascending (as required by Bridge._verifyOperatorSigs).
type CheckpointPackageV1 struct {
	Digest          common.Hash
	Checkpoint      Checkpoint
	OperatorSetHash common.Hash

	Signers    []common.Address
	Signatures [][]byte

	CreatedAt time.Time
}

type Aggregator struct {
	baseChainID    uint64
	bridgeContract common.Address

	threshold int

	operators       map[common.Address]struct{}
	operatorSetHash common.Hash

	now func() time.Time

	maxOpen    int
	maxEmitted int

	open map[common.Hash]*openState

	emitted      map[common.Hash]struct{}
	emittedOrder []common.Hash
}

type openState struct {
	checkpoint Checkpoint
	firstSeen  time.Time
	sigs       map[common.Address][]byte
}

func NewAggregator(cfg AggregatorConfig) (*Aggregator, error) {
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: base chain id must be non-zero", ErrInvalidAggregatorConfig)
	}
	if cfg.BridgeContract == (common.Address{}) {
		return nil, fmt.Errorf("%w: bridge contract must be non-zero", ErrInvalidAggregatorConfig)
	}
	if cfg.Threshold <= 0 {
		return nil, fmt.Errorf("%w: threshold must be > 0", ErrInvalidAggregatorConfig)
	}
	if len(cfg.Operators) == 0 {
		return nil, fmt.Errorf("%w: operators must be non-empty", ErrInvalidAggregatorConfig)
	}
	if cfg.Threshold > len(cfg.Operators) {
		return nil, fmt.Errorf("%w: threshold %d > operator count %d", ErrInvalidAggregatorConfig, cfg.Threshold, len(cfg.Operators))
	}

	opsMap := make(map[common.Address]struct{}, len(cfg.Operators))
	for i, op := range cfg.Operators {
		if op == (common.Address{}) {
			return nil, fmt.Errorf("%w: operator at index %d is zero", ErrInvalidAggregatorConfig, i)
		}
		if _, ok := opsMap[op]; ok {
			return nil, fmt.Errorf("%w: duplicate operator %s", ErrInvalidAggregatorConfig, op)
		}
		opsMap[op] = struct{}{}
	}

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	maxOpen := cfg.MaxOpen
	if maxOpen == 0 {
		maxOpen = 4
	}
	if maxOpen < 0 {
		return nil, fmt.Errorf("%w: maxOpen must be >= 0", ErrInvalidAggregatorConfig)
	}

	maxEmitted := cfg.MaxEmitted
	if maxEmitted == 0 {
		maxEmitted = 128
	}
	if maxEmitted < 0 {
		return nil, fmt.Errorf("%w: maxEmitted must be >= 0", ErrInvalidAggregatorConfig)
	}

	operatorSetHash := computeOperatorSetHash(cfg.BaseChainID, cfg.BridgeContract, uint64(cfg.Threshold), cfg.Operators)

	return &Aggregator{
		baseChainID:     cfg.BaseChainID,
		bridgeContract:  cfg.BridgeContract,
		threshold:       cfg.Threshold,
		operators:       opsMap,
		operatorSetHash: operatorSetHash,
		now:             nowFn,
		maxOpen:         maxOpen,
		maxEmitted:      maxEmitted,
		open:            make(map[common.Hash]*openState),
		emitted:         make(map[common.Hash]struct{}),
	}, nil
}

// AddSignature ingests a signer output message and returns a package once the threshold is met.
//
// It is safe to call AddSignature with duplicate messages; duplicates are ignored.
func (a *Aggregator) AddSignature(msg SignatureMessageV1) (*CheckpointPackageV1, bool, error) {
	if msg.Checkpoint.BaseChainID != a.baseChainID || msg.Checkpoint.BridgeContract != a.bridgeContract {
		return nil, false, fmt.Errorf("%w: want chainID=%d bridge=%s got chainID=%d bridge=%s",
			ErrBadCheckpointDomain,
			a.baseChainID, a.bridgeContract,
			msg.Checkpoint.BaseChainID, msg.Checkpoint.BridgeContract,
		)
	}

	d := Digest(msg.Checkpoint)
	if msg.Digest != d {
		return nil, false, fmt.Errorf("%w: computed %s got %s", ErrDigestMismatch, d, msg.Digest)
	}

	sig, err := normalizeSignatureV(msg.Signature)
	if err != nil {
		return nil, false, err
	}

	signer, err := RecoverSigner(d, sig)
	if err != nil {
		return nil, false, err
	}
	if msg.Operator != signer {
		return nil, false, fmt.Errorf("%w: claimed %s recovered %s", ErrOperatorMismatch, msg.Operator, signer)
	}
	if _, ok := a.operators[signer]; !ok {
		return nil, false, fmt.Errorf("%w: %s", ErrUnknownOperator, signer)
	}

	// If already emitted, ignore (idempotent).
	if _, ok := a.emitted[d]; ok {
		return nil, false, nil
	}

	st, ok := a.open[d]
	if !ok {
		if a.maxOpen > 0 && len(a.open) >= a.maxOpen {
			a.evictOldestOpen()
		}
		st = &openState{
			checkpoint: msg.Checkpoint,
			firstSeen:  a.now(),
			sigs:       make(map[common.Address][]byte),
		}
		a.open[d] = st
	}

	if _, exists := st.sigs[signer]; exists {
		return nil, false, nil
	}
	st.sigs[signer] = sig

	if len(st.sigs) < a.threshold {
		return nil, false, nil
	}

	// Build minimal threshold set, sorted by signer address ascending.
	type pair struct {
		signer common.Address
		sig    []byte
	}
	pairs := make([]pair, 0, len(st.sigs))
	for op, s := range st.sigs {
		pairs = append(pairs, pair{signer: op, sig: s})
	}
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].signer.Bytes(), pairs[j].signer.Bytes()) < 0 })
	if len(pairs) > a.threshold {
		pairs = pairs[:a.threshold]
	}

	out := &CheckpointPackageV1{
		Digest:          d,
		Checkpoint:      st.checkpoint,
		OperatorSetHash: a.operatorSetHash,
		CreatedAt:       a.now(),
		Signers:         make([]common.Address, 0, len(pairs)),
		Signatures:      make([][]byte, 0, len(pairs)),
	}
	for _, p := range pairs {
		out.Signers = append(out.Signers, p.signer)
		out.Signatures = append(out.Signatures, p.sig)
	}

	delete(a.open, d)
	a.markEmitted(d)

	return out, true, nil
}

func (a *Aggregator) evictOldestOpen() {
	var (
		oldestDigest common.Hash
		oldestTime   time.Time
		has          bool
	)
	for d, st := range a.open {
		if !has || st.firstSeen.Before(oldestTime) {
			has = true
			oldestDigest = d
			oldestTime = st.firstSeen
		}
	}
	if has {
		delete(a.open, oldestDigest)
	}
}

func (a *Aggregator) markEmitted(d common.Hash) {
	a.emitted[d] = struct{}{}
	a.emittedOrder = append(a.emittedOrder, d)
	if a.maxEmitted <= 0 {
		return
	}
	for len(a.emittedOrder) > a.maxEmitted {
		evict := a.emittedOrder[0]
		a.emittedOrder = a.emittedOrder[1:]
		delete(a.emitted, evict)
	}
}

func normalizeSignatureV(sig []byte) ([]byte, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidSignature, len(sig))
	}
	out := make([]byte, 65)
	copy(out, sig)
	switch out[64] {
	case 0, 1:
		out[64] += 27
	case 27, 28:
		// ok
	default:
		return nil, fmt.Errorf("%w: bad v %d", ErrInvalidSignature, out[64])
	}
	return out, nil
}

func computeOperatorSetHash(baseChainID uint64, bridge common.Address, threshold uint64, operators []common.Address) common.Hash {
	ops := make([]common.Address, 0, len(operators))
	seen := make(map[common.Address]struct{}, len(operators))
	for _, op := range operators {
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return bytes.Compare(ops[i].Bytes(), ops[j].Bytes()) < 0 })

	var b []byte
	b = append(b, []byte("WJUNO_OPERATOR_SET_V1")...)
	b = append(b, encodeUint256FromUint64(baseChainID)...)
	b = append(b, encodeAddress(bridge)...)
	b = append(b, encodeUint256FromUint64(threshold)...)
	for _, op := range ops {
		b = append(b, encodeAddress(op)...)
	}
	return crypto.Keccak256Hash(b)
}
