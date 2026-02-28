package witnessextract

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	"github.com/juno-intents/intents-juno/internal/witnessitem"
)

var (
	ErrInvalidConfig = errors.New("witnessextract: invalid config")
	ErrNoteNotFound  = errors.New("witnessextract: note not found")
)

type ScanClient interface {
	ListWalletNotes(ctx context.Context, walletID string) ([]WalletNote, error)
	OrchardWitness(ctx context.Context, anchorHeight *int64, positions []uint32) (WitnessResponse, error)
}

type RPCClient interface {
	GetOrchardAction(ctx context.Context, txid string, actionIndex uint32) (junorpc.OrchardAction, error)
}

type Builder struct {
	scan ScanClient
	rpc  RPCClient
}

type WalletNote struct {
	TxID        string
	ActionIndex int32
	Position    *int64
	ValueZat    uint64
}

type WitnessPath struct {
	Position uint32
	AuthPath []string
}

type WitnessResponse struct {
	AnchorHeight int64
	Root         string
	Paths        []WitnessPath
}

type DepositRequest struct {
	WalletID     string
	TxID         string
	ActionIndex  uint32
	AnchorHeight *int64
}

type WithdrawRequest struct {
	WalletID            string
	TxID                string
	ActionIndex         uint32
	ExpectedValueZat    *uint64
	AnchorHeight        *int64
	WithdrawalID        [32]byte
	RecipientRawAddress [43]byte
}

type BuildResult struct {
	FinalOrchardRoot common.Hash
	AnchorHeight     int64
	Position         uint32
	WitnessItem      []byte
}

func New(scan ScanClient, rpc RPCClient) *Builder {
	return &Builder{scan: scan, rpc: rpc}
}

func (b *Builder) BuildDeposit(ctx context.Context, req DepositRequest) (BuildResult, error) {
	if b == nil || b.scan == nil || b.rpc == nil {
		return BuildResult{}, fmt.Errorf("%w: nil clients", ErrInvalidConfig)
	}
	position, err := b.findNotePosition(ctx, req.WalletID, req.TxID, req.ActionIndex)
	if err != nil {
		return BuildResult{}, err
	}
	wit, err := b.scan.OrchardWitness(ctx, req.AnchorHeight, []uint32{position})
	if err != nil {
		return BuildResult{}, fmt.Errorf("witnessextract: orchard witness: %w", err)
	}
	root, err := parseHash32Hex(wit.Root)
	if err != nil {
		return BuildResult{}, fmt.Errorf("witnessextract: parse witness root: %w", err)
	}
	authPathHex, ok := findAuthPathForPosition(wit.Paths, position)
	if !ok {
		return BuildResult{}, fmt.Errorf("witnessextract: witness path missing for position %d", position)
	}
	authPath, err := decodeAuthPathHex(authPathHex)
	if err != nil {
		return BuildResult{}, err
	}
	action, err := b.rpc.GetOrchardAction(ctx, req.TxID, req.ActionIndex)
	if err != nil {
		return BuildResult{}, fmt.Errorf("witnessextract: get orchard action: %w", err)
	}
	item, err := witnessitem.EncodeDepositItem(position, authPath, toWitnessAction(action))
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		FinalOrchardRoot: root,
		AnchorHeight:     wit.AnchorHeight,
		Position:         position,
		WitnessItem:      item,
	}, nil
}

func (b *Builder) BuildWithdraw(ctx context.Context, req WithdrawRequest) (BuildResult, error) {
	if b == nil || b.scan == nil || b.rpc == nil {
		return BuildResult{}, fmt.Errorf("%w: nil clients", ErrInvalidConfig)
	}
	position, actionIndex, err := b.findWithdrawNote(ctx, req.WalletID, req.TxID, req.ActionIndex, req.ExpectedValueZat)
	if err != nil {
		return BuildResult{}, err
	}
	wit, err := b.scan.OrchardWitness(ctx, req.AnchorHeight, []uint32{position})
	if err != nil {
		return BuildResult{}, fmt.Errorf("witnessextract: orchard witness: %w", err)
	}
	root, err := parseHash32Hex(wit.Root)
	if err != nil {
		return BuildResult{}, fmt.Errorf("witnessextract: parse witness root: %w", err)
	}
	authPathHex, ok := findAuthPathForPosition(wit.Paths, position)
	if !ok {
		return BuildResult{}, fmt.Errorf("witnessextract: witness path missing for position %d", position)
	}
	authPath, err := decodeAuthPathHex(authPathHex)
	if err != nil {
		return BuildResult{}, err
	}
	action, err := b.rpc.GetOrchardAction(ctx, req.TxID, actionIndex)
	if err != nil {
		return BuildResult{}, fmt.Errorf("witnessextract: get orchard action: %w", err)
	}
	item, err := witnessitem.EncodeWithdrawItem(
		req.WithdrawalID,
		req.RecipientRawAddress,
		position,
		authPath,
		toWitnessAction(action),
	)
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		FinalOrchardRoot: root,
		AnchorHeight:     wit.AnchorHeight,
		Position:         position,
		WitnessItem:      item,
	}, nil
}

func (b *Builder) findWithdrawNote(ctx context.Context, walletID, txid string, actionIndex uint32, expectedValueZat *uint64) (uint32, uint32, error) {
	wallet := strings.TrimSpace(walletID)
	if wallet == "" {
		return 0, 0, fmt.Errorf("%w: wallet id is required", ErrInvalidConfig)
	}
	txid = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(txid)), "0x")
	if _, err := parseHash32Hex(txid); err != nil {
		return 0, 0, fmt.Errorf("%w: invalid txid: %v", ErrInvalidConfig, err)
	}

	notes, err := b.scan.ListWalletNotes(ctx, wallet)
	if err != nil {
		return 0, 0, fmt.Errorf("witnessextract: list wallet notes: %w", err)
	}

	matching := make([]WalletNote, 0, len(notes))
	for _, n := range notes {
		nTxID := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n.TxID)), "0x")
		if nTxID == txid {
			matching = append(matching, n)
		}
	}
	if len(matching) == 0 {
		return 0, 0, fmt.Errorf("%w: wallet=%s txid=%s action_index=%d", ErrNoteNotFound, wallet, txid, actionIndex)
	}

	if pos, ok, err := notePositionForActionIndex(matching, txid, actionIndex, expectedValueZat); err != nil {
		return 0, 0, err
	} else if ok {
		return pos, actionIndex, nil
	}

	if expectedValueZat != nil {
		selectedIdx := -1
		for i := range matching {
			n := matching[i]
			if n.ValueZat != *expectedValueZat {
				continue
			}
			if selectedIdx >= 0 {
				return 0, 0, fmt.Errorf("%w: ambiguous txid=%s expected_value_zat=%d", ErrNoteNotFound, txid, *expectedValueZat)
			}
			selectedIdx = i
		}
		if selectedIdx < 0 {
			return 0, 0, fmt.Errorf("%w: wallet=%s txid=%s action_index=%d expected_value_zat=%d", ErrNoteNotFound, wallet, txid, actionIndex, *expectedValueZat)
		}
		selected := matching[selectedIdx]
		if selected.ActionIndex < 0 {
			return 0, 0, fmt.Errorf("witnessextract: invalid action index for txid=%s action_index=%d", txid, selected.ActionIndex)
		}
		if selected.Position == nil || *selected.Position < 0 || *selected.Position > math.MaxUint32 {
			return 0, 0, fmt.Errorf("witnessextract: invalid note position for txid=%s action_index=%d", txid, selected.ActionIndex)
		}
		return uint32(*selected.Position), uint32(selected.ActionIndex), nil
	}

	return 0, 0, fmt.Errorf("%w: wallet=%s txid=%s action_index=%d", ErrNoteNotFound, wallet, txid, actionIndex)
}

func notePositionForActionIndex(notes []WalletNote, txid string, actionIndex uint32, expectedValueZat *uint64) (uint32, bool, error) {
	for _, n := range notes {
		if n.ActionIndex < 0 || uint32(n.ActionIndex) != actionIndex {
			continue
		}
		if expectedValueZat != nil && n.ValueZat != *expectedValueZat {
			return 0, false, nil
		}
		if n.Position == nil || *n.Position < 0 || *n.Position > math.MaxUint32 {
			return 0, false, fmt.Errorf("witnessextract: invalid note position for txid=%s action_index=%d", txid, actionIndex)
		}
		return uint32(*n.Position), true, nil
	}
	return 0, false, nil
}

func (b *Builder) findNotePosition(ctx context.Context, walletID, txid string, actionIndex uint32) (uint32, error) {
	wallet := strings.TrimSpace(walletID)
	if wallet == "" {
		return 0, fmt.Errorf("%w: wallet id is required", ErrInvalidConfig)
	}
	txid = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(txid)), "0x")
	if _, err := parseHash32Hex(txid); err != nil {
		return 0, fmt.Errorf("%w: invalid txid: %v", ErrInvalidConfig, err)
	}

	notes, err := b.scan.ListWalletNotes(ctx, wallet)
	if err != nil {
		return 0, fmt.Errorf("witnessextract: list wallet notes: %w", err)
	}
	for _, n := range notes {
		nTxID := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n.TxID)), "0x")
		if nTxID != txid || n.ActionIndex < 0 || uint32(n.ActionIndex) != actionIndex {
			continue
		}
		if n.Position == nil || *n.Position < 0 || *n.Position > math.MaxUint32 {
			return 0, fmt.Errorf("witnessextract: invalid note position for txid=%s action_index=%d", txid, actionIndex)
		}
		return uint32(*n.Position), nil
	}
	return 0, fmt.Errorf("%w: wallet=%s txid=%s action_index=%d", ErrNoteNotFound, wallet, txid, actionIndex)
}

func findAuthPathForPosition(paths []WitnessPath, position uint32) ([]string, bool) {
	for _, p := range paths {
		if p.Position == position {
			return p.AuthPath, true
		}
	}
	return nil, false
}

func decodeAuthPathHex(pathHex []string) ([][32]byte, error) {
	if len(pathHex) != 32 {
		return nil, fmt.Errorf("witnessextract: invalid auth_path depth: got=%d want=32", len(pathHex))
	}
	out := make([][32]byte, 0, len(pathHex))
	for i, h := range pathHex {
		b, err := decodeHexFixed(h, 32)
		if err != nil {
			return nil, fmt.Errorf("witnessextract: invalid auth_path[%d]: %w", i, err)
		}
		var item [32]byte
		copy(item[:], b)
		out = append(out, item)
	}
	return out, nil
}

func parseHash32Hex(raw string) (common.Hash, error) {
	b, err := decodeHexFixed(raw, 32)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(b), nil
}

func decodeHexFixed(raw string, wantLen int) ([]byte, error) {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(v, "0x")
	v = strings.TrimPrefix(v, "0X")
	if len(v) != wantLen*2 {
		return nil, fmt.Errorf("invalid hex length: got=%d want=%d", len(v), wantLen*2)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func toWitnessAction(a junorpc.OrchardAction) witnessitem.OrchardAction {
	return witnessitem.OrchardAction{
		Nullifier:     a.Nullifier,
		RK:            a.RK,
		CMX:           a.CMX,
		EphemeralKey:  a.EphemeralKey,
		EncCiphertext: a.EncCiphertext,
		OutCiphertext: a.OutCiphertext,
		CV:            a.CV,
	}
}
