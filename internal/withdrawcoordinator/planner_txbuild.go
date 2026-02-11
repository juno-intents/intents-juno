package withdrawcoordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var ErrInvalidTxBuildPlannerConfig = errors.New("withdrawcoordinator: invalid txbuild planner config")

type TxBuildPlannerConfig struct {
	Binary        string
	WalletID      string
	ChangeAddress string

	BaseChainID   uint32
	BridgeAddress common.Address

	CoinType         uint32
	Account          uint32
	MinConfirmations int64
	ExpiryOffset     uint32
	FeeMultiplier    uint64
	FeeAddZat        uint64
	MinChangeZat     uint64
	MinNoteZat       uint64

	RPCURL          string
	RPCUser         string
	RPCPass         string
	ScanURL         string
	ScanBearerToken string
}

type txbuildOutput struct {
	ToAddress string `json:"to_address"`
	AmountZat string `json:"amount_zat"`
	MemoHex   string `json:"memo_hex,omitempty"`
}

type execCommandFn func(ctx context.Context, name string, args []string, env []string) ([]byte, error)

type TxBuildPlanner struct {
	cfg         TxBuildPlannerConfig
	execCommand execCommandFn
}

func NewTxBuildPlanner(cfg TxBuildPlannerConfig) (*TxBuildPlanner, error) {
	if strings.TrimSpace(cfg.Binary) == "" {
		return nil, fmt.Errorf("%w: missing binary", ErrInvalidTxBuildPlannerConfig)
	}
	if strings.TrimSpace(cfg.WalletID) == "" {
		return nil, fmt.Errorf("%w: missing wallet id", ErrInvalidTxBuildPlannerConfig)
	}
	if strings.TrimSpace(cfg.ChangeAddress) == "" {
		return nil, fmt.Errorf("%w: missing change address", ErrInvalidTxBuildPlannerConfig)
	}
	if cfg.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: base chain id must be non-zero", ErrInvalidTxBuildPlannerConfig)
	}
	if cfg.BridgeAddress == (common.Address{}) {
		return nil, fmt.Errorf("%w: bridge address must be non-zero", ErrInvalidTxBuildPlannerConfig)
	}
	if cfg.MinConfirmations <= 0 {
		return nil, fmt.Errorf("%w: min confirmations must be > 0", ErrInvalidTxBuildPlannerConfig)
	}
	if cfg.ExpiryOffset < 4 {
		return nil, fmt.Errorf("%w: expiry offset must be >= 4", ErrInvalidTxBuildPlannerConfig)
	}
	if cfg.FeeMultiplier == 0 {
		return nil, fmt.Errorf("%w: fee multiplier must be >= 1", ErrInvalidTxBuildPlannerConfig)
	}

	return &TxBuildPlanner{
		cfg:         cfg,
		execCommand: runExecCommand,
	}, nil
}

func (p *TxBuildPlanner) Plan(ctx context.Context, batchID [32]byte, ws []withdraw.Withdrawal) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil planner", ErrInvalidTxBuildPlannerConfig)
	}

	outs, err := buildTxBuildOutputs(batchID, ws, p.cfg.BaseChainID, p.cfg.BridgeAddress)
	if err != nil {
		return nil, err
	}

	tmpf, err := os.CreateTemp("", "withdraw-txbuild-outputs-*.json")
	if err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: create outputs file: %w", err)
	}
	tmpPath := tmpf.Name()
	defer func() {
		_ = tmpf.Close()
		_ = os.Remove(tmpPath)
	}()

	enc := json.NewEncoder(tmpf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(outs); err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: encode outputs file: %w", err)
	}
	if err := tmpf.Close(); err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: close outputs file: %w", err)
	}

	args := []string{
		"send-many",
		"--wallet-id", p.cfg.WalletID,
		"--coin-type", strconv.FormatUint(uint64(p.cfg.CoinType), 10),
		"--account", strconv.FormatUint(uint64(p.cfg.Account), 10),
		"--outputs-file", tmpPath,
		"--change-address", p.cfg.ChangeAddress,
		"--minconf", strconv.FormatInt(p.cfg.MinConfirmations, 10),
		"--expiry-offset", strconv.FormatUint(uint64(p.cfg.ExpiryOffset), 10),
		"--fee-multiplier", strconv.FormatUint(p.cfg.FeeMultiplier, 10),
		"--fee-add-zat", strconv.FormatUint(p.cfg.FeeAddZat, 10),
		"--min-change-zat", strconv.FormatUint(p.cfg.MinChangeZat, 10),
		"--min-note-zat", strconv.FormatUint(p.cfg.MinNoteZat, 10),
		"--json",
	}

	out, err := p.execCommand(ctx, p.cfg.Binary, args, p.commandEnv())
	if err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: txbuild command failed: %w", err)
	}
	return parseTxBuildJSONEnvelope(out)
}

func buildTxBuildOutputs(batchID [32]byte, ws []withdraw.Withdrawal, baseChainID uint32, bridgeAddress common.Address) ([]txbuildOutput, error) {
	ws2, err := withdraw.SelectForBatch(ws, len(ws))
	if err != nil {
		return nil, err
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridgeAddress[:])

	outs := make([]txbuildOutput, 0, len(ws2))
	for _, w := range ws2 {
		recipient := strings.TrimSpace(string(w.RecipientUA))
		if recipient == "" || !utf8.ValidString(recipient) {
			return nil, fmt.Errorf("withdrawcoordinator: invalid withdrawal recipient UA for %x", w.ID)
		}

		_, net, err := withdraw.ComputeFeeAndNet(w.Amount, w.FeeBps)
		if err != nil {
			return nil, err
		}

		m := memo.WithdrawalMemoV1{
			BaseChainID:  baseChainID,
			BridgeAddr:   bridge20,
			WithdrawalID: w.ID,
			BatchID:      batchID,
		}
		memoB := m.Encode()
		outs = append(outs, txbuildOutput{
			ToAddress: recipient,
			AmountZat: strconv.FormatUint(net, 10),
			MemoHex:   hex.EncodeToString(memoB[:]),
		})
	}
	return outs, nil
}

func (p *TxBuildPlanner) commandEnv() []string {
	env := os.Environ()
	if v := strings.TrimSpace(p.cfg.RPCURL); v != "" {
		env = append(env, "JUNO_RPC_URL="+v)
	}
	if v := strings.TrimSpace(p.cfg.RPCUser); v != "" {
		env = append(env, "JUNO_RPC_USER="+v)
	}
	if v := strings.TrimSpace(p.cfg.RPCPass); v != "" {
		env = append(env, "JUNO_RPC_PASS="+v)
	}
	if v := strings.TrimSpace(p.cfg.ScanURL); v != "" {
		env = append(env, "JUNO_SCAN_URL="+v)
	}
	if v := strings.TrimSpace(p.cfg.ScanBearerToken); v != "" {
		env = append(env, "JUNO_SCAN_BEARER_TOKEN="+v)
	}
	return env
}

func parseTxBuildJSONEnvelope(raw []byte) ([]byte, error) {
	var env struct {
		Version string          `json:"version"`
		Status  string          `json:"status"`
		Data    json.RawMessage `json:"data"`
		Error   *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("withdrawcoordinator: decode txbuild json envelope: %w", err)
	}
	switch env.Status {
	case "ok":
		if len(env.Data) == 0 {
			return nil, fmt.Errorf("withdrawcoordinator: txbuild returned empty plan")
		}
		var v any
		if err := json.Unmarshal(env.Data, &v); err != nil {
			return nil, fmt.Errorf("withdrawcoordinator: decode txbuild plan: %w", err)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("withdrawcoordinator: re-encode txbuild plan: %w", err)
		}
		return b, nil
	case "err":
		code := ""
		msg := ""
		if env.Error != nil {
			code = strings.TrimSpace(env.Error.Code)
			msg = strings.TrimSpace(env.Error.Message)
		}
		if msg == "" {
			msg = "unknown txbuild error"
		}
		if code != "" {
			return nil, fmt.Errorf("withdrawcoordinator: txbuild error (%s): %s", code, msg)
		}
		return nil, fmt.Errorf("withdrawcoordinator: txbuild error: %s", msg)
	default:
		return nil, fmt.Errorf("withdrawcoordinator: invalid txbuild status %q", env.Status)
	}
}

func runExecCommand(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", err, msg)
	}
	return out, nil
}
