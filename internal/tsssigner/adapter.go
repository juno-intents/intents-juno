package tsssigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

var ErrInvalidConfig = errors.New("tsssigner: invalid config")

type execFn func(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, []byte, error)

type Config struct {
	TxSignBin          string
	UFVK               string
	SpendAuthSignerBin string

	// WorkDir is used for temporary files during ext-prepare/sign/finalize.
	// If empty, the OS temp directory is used.
	WorkDir string

	Exec execFn
}

type Adapter struct {
	cfg Config
}

func NewAdapter(cfg Config) (*Adapter, error) {
	if strings.TrimSpace(cfg.TxSignBin) == "" {
		return nil, fmt.Errorf("%w: missing txsign bin", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.UFVK) == "" {
		return nil, fmt.Errorf("%w: missing ufvk", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.SpendAuthSignerBin) == "" {
		return nil, fmt.Errorf("%w: missing spend-auth signer bin", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.WorkDir) == "" {
		cfg.WorkDir = os.TempDir()
	}
	if cfg.Exec == nil {
		cfg.Exec = runExec
	}
	return &Adapter{cfg: cfg}, nil
}

func (a *Adapter) Sign(ctx context.Context, sessionID [32]byte, txPlan []byte) ([]byte, error) {
	if a == nil || a.cfg.Exec == nil {
		return nil, fmt.Errorf("%w: nil adapter", ErrInvalidConfig)
	}
	if len(txPlan) == 0 {
		return nil, fmt.Errorf("%w: empty txplan", ErrInvalidConfig)
	}

	p := buildPaths(a.cfg.WorkDir, sessionID)
	if p.err != nil {
		return nil, fmt.Errorf("tsssigner: create work dir: %w", p.err)
	}
	defer os.RemoveAll(p.dir)

	if err := os.WriteFile(p.txPlan, txPlan, 0o600); err != nil {
		return nil, fmt.Errorf("tsssigner: write txplan: %w", err)
	}

	if err := a.extPrepare(ctx, p); err != nil {
		return nil, err
	}
	if err := a.signSpendAuth(ctx, sessionID, p); err != nil {
		return nil, err
	}
	return a.extFinalize(ctx, p)
}

func (a *Adapter) extPrepare(ctx context.Context, p paths) error {
	stdout, stderr, err := a.cfg.Exec(ctx, a.cfg.TxSignBin, []string{
		"ext-prepare",
		"--txplan", p.txPlan,
		"--ufvk", a.cfg.UFVK,
		"--out-prepared", p.prepared,
		"--out-requests", p.requests,
	}, nil)
	if err != nil {
		return commandError("ext-prepare", err, stdout, stderr)
	}
	if err := ensureTxSignEnvelopeOK(stdout); err != nil {
		return fmt.Errorf("tsssigner: ext-prepare response: %w", err)
	}
	return nil
}

func (a *Adapter) signSpendAuth(ctx context.Context, sessionID [32]byte, p paths) error {
	stdout, stderr, err := a.cfg.Exec(ctx, a.cfg.SpendAuthSignerBin, []string{
		"sign-spendauth",
		"--session-id", "0x" + hex.EncodeToString(sessionID[:]),
		"--requests", p.requests,
		"--out", p.sigs,
	}, nil)
	if err != nil {
		return commandError("sign-spendauth", err, stdout, stderr)
	}

	b, err := os.ReadFile(p.sigs)
	if err != nil {
		return fmt.Errorf("tsssigner: read spend-auth signatures: %w", err)
	}
	var sub spendAuthSigSubmission
	if err := json.Unmarshal(b, &sub); err != nil {
		return fmt.Errorf("tsssigner: invalid spend-auth signatures: %w", err)
	}
	if err := validateSpendAuthSubmission(sub); err != nil {
		return fmt.Errorf("tsssigner: invalid spend-auth signatures: %w", err)
	}
	return nil
}

func (a *Adapter) extFinalize(ctx context.Context, p paths) ([]byte, error) {
	stdout, stderr, err := a.cfg.Exec(ctx, a.cfg.TxSignBin, []string{
		"ext-finalize",
		"--prepared-tx", p.prepared,
		"--sigs", p.sigs,
		"--json",
	}, nil)
	if err != nil {
		return nil, commandError("ext-finalize", err, stdout, stderr)
	}

	hexRaw, err := parseFinalizeRawHex(stdout)
	if err != nil {
		return nil, fmt.Errorf("tsssigner: ext-finalize response: %w", err)
	}
	rawTx, err := decodeHexBytesStrict(hexRaw)
	if err != nil {
		return nil, fmt.Errorf("tsssigner: decode raw tx hex: %w", err)
	}
	if len(rawTx) == 0 {
		return nil, fmt.Errorf("tsssigner: empty raw tx")
	}
	return rawTx, nil
}

func runExec(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func commandError(op string, cmdErr error, stdout []byte, stderr []byte) error {
	msg := strings.TrimSpace(string(stderr))
	if msg == "" {
		msg = strings.TrimSpace(string(stdout))
	}
	if msg == "" {
		return fmt.Errorf("tsssigner: %s failed: %w", op, cmdErr)
	}
	return fmt.Errorf("tsssigner: %s failed: %w: %s", op, cmdErr, msg)
}

type paths struct {
	dir      string
	txPlan   string
	prepared string
	requests string
	sigs     string
	err      error
}

func buildPaths(workDir string, sessionID [32]byte) paths {
	prefix := hex.EncodeToString(sessionID[:4])
	dir, err := os.MkdirTemp(workDir, "tsssigner-"+prefix+"-")
	return paths{
		dir:      dir,
		txPlan:   filepath.Join(dir, "txplan.json"),
		prepared: filepath.Join(dir, "prepared.json"),
		requests: filepath.Join(dir, "requests.json"),
		sigs:     filepath.Join(dir, "sigs.json"),
		err:      err,
	}
}

type txsignEnvelope struct {
	Version string          `json:"version"`
	Status  string          `json:"status"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func ensureTxSignEnvelopeOK(stdout []byte) error {
	var env txsignEnvelope
	if err := json.Unmarshal(stdout, &env); err != nil {
		return err
	}
	if env.Version != "v1" {
		return fmt.Errorf("unexpected version %q", env.Version)
	}
	if env.Status == "ok" {
		return nil
	}
	if env.Status == "err" {
		code := ""
		msg := ""
		if env.Error != nil {
			code = strings.TrimSpace(env.Error.Code)
			msg = strings.TrimSpace(env.Error.Message)
		}
		if code != "" || msg != "" {
			return fmt.Errorf("%s: %s", code, msg)
		}
		return fmt.Errorf("error status without details")
	}
	return fmt.Errorf("unexpected status %q", env.Status)
}

func parseFinalizeRawHex(stdout []byte) (string, error) {
	var env txsignEnvelope
	if err := json.Unmarshal(stdout, &env); err != nil {
		return "", err
	}
	if env.Version != "v1" {
		return "", fmt.Errorf("unexpected version %q", env.Version)
	}
	if env.Status == "err" {
		code := ""
		msg := ""
		if env.Error != nil {
			code = strings.TrimSpace(env.Error.Code)
			msg = strings.TrimSpace(env.Error.Message)
		}
		if code != "" {
			return "", fmt.Errorf("%s: %s", code, msg)
		}
		return "", fmt.Errorf("ext-finalize returned error")
	}
	if env.Status != "ok" {
		return "", fmt.Errorf("unexpected status %q", env.Status)
	}

	var data struct {
		RawTxHex string `json:"raw_tx_hex"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return "", err
	}
	if strings.TrimSpace(data.RawTxHex) == "" {
		return "", fmt.Errorf("missing raw_tx_hex")
	}
	return data.RawTxHex, nil
}

type spendAuthSigSubmission struct {
	Version    string               `json:"version"`
	Signatures []spendAuthSignature `json:"signatures"`
}

type spendAuthSignature struct {
	ActionIndex  uint32 `json:"action_index"`
	SpendAuthSig string `json:"spend_auth_sig"`
}

func validateSpendAuthSubmission(s spendAuthSigSubmission) error {
	if s.Version != "v0" {
		return fmt.Errorf("unexpected version %q", s.Version)
	}
	if len(s.Signatures) == 0 {
		return fmt.Errorf("empty signatures")
	}
	seen := make(map[uint32]struct{}, len(s.Signatures))
	for i, sig := range s.Signatures {
		if _, ok := seen[sig.ActionIndex]; ok {
			return fmt.Errorf("duplicate action_index %d", sig.ActionIndex)
		}
		seen[sig.ActionIndex] = struct{}{}

		b, err := decodeHexBytesStrict(sig.SpendAuthSig)
		if err != nil {
			return fmt.Errorf("signature[%d] invalid hex: %w", i, err)
		}
		if len(b) != 64 {
			return fmt.Errorf("signature[%d] invalid length %d", i, len(b))
		}
	}

	// Deterministic ordering of action_index helps avoid accidental ambiguous submissions.
	actionIndices := make([]uint32, 0, len(s.Signatures))
	for _, sig := range s.Signatures {
		actionIndices = append(actionIndices, sig.ActionIndex)
	}
	if !slices.IsSorted(actionIndices) {
		return fmt.Errorf("signatures must be sorted by action_index")
	}
	return nil
}

func decodeHexBytesStrict(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, fmt.Errorf("empty hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
