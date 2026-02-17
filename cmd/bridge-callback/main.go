package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

const (
	proofInputsVersionV1 = "bridge-e2e.proof_inputs.v1"
	defaultRunTimeout    = 15 * time.Minute
	defaultGasLimit      = uint64(1_000_000)
)

type config struct {
	RPCURL string

	SenderKeyHex string

	ProofInputsPath string

	DepositSeal  []byte
	WithdrawSeal []byte

	ChainIDOverride uint64

	WithdrawAmountOverride *big.Int

	RunTimeout time.Duration
	OutputPath string
}

type rawProofInputsFile struct {
	Version        string `json:"version"`
	GeneratedAtUTC string `json:"generated_at_utc"`
	ChainID        uint64 `json:"chain_id"`
	BridgeContract string `json:"bridge_contract"`

	Checkpoint checkpoint.Checkpoint `json:"checkpoint"`

	OperatorSignatures []string `json:"operator_signatures"`

	Deposit struct {
		ProofInput struct {
			Pipeline string `json:"pipeline"`
			ImageID  string `json:"image_id"`
			Journal  string `json:"journal"`
		} `json:"proof_input"`
	} `json:"deposit"`

	Withdraw struct {
		ProofInput struct {
			Pipeline string `json:"pipeline"`
			ImageID  string `json:"image_id"`
			Journal  string `json:"journal"`
		} `json:"proof_input"`
		RecipientUAHex string `json:"recipient_ua_hex"`
		WithdrawalID   string `json:"withdrawal_id"`
		Amount         string `json:"amount,omitempty"`
	} `json:"withdraw"`
}

type proofBundle struct {
	ChainID        uint64
	BridgeContract common.Address
	Checkpoint     checkpoint.Checkpoint
	OperatorSigs   [][]byte

	DepositJournal  []byte
	WithdrawJournal []byte

	RecipientUA  []byte
	WithdrawalID common.Hash

	WithdrawAmount *big.Int
}

type report struct {
	GeneratedAtUTC string `json:"generated_at_utc"`
	RPCURL         string `json:"rpc_url"`
	ChainID        uint64 `json:"chain_id"`

	SenderAddress string `json:"sender_address"`

	Contracts struct {
		Bridge string `json:"bridge"`
		WJuno  string `json:"wjuno"`
	} `json:"contracts"`

	ProofInputs struct {
		Path              string `json:"path"`
		Version           string `json:"version"`
		CheckpointHeight  uint64 `json:"checkpoint_height"`
		CheckpointHash    string `json:"checkpoint_hash"`
		FinalOrchardRoot  string `json:"final_orchard_root"`
		WithdrawalID      string `json:"withdrawal_id"`
		WithdrawAmountZat string `json:"withdraw_amount_zat"`
	} `json:"proof_inputs"`

	Seals struct {
		DepositBytes  int `json:"deposit_bytes"`
		WithdrawBytes int `json:"withdraw_bytes"`
	} `json:"seals"`

	Transactions struct {
		MintBatch        string `json:"mint_batch"`
		ApproveWithdraw  string `json:"approve_withdraw"`
		RequestWithdraw  string `json:"request_withdraw"`
		FinalizeWithdraw string `json:"finalize_withdraw"`
	} `json:"transactions"`
}

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	cfg, err := parseArgs(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.RunTimeout)
	defer cancel()

	rep, err := run(ctx, cfg)
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	if cfg.OutputPath == "-" {
		_, err = fmt.Fprintf(stdout, "%s\n", out)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.OutputPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.OutputPath, append(out, '\n'), 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "wrote report: %s\n", cfg.OutputPath)
	return err
}

func parseArgs(args []string) (config, error) {
	var cfg config

	var senderKeyFile string
	var senderKeyHex string
	var depositSealFile string
	var withdrawSealFile string
	var depositSealHex string
	var withdrawSealHex string
	var withdrawAmountOverride string

	cfg.RunTimeout = defaultRunTimeout
	cfg.OutputPath = "-"

	fs := flag.NewFlagSet("bridge-callback", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.RPCURL, "rpc-url", "", "Base RPC URL")
	fs.StringVar(&senderKeyFile, "sender-key-file", "", "sender private key file")
	fs.StringVar(&senderKeyHex, "sender-key-hex", "", "sender private key hex")
	fs.StringVar(&cfg.ProofInputsPath, "proof-inputs-file", "", "path to bridge-proof-inputs.json")
	fs.StringVar(&depositSealFile, "deposit-seal-file", "", "path to deposit seal hex file")
	fs.StringVar(&withdrawSealFile, "withdraw-seal-file", "", "path to withdraw seal hex file")
	fs.StringVar(&depositSealHex, "deposit-seal-hex", "", "deposit seal hex")
	fs.StringVar(&withdrawSealHex, "withdraw-seal-hex", "", "withdraw seal hex")
	fs.Uint64Var(&cfg.ChainIDOverride, "chain-id", 0, "optional chain-id override (must match proof inputs)")
	fs.StringVar(&withdrawAmountOverride, "withdraw-amount", "", "optional withdraw amount override in zat")
	fs.DurationVar(&cfg.RunTimeout, "run-timeout", defaultRunTimeout, "runtime timeout")
	fs.StringVar(&cfg.OutputPath, "output", "-", "report output path ('-' for stdout)")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if strings.TrimSpace(cfg.RPCURL) == "" {
		return cfg, errors.New("--rpc-url is required")
	}
	if strings.TrimSpace(cfg.ProofInputsPath) == "" {
		return cfg, errors.New("--proof-inputs-file is required")
	}
	if cfg.RunTimeout <= 0 {
		return cfg, errors.New("--run-timeout must be > 0")
	}

	if senderKeyFile != "" && senderKeyHex != "" {
		return cfg, errors.New("use only one of --sender-key-file or --sender-key-hex")
	}
	if senderKeyFile == "" && strings.TrimSpace(senderKeyHex) == "" {
		return cfg, errors.New("--sender-key-file or --sender-key-hex is required")
	}
	if senderKeyFile != "" {
		b, err := os.ReadFile(senderKeyFile)
		if err != nil {
			return cfg, fmt.Errorf("read sender key file: %w", err)
		}
		senderKeyHex = strings.TrimSpace(string(b))
	}
	cfg.SenderKeyHex = strings.TrimSpace(senderKeyHex)

	var err error
	cfg.DepositSeal, err = loadHexInput("deposit seal", depositSealFile, depositSealHex)
	if err != nil {
		return cfg, err
	}
	cfg.WithdrawSeal, err = loadHexInput("withdraw seal", withdrawSealFile, withdrawSealHex)
	if err != nil {
		return cfg, err
	}

	if strings.TrimSpace(withdrawAmountOverride) != "" {
		cfg.WithdrawAmountOverride, err = parseUintAmount("--withdraw-amount", withdrawAmountOverride)
		if err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

func loadHexInput(label, filePath, inline string) ([]byte, error) {
	if filePath != "" && strings.TrimSpace(inline) != "" {
		return nil, fmt.Errorf("use only one of --%s-file or --%s-hex", strings.ReplaceAll(label, " ", "-"), strings.ReplaceAll(label, " ", "-"))
	}
	if filePath == "" && strings.TrimSpace(inline) == "" {
		return nil, fmt.Errorf("%s input is required", label)
	}
	raw := inline
	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read %s file: %w", label, err)
		}
		raw = string(b)
	}
	out, err := parseHexBytesFlag(label, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s must not be empty", label)
	}
	return out, nil
}

func parseHexBytesFlag(flagName, raw string) ([]byte, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, nil
	}
	if !strings.HasPrefix(v, "0x") && !strings.HasPrefix(v, "0X") {
		v = "0x" + v
	}
	out, err := hexutil.Decode(v)
	if err != nil {
		return nil, fmt.Errorf("%s must be valid hex bytes: %w", flagName, err)
	}
	return out, nil
}

func parseUintAmount(flagName, raw string) (*big.Int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, fmt.Errorf("%s must be set", flagName)
	}
	out, ok := new(big.Int).SetString(v, 10)
	if !ok {
		return nil, fmt.Errorf("%s must be a base-10 integer", flagName)
	}
	if out.Sign() <= 0 {
		return nil, fmt.Errorf("%s must be > 0", flagName)
	}
	return out, nil
}

func loadProofBundle(path string) (proofBundle, error) {
	var out proofBundle

	raw, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("read proof inputs file: %w", err)
	}

	var file rawProofInputsFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return out, fmt.Errorf("parse proof inputs file: %w", err)
	}

	if strings.TrimSpace(file.Version) != proofInputsVersionV1 {
		return out, fmt.Errorf("unsupported proof inputs version: %s", strings.TrimSpace(file.Version))
	}
	if file.ChainID == 0 {
		return out, errors.New("proof inputs missing chain_id")
	}
	if !common.IsHexAddress(file.BridgeContract) {
		return out, errors.New("proof inputs bridge_contract must be a valid address")
	}
	bridgeAddr := common.HexToAddress(file.BridgeContract)
	if file.Checkpoint.BaseChainID != file.ChainID {
		return out, errors.New("proof inputs checkpoint.baseChainId mismatch")
	}
	if file.Checkpoint.BridgeContract != bridgeAddr {
		return out, errors.New("proof inputs checkpoint.bridgeContract mismatch")
	}

	if len(file.OperatorSignatures) == 0 {
		return out, errors.New("proof inputs operator_signatures is empty")
	}
	sigs := make([][]byte, 0, len(file.OperatorSignatures))
	for i, rawSig := range file.OperatorSignatures {
		sig, err := parseHexBytesFlag(fmt.Sprintf("operator_signatures[%d]", i), rawSig)
		if err != nil {
			return out, err
		}
		if len(sig) == 0 {
			return out, fmt.Errorf("operator_signatures[%d] must not be empty", i)
		}
		sigs = append(sigs, sig)
	}

	depositJournal, err := parseHexBytesFlag("deposit.proof_input.journal", file.Deposit.ProofInput.Journal)
	if err != nil {
		return out, err
	}
	if len(depositJournal) == 0 {
		return out, errors.New("proof inputs deposit.proof_input.journal must not be empty")
	}

	withdrawJournal, err := parseHexBytesFlag("withdraw.proof_input.journal", file.Withdraw.ProofInput.Journal)
	if err != nil {
		return out, err
	}
	if len(withdrawJournal) == 0 {
		return out, errors.New("proof inputs withdraw.proof_input.journal must not be empty")
	}

	recipientUA, err := parseHexBytesFlag("withdraw.recipient_ua_hex", file.Withdraw.RecipientUAHex)
	if err != nil {
		return out, err
	}
	if len(recipientUA) == 0 {
		return out, errors.New("proof inputs withdraw.recipient_ua_hex must not be empty")
	}

	if len(strings.TrimSpace(file.Withdraw.WithdrawalID)) == 0 {
		return out, errors.New("proof inputs withdraw.withdrawal_id is required")
	}
	withdrawalIDBytes, err := parseHexBytesFlag("withdraw.withdrawal_id", file.Withdraw.WithdrawalID)
	if err != nil {
		return out, err
	}
	if len(withdrawalIDBytes) != 32 {
		return out, errors.New("proof inputs withdraw.withdrawal_id must be 32 bytes")
	}

	var withdrawAmount *big.Int
	if strings.TrimSpace(file.Withdraw.Amount) != "" {
		withdrawAmount, err = parseUintAmount("withdraw.amount", file.Withdraw.Amount)
		if err != nil {
			return out, err
		}
	}

	out = proofBundle{
		ChainID:         file.ChainID,
		BridgeContract:  bridgeAddr,
		Checkpoint:      file.Checkpoint,
		OperatorSigs:    sigs,
		DepositJournal:  depositJournal,
		WithdrawJournal: withdrawJournal,
		RecipientUA:     recipientUA,
		WithdrawalID:    common.BytesToHash(withdrawalIDBytes),
		WithdrawAmount:  withdrawAmount,
	}

	return out, nil
}

func run(ctx context.Context, cfg config) (*report, error) {
	bundle, err := loadProofBundle(cfg.ProofInputsPath)
	if err != nil {
		return nil, err
	}

	if cfg.ChainIDOverride != 0 && cfg.ChainIDOverride != bundle.ChainID {
		return nil, fmt.Errorf(
			"chain-id mismatch: override=%d proof_inputs=%d",
			cfg.ChainIDOverride,
			bundle.ChainID,
		)
	}

	withdrawAmount := bundle.WithdrawAmount
	if withdrawAmount == nil {
		if cfg.WithdrawAmountOverride == nil {
			return nil, errors.New("proof inputs missing withdraw.amount; provide --withdraw-amount for callback")
		}
		withdrawAmount = new(big.Int).Set(cfg.WithdrawAmountOverride)
	}

	senderKey, err := parsePrivateKeyHex(cfg.SenderKeyHex)
	if err != nil {
		return nil, fmt.Errorf("parse sender key: %w", err)
	}

	client, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	rpcChainIDBig, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain id from rpc: %w", err)
	}
	if !rpcChainIDBig.IsUint64() {
		return nil, errors.New("rpc chain id does not fit uint64")
	}
	rpcChainID := rpcChainIDBig.Uint64()

	expectedChainID := bundle.ChainID
	if cfg.ChainIDOverride != 0 {
		expectedChainID = cfg.ChainIDOverride
	}
	if rpcChainID != expectedChainID {
		return nil, fmt.Errorf("rpc chain id mismatch: rpc=%d expected=%d", rpcChainID, expectedChainID)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(senderKey, rpcChainIDBig)
	if err != nil {
		return nil, fmt.Errorf("new transactor: %w", err)
	}
	auth.Context = ctx
	startNonce, err := client.PendingNonceAt(ctx, auth.From)
	if err != nil {
		return nil, fmt.Errorf("pending nonce: %w", err)
	}
	auth.Nonce = new(big.Int).SetUint64(startNonce)

	bridgeRuntimeABI, err := runtimeBridgeABI()
	if err != nil {
		return nil, err
	}
	erc20ABI, err := runtimeERC20ABI()
	if err != nil {
		return nil, err
	}

	bridge := bind.NewBoundContract(bundle.BridgeContract, bridgeRuntimeABI, client, client, client)

	nonceBefore, err := callUint64(ctx, bridge, "withdrawNonce")
	if err != nil {
		return nil, fmt.Errorf("withdrawNonce: %w", err)
	}
	predictedWithdrawalID, err := computePredictedWithdrawalID(
		bundle.ChainID,
		bundle.BridgeContract,
		nonceBefore+1,
		auth.From,
		withdrawAmount,
		bundle.RecipientUA,
	)
	if err != nil {
		return nil, fmt.Errorf("compute predicted withdrawal id: %w", err)
	}
	if predictedWithdrawalID != bundle.WithdrawalID {
		return nil, fmt.Errorf(
			"withdrawal id mismatch before callback: predicted=%s proof_inputs=%s",
			predictedWithdrawalID.Hex(),
			bundle.WithdrawalID.Hex(),
		)
	}

	mintCalldata, err := bridgeabi.PackMintBatchCalldata(bundle.Checkpoint, bundle.OperatorSigs, cfg.DepositSeal, bundle.DepositJournal)
	if err != nil {
		return nil, fmt.Errorf("pack mintBatch calldata: %w", err)
	}
	mintTx, _, err := rawTransactAndWaitWithReceipt(ctx, client, auth, bridge, "mintBatch", mintCalldata)
	if err != nil {
		return nil, fmt.Errorf("mintBatch: %w", err)
	}

	wjunoAddr, err := callAddress(ctx, bridge, "wjuno")
	if err != nil {
		return nil, fmt.Errorf("bridge.wjuno: %w", err)
	}
	wjuno := bind.NewBoundContract(wjunoAddr, erc20ABI, client, client, client)

	approveTx, _, err := transactAndWaitWithReceipt(ctx, client, auth, wjuno, "approve", bundle.BridgeContract, withdrawAmount)
	if err != nil {
		return nil, fmt.Errorf("approve withdraw: %w", err)
	}

	requestTx, _, err := transactAndWaitWithReceipt(ctx, client, auth, bridge, "requestWithdraw", withdrawAmount, bundle.RecipientUA)
	if err != nil {
		return nil, fmt.Errorf("requestWithdraw: %w", err)
	}

	finalizeCalldata, err := bridgeabi.PackFinalizeWithdrawBatchCalldata(bundle.Checkpoint, bundle.OperatorSigs, cfg.WithdrawSeal, bundle.WithdrawJournal)
	if err != nil {
		return nil, fmt.Errorf("pack finalizeWithdrawBatch calldata: %w", err)
	}
	finalizeTx, _, err := rawTransactAndWaitWithReceipt(ctx, client, auth, bridge, "finalizeWithdrawBatch", finalizeCalldata)
	if err != nil {
		return nil, fmt.Errorf("finalizeWithdrawBatch: %w", err)
	}

	var rep report
	rep.GeneratedAtUTC = time.Now().UTC().Format(time.RFC3339)
	rep.RPCURL = cfg.RPCURL
	rep.ChainID = expectedChainID
	rep.SenderAddress = auth.From.Hex()
	rep.Contracts.Bridge = bundle.BridgeContract.Hex()
	rep.Contracts.WJuno = wjunoAddr.Hex()
	rep.ProofInputs.Path = cfg.ProofInputsPath
	rep.ProofInputs.Version = proofInputsVersionV1
	rep.ProofInputs.CheckpointHeight = bundle.Checkpoint.Height
	rep.ProofInputs.CheckpointHash = bundle.Checkpoint.BlockHash.Hex()
	rep.ProofInputs.FinalOrchardRoot = bundle.Checkpoint.FinalOrchardRoot.Hex()
	rep.ProofInputs.WithdrawalID = bundle.WithdrawalID.Hex()
	rep.ProofInputs.WithdrawAmountZat = withdrawAmount.String()
	rep.Seals.DepositBytes = len(cfg.DepositSeal)
	rep.Seals.WithdrawBytes = len(cfg.WithdrawSeal)
	rep.Transactions.MintBatch = mintTx.Hex()
	rep.Transactions.ApproveWithdraw = approveTx.Hex()
	rep.Transactions.RequestWithdraw = requestTx.Hex()
	rep.Transactions.FinalizeWithdraw = finalizeTx.Hex()

	return &rep, nil
}

func parsePrivateKeyHex(raw string) (*ecdsa.PrivateKey, error) {
	hex := strings.TrimSpace(strings.TrimPrefix(raw, "0x"))
	if hex == "" {
		return nil, errors.New("empty private key")
	}
	return crypto.HexToECDSA(hex)
}

type txBackend interface {
	bind.DeployBackend
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

func transactAndWaitWithReceipt(ctx context.Context, backend txBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, args ...any) (common.Hash, *types.Receipt, error) {
	for attempt := 1; attempt <= 4; attempt++ {
		txAuth := transactAuthWithDefaults(auth, defaultGasLimit)
		tx, err := c.Transact(txAuth, method, args...)
		if err != nil {
			if attempt < 4 && isRetriableNonceError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Hash{}, nil, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Hash{}, nil, err
		}
		incrementAuthNonce(auth)
		rcpt, err := waitMined(ctx, backend, tx)
		if err != nil {
			return common.Hash{}, nil, err
		}
		if rcpt.Status != 1 {
			return common.Hash{}, nil, fmt.Errorf("%s reverted: %s", method, tx.Hash().Hex())
		}
		return tx.Hash(), rcpt, nil
	}
	return common.Hash{}, nil, fmt.Errorf("%s retries exhausted", method)
}

func rawTransactAndWaitWithReceipt(ctx context.Context, backend txBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, calldata []byte) (common.Hash, *types.Receipt, error) {
	for attempt := 1; attempt <= 4; attempt++ {
		txAuth := transactAuthWithDefaults(auth, defaultGasLimit)
		tx, err := c.RawTransact(txAuth, calldata)
		if err != nil {
			if attempt < 4 && isRetriableNonceError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Hash{}, nil, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Hash{}, nil, err
		}
		incrementAuthNonce(auth)
		rcpt, err := waitMined(ctx, backend, tx)
		if err != nil {
			return common.Hash{}, nil, err
		}
		if rcpt.Status != 1 {
			return common.Hash{}, nil, fmt.Errorf("%s reverted: %s", method, tx.Hash().Hex())
		}
		return tx.Hash(), rcpt, nil
	}
	return common.Hash{}, nil, fmt.Errorf("%s retries exhausted", method)
}

func transactAuthWithDefaults(auth *bind.TransactOpts, defaultGasLimit uint64) *bind.TransactOpts {
	if auth == nil {
		return nil
	}
	cloned := *auth
	if cloned.GasLimit == 0 {
		cloned.GasLimit = defaultGasLimit
	}
	return &cloned
}

func isRetriableNonceError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "nonce too low") || strings.Contains(msg, "replacement transaction underpriced")
}

func refreshAuthNonce(ctx context.Context, backend txBackend, auth *bind.TransactOpts) error {
	if auth == nil {
		return errors.New("nil auth")
	}
	nonce, err := backend.PendingNonceAt(ctx, auth.From)
	if err != nil {
		return err
	}
	auth.Nonce = new(big.Int).SetUint64(nonce)
	return nil
}

func incrementAuthNonce(auth *bind.TransactOpts) {
	if auth == nil || auth.Nonce == nil {
		return
	}
	auth.Nonce = new(big.Int).Add(auth.Nonce, big.NewInt(1))
}

func waitMined(ctx context.Context, backend bind.DeployBackend, tx *types.Transaction) (*types.Receipt, error) {
	return bind.WaitMined(ctx, backend, tx)
}

func callUint64(ctx context.Context, c *bind.BoundContract, method string, args ...any) (uint64, error) {
	var res []any
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, method, args...); err != nil {
		return 0, err
	}
	if len(res) != 1 {
		return 0, fmt.Errorf("unexpected %s result count: %d", method, len(res))
	}
	switch v := res[0].(type) {
	case *big.Int:
		if v == nil {
			return 0, nil
		}
		return v.Uint64(), nil
	case uint64:
		return v, nil
	case uint32:
		return uint64(v), nil
	default:
		return 0, fmt.Errorf("unexpected %s type: %T", method, res[0])
	}
}

func callAddress(ctx context.Context, c *bind.BoundContract, method string, args ...any) (common.Address, error) {
	var res []any
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, method, args...); err != nil {
		return common.Address{}, err
	}
	if len(res) != 1 {
		return common.Address{}, fmt.Errorf("unexpected %s result count: %d", method, len(res))
	}
	switch v := res[0].(type) {
	case common.Address:
		return v, nil
	case *common.Address:
		if v == nil {
			return common.Address{}, errors.New("nil address result")
		}
		return *v, nil
	default:
		return common.Address{}, fmt.Errorf("unexpected %s type: %T", method, res[0])
	}
}

func runtimeBridgeABI() (abi.ABI, error) {
	const bridgeRuntimeABIJSON = `[
  {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"bytes","name":"junoRecipientUA","type":"bytes"}],"name":"requestWithdraw","outputs":[{"internalType":"bytes32","name":"withdrawalId","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[],"name":"withdrawNonce","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"wjuno","outputs":[{"internalType":"contract WJuno","name":"","type":"address"}],"stateMutability":"view","type":"function"}
]`
	return abi.JSON(strings.NewReader(bridgeRuntimeABIJSON))
}

func runtimeERC20ABI() (abi.ABI, error) {
	const erc20RuntimeABIJSON = `[
  {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
]`
	return abi.JSON(strings.NewReader(erc20RuntimeABIJSON))
}

func computePredictedWithdrawalID(chainID uint64, bridge common.Address, nonce uint64, requester common.Address, amount *big.Int, recipientUA []byte) (common.Hash, error) {
	if amount == nil {
		return common.Hash{}, errors.New("nil amount")
	}
	if nonce == 0 {
		return common.Hash{}, errors.New("nonce must be > 0")
	}
	if len(recipientUA) == 0 {
		return common.Hash{}, errors.New("recipient UA must not be empty")
	}

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	uintType, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return common.Hash{}, err
	}

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: uintType},
		{Type: addressType},
		{Type: uintType},
		{Type: addressType},
		{Type: uintType},
		{Type: bytes32Type},
	}

	var versionTag [32]byte
	copy(versionTag[:], []byte("WJUNO_WITHDRAW_V1"))

	payload, err := args.Pack(
		versionTag,
		new(big.Int).SetUint64(chainID),
		bridge,
		new(big.Int).SetUint64(nonce),
		requester,
		new(big.Int).Set(amount),
		crypto.Keccak256Hash(recipientUA),
	)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(payload), nil
}
