package main

import (
	"bytes"
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
	"sort"
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

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, v)
	return nil
}

type config struct {
	RPCURL           string
	ChainID          uint64
	DeployerKeyHex   string
	OperatorKeyFiles []string
	Threshold        int
	ContractsOut     string
	DepositAmount    uint64
	WithdrawAmount   uint64
	Recipient        common.Address
	RecipientSet     bool
	OutputPath       string
}

type report struct {
	GeneratedAtUTC string `json:"generated_at_utc"`
	RPCURL         string `json:"rpc_url"`
	ChainID        uint64 `json:"chain_id"`

	OwnerAddress string `json:"owner_address"`
	Recipient    string `json:"recipient"`

	Contracts struct {
		Verifier         string `json:"verifier"`
		WJuno            string `json:"wjuno"`
		OperatorRegistry string `json:"operator_registry"`
		FeeDistributor   string `json:"fee_distributor"`
		Bridge           string `json:"bridge"`
	} `json:"contracts"`

	Operators []string `json:"operators"`
	Threshold int      `json:"threshold"`

	Checkpoint struct {
		Height           uint64 `json:"height"`
		BlockHash        string `json:"block_hash"`
		FinalOrchardRoot string `json:"final_orchard_root"`
	} `json:"checkpoint"`

	Transactions struct {
		SetFeeDistributor string `json:"set_fee_distributor"`
		SetThreshold      string `json:"set_threshold"`
		SetBridgeWJuno    string `json:"set_bridge_wjuno"`
		SetBridgeFees     string `json:"set_bridge_fees"`
		MintBatch         string `json:"mint_batch"`
		ApproveWithdraw   string `json:"approve_withdraw"`
		RequestWithdraw   string `json:"request_withdraw"`
		FinalizeWithdraw  string `json:"finalize_withdraw"`
	} `json:"transactions"`

	Withdraw struct {
		WithdrawalID string `json:"withdrawal_id"`
		FeeBps       uint64 `json:"fee_bps"`
	} `json:"withdraw"`

	Balances struct {
		RecipientWJuno string `json:"recipient_wjuno"`
		FeeDistributor string `json:"fee_distributor"`
	} `json:"balances"`
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

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
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
	var deployerKeyFile string
	var operatorKeyFiles stringListFlag
	var recipientHex string

	fs := flag.NewFlagSet("bridge-e2e", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.RPCURL, "rpc-url", "", "Base testnet RPC URL")
	fs.Uint64Var(&cfg.ChainID, "chain-id", 0, "Base chain ID")
	fs.StringVar(&deployerKeyFile, "deployer-key-file", "", "file containing deployer private key hex")
	fs.StringVar(&cfg.DeployerKeyHex, "deployer-key-hex", "", "deployer private key hex")
	fs.Var(&operatorKeyFiles, "operator-key-file", "operator private key file path (repeat)")
	fs.IntVar(&cfg.Threshold, "threshold", 3, "operator quorum threshold")
	fs.StringVar(&cfg.ContractsOut, "contracts-out", "contracts/out", "path to foundry build output directory")
	fs.Uint64Var(&cfg.DepositAmount, "deposit-amount", 100_000, "mintBatch item amount (wJUNO base units)")
	fs.Uint64Var(&cfg.WithdrawAmount, "withdraw-amount", 10_000, "request/finalize amount (wJUNO base units)")
	fs.StringVar(&recipientHex, "recipient", "", "optional recipient address for mint (defaults to deployer)")
	fs.StringVar(&cfg.OutputPath, "output", "-", "output report path or '-' for stdout")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if cfg.RPCURL == "" {
		return cfg, errors.New("--rpc-url is required")
	}
	if cfg.ChainID == 0 {
		return cfg, errors.New("--chain-id is required")
	}
	if cfg.Threshold < 2 {
		return cfg, errors.New("--threshold must be >= 2")
	}
	if cfg.DepositAmount == 0 {
		return cfg, errors.New("--deposit-amount must be > 0")
	}
	if cfg.WithdrawAmount == 0 {
		return cfg, errors.New("--withdraw-amount must be > 0")
	}
	if cfg.WithdrawAmount > cfg.DepositAmount {
		return cfg, errors.New("--withdraw-amount must be <= --deposit-amount")
	}

	if deployerKeyFile != "" && cfg.DeployerKeyHex != "" {
		return cfg, errors.New("use only one of --deployer-key-file or --deployer-key-hex")
	}
	if deployerKeyFile != "" {
		keyBytes, err := os.ReadFile(deployerKeyFile)
		if err != nil {
			return cfg, fmt.Errorf("read deployer key file: %w", err)
		}
		cfg.DeployerKeyHex = strings.TrimSpace(string(keyBytes))
	}
	if cfg.DeployerKeyHex == "" {
		return cfg, errors.New("deployer key is required (--deployer-key-file or --deployer-key-hex)")
	}

	cfg.OperatorKeyFiles = append(cfg.OperatorKeyFiles, operatorKeyFiles...)
	if len(cfg.OperatorKeyFiles) < cfg.Threshold {
		return cfg, fmt.Errorf("need at least %d operator keys, got %d", cfg.Threshold, len(cfg.OperatorKeyFiles))
	}

	if recipientHex != "" {
		if !common.IsHexAddress(recipientHex) {
			return cfg, errors.New("--recipient must be a valid hex address")
		}
		cfg.Recipient = common.HexToAddress(recipientHex)
		cfg.RecipientSet = true
	}

	return cfg, nil
}

func run(ctx context.Context, cfg config) (*report, error) {
	client, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	chainID := new(big.Int).SetUint64(cfg.ChainID)

	deployerKey, err := parsePrivateKeyHex(cfg.DeployerKeyHex)
	if err != nil {
		return nil, fmt.Errorf("parse deployer key: %w", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(deployerKey, chainID)
	if err != nil {
		return nil, fmt.Errorf("new transactor: %w", err)
	}
	auth.Context = ctx
	owner := auth.From
	startNonce, err := client.PendingNonceAt(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("pending nonce for owner: %w", err)
	}
	auth.Nonce = new(big.Int).SetUint64(startNonce)

	operatorKeys := make([]*ecdsa.PrivateKey, 0, len(cfg.OperatorKeyFiles))
	for _, path := range cfg.OperatorKeyFiles {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read operator key %s: %w", path, err)
		}
		key, err := parsePrivateKeyHex(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("parse operator key %s: %w", path, err)
		}
		operatorKeys = append(operatorKeys, key)
	}

	recipient := owner
	if cfg.RecipientSet {
		recipient = cfg.Recipient
	}

	wjunoABI, wjunoBin, err := loadFoundryArtifact(filepath.Join(cfg.ContractsOut, "WJuno.sol", "WJuno.json"))
	if err != nil {
		return nil, err
	}
	regABI, regBin, err := loadFoundryArtifact(filepath.Join(cfg.ContractsOut, "OperatorRegistry.sol", "OperatorRegistry.json"))
	if err != nil {
		return nil, err
	}
	fdABI, fdBin, err := loadFoundryArtifact(filepath.Join(cfg.ContractsOut, "FeeDistributor.sol", "FeeDistributor.json"))
	if err != nil {
		return nil, err
	}
	bridgeABI, bridgeBin, err := loadFoundryArtifact(filepath.Join(cfg.ContractsOut, "Bridge.sol", "Bridge.json"))
	if err != nil {
		return nil, err
	}

	verifierAddr, _, err := deployNoopVerifier(ctx, client, auth)
	if err != nil {
		return nil, fmt.Errorf("deploy verifier: %w", err)
	}

	wjunoAddr, _, err := deployContract(ctx, client, auth, wjunoABI, wjunoBin, owner)
	if err != nil {
		return nil, fmt.Errorf("deploy wjuno: %w", err)
	}
	regAddr, _, err := deployContract(ctx, client, auth, regABI, regBin, owner)
	if err != nil {
		return nil, fmt.Errorf("deploy operator registry: %w", err)
	}
	fdAddr, _, err := deployContract(ctx, client, auth, fdABI, fdBin, owner, wjunoAddr, regAddr)
	if err != nil {
		return nil, fmt.Errorf("deploy fee distributor: %w", err)
	}

	depositImageID := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01")
	withdrawImageID := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02")
	const feeBps uint64 = 50
	const tipBps uint64 = 1000
	const refundWindowSeconds uint64 = 24 * 60 * 60
	const maxExtendSeconds uint64 = 12 * 60 * 60

	bridgeAddr, _, err := deployContract(
		ctx, client, auth, bridgeABI, bridgeBin,
		owner,
		wjunoAddr,
		fdAddr,
		regAddr,
		verifierAddr,
		depositImageID,
		withdrawImageID,
		new(big.Int).SetUint64(feeBps),
		new(big.Int).SetUint64(tipBps),
		refundWindowSeconds,
		maxExtendSeconds,
	)
	if err != nil {
		return nil, fmt.Errorf("deploy bridge: %w", err)
	}

	reg := bind.NewBoundContract(regAddr, regABI, client, client, client)
	fd := bind.NewBoundContract(fdAddr, fdABI, client, client, client)
	wjuno := bind.NewBoundContract(wjunoAddr, wjunoABI, client, client, client)
	bridge := bind.NewBoundContract(bridgeAddr, bridgeABI, client, client, client)

	setFeeDistributorTx, err := transactAndWait(ctx, client, auth, reg, "setFeeDistributor", fdAddr)
	if err != nil {
		return nil, fmt.Errorf("setFeeDistributor: %w", err)
	}

	operatorAddrs := make([]common.Address, 0, len(operatorKeys))
	for _, k := range operatorKeys {
		op := crypto.PubkeyToAddress(k.PublicKey)
		operatorAddrs = append(operatorAddrs, op)
		if _, err := transactAndWait(ctx, client, auth, reg, "setOperator", op, op, big.NewInt(1), true); err != nil {
			return nil, fmt.Errorf("setOperator(%s): %w", op.Hex(), err)
		}
	}

	setThresholdTx, err := transactAndWait(ctx, client, auth, reg, "setThreshold", big.NewInt(int64(cfg.Threshold)))
	if err != nil {
		return nil, fmt.Errorf("setThreshold: %w", err)
	}

	setBridgeWJunoTx, err := transactAndWait(ctx, client, auth, wjuno, "setBridge", bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("wjuno.setBridge: %w", err)
	}
	setBridgeFeesTx, err := transactAndWait(ctx, client, auth, fd, "setBridge", bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("feeDistributor.setBridge: %w", err)
	}

	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("latest header: %w", err)
	}
	cp := checkpoint.Checkpoint{
		Height:           header.Number.Uint64(),
		BlockHash:        header.Hash(),
		FinalOrchardRoot: crypto.Keccak256Hash([]byte("juno-e2e"), header.Hash().Bytes()),
		BaseChainID:      cfg.ChainID,
		BridgeContract:   bridgeAddr,
	}
	digest := checkpoint.Digest(cp)
	cpSigs, err := signDigestSorted(digest, operatorKeys[:cfg.Threshold])
	if err != nil {
		return nil, fmt.Errorf("sign checkpoint digest: %w", err)
	}

	type checkpointABI struct {
		Height           uint64
		BlockHash        common.Hash
		FinalOrchardRoot common.Hash
		BaseChainId      *big.Int
		BridgeContract   common.Address
	}
	cpABI := checkpointABI{
		Height:           cp.Height,
		BlockHash:        cp.BlockHash,
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
	}

	depositID := crypto.Keccak256Hash([]byte("bridge-e2e-deposit-1"))
	depositJournal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []bridgeabi.MintItem{
			{
				DepositId: depositID,
				Recipient: recipient,
				Amount:    new(big.Int).SetUint64(cfg.DepositAmount),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode deposit journal: %w", err)
	}

	mintBatchTx, mintBatchRcpt, err := transactAndWaitWithReceipt(ctx, client, auth, bridge, "mintBatch", cpABI, cpSigs, []byte{0x99}, depositJournal)
	if err != nil {
		return nil, fmt.Errorf("mintBatch: %w", err)
	}

	used, err := waitDepositUsedAtBlock(ctx, bridge, depositID, mintBatchRcpt.BlockNumber, 20, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if !used {
		return nil, errors.New("depositUsed=false after mintBatch")
	}

	withdrawAmount := new(big.Int).SetUint64(cfg.WithdrawAmount)
	approveWithdrawTx, err := transactAndWait(ctx, client, auth, wjuno, "approve", bridgeAddr, withdrawAmount)
	if err != nil {
		return nil, fmt.Errorf("approve withdraw: %w", err)
	}

	recipientUA := []byte{0x01, 0x02, 0x03}
	requestWithdrawTx, requestRcpt, err := transactAndWaitWithReceipt(ctx, client, auth, bridge, "requestWithdraw", withdrawAmount, recipientUA)
	if err != nil {
		return nil, fmt.Errorf("requestWithdraw: %w", err)
	}
	withdrawalID, feeBpsAtReq, err := parseWithdrawRequested(bridgeABI, requestRcpt)
	if err != nil {
		return nil, fmt.Errorf("parse WithdrawRequested: %w", err)
	}

	fee := new(big.Int).Mul(withdrawAmount, new(big.Int).SetUint64(feeBpsAtReq))
	fee.Div(fee, big.NewInt(10_000))
	net := new(big.Int).Sub(withdrawAmount, fee)

	withdrawJournal, err := bridgeabi.EncodeWithdrawJournal(bridgeabi.WithdrawJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []bridgeabi.FinalizeItem{
			{
				WithdrawalId:    withdrawalID,
				RecipientUAHash: crypto.Keccak256Hash(recipientUA),
				NetAmount:       net,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode withdraw journal: %w", err)
	}

	finalizeWithdrawTx, err := transactAndWait(ctx, client, auth, bridge, "finalizeWithdrawBatch", cpABI, cpSigs, []byte{0x99}, withdrawJournal)
	if err != nil {
		return nil, fmt.Errorf("finalizeWithdrawBatch: %w", err)
	}

	recipientBal, err := callBalanceOf(ctx, wjuno, recipient)
	if err != nil {
		return nil, err
	}
	fdBal, err := callBalanceOf(ctx, wjuno, fdAddr)
	if err != nil {
		return nil, err
	}

	var rep report
	rep.GeneratedAtUTC = time.Now().UTC().Format(time.RFC3339)
	rep.RPCURL = cfg.RPCURL
	rep.ChainID = cfg.ChainID
	rep.OwnerAddress = owner.Hex()
	rep.Recipient = recipient.Hex()

	rep.Contracts.Verifier = verifierAddr.Hex()
	rep.Contracts.WJuno = wjunoAddr.Hex()
	rep.Contracts.OperatorRegistry = regAddr.Hex()
	rep.Contracts.FeeDistributor = fdAddr.Hex()
	rep.Contracts.Bridge = bridgeAddr.Hex()

	rep.Operators = make([]string, 0, len(operatorAddrs))
	for _, op := range operatorAddrs {
		rep.Operators = append(rep.Operators, op.Hex())
	}
	rep.Threshold = cfg.Threshold
	rep.Checkpoint.Height = cp.Height
	rep.Checkpoint.BlockHash = cp.BlockHash.Hex()
	rep.Checkpoint.FinalOrchardRoot = cp.FinalOrchardRoot.Hex()

	rep.Transactions.SetFeeDistributor = setFeeDistributorTx.Hex()
	rep.Transactions.SetThreshold = setThresholdTx.Hex()
	rep.Transactions.SetBridgeWJuno = setBridgeWJunoTx.Hex()
	rep.Transactions.SetBridgeFees = setBridgeFeesTx.Hex()
	rep.Transactions.MintBatch = mintBatchTx.Hex()
	rep.Transactions.ApproveWithdraw = approveWithdrawTx.Hex()
	rep.Transactions.RequestWithdraw = requestWithdrawTx.Hex()
	rep.Transactions.FinalizeWithdraw = finalizeWithdrawTx.Hex()

	rep.Withdraw.WithdrawalID = withdrawalID.Hex()
	rep.Withdraw.FeeBps = feeBpsAtReq

	rep.Balances.RecipientWJuno = recipientBal.String()
	rep.Balances.FeeDistributor = fdBal.String()

	return &rep, nil
}

func parsePrivateKeyHex(raw string) (*ecdsa.PrivateKey, error) {
	hex := strings.TrimSpace(strings.TrimPrefix(raw, "0x"))
	if hex == "" {
		return nil, errors.New("empty private key")
	}
	return crypto.HexToECDSA(hex)
}

type foundryArtifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

func loadFoundryArtifact(path string) (abi.ABI, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return abi.ABI{}, nil, fmt.Errorf("read artifact %s: %w", path, err)
	}
	var a foundryArtifact
	if err := json.Unmarshal(b, &a); err != nil {
		return abi.ABI{}, nil, fmt.Errorf("unmarshal artifact %s: %w", path, err)
	}
	parsed, err := abi.JSON(bytes.NewReader(a.ABI))
	if err != nil {
		return abi.ABI{}, nil, fmt.Errorf("parse abi %s: %w", path, err)
	}
	code, err := hexutil.Decode(a.Bytecode.Object)
	if err != nil {
		return abi.ABI{}, nil, fmt.Errorf("decode bytecode %s: %w", path, err)
	}
	return parsed, code, nil
}

type evmBackend interface {
	bind.ContractBackend
	bind.DeployBackend
}

type txBackend interface {
	bind.DeployBackend
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

func deployContract(ctx context.Context, backend evmBackend, auth *bind.TransactOpts, a abi.ABI, bin []byte, args ...any) (common.Address, common.Hash, error) {
	for attempt := 1; attempt <= 4; attempt++ {
		txAuth := transactAuthWithDefaults(auth, 0)
		addr, tx, _, err := bind.DeployContract(txAuth, a, bin, backend, args...)
		if err != nil {
			if attempt < 4 && isRetriableNonceError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Address{}, common.Hash{}, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Address{}, common.Hash{}, err
		}
		incrementAuthNonce(auth)
		rcpt, err := waitMined(ctx, backend, tx)
		if err != nil {
			return common.Address{}, common.Hash{}, err
		}
		if rcpt.Status != 1 {
			return common.Address{}, common.Hash{}, fmt.Errorf("deployment reverted: %s", tx.Hash().Hex())
		}
		return addr, tx.Hash(), nil
	}
	return common.Address{}, common.Hash{}, errors.New("deploy contract retries exhausted")
}

func deployNoopVerifier(ctx context.Context, backend evmBackend, auth *bind.TransactOpts) (common.Address, common.Hash, error) {
	emptyABI, err := abi.JSON(strings.NewReader("[]"))
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}
	initCode, err := hexutil.Decode("0x6001600c60003960016000f300")
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}
	return deployContract(ctx, backend, auth, emptyABI, initCode)
}

func transactAndWait(ctx context.Context, backend txBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, args ...any) (common.Hash, error) {
	txHash, _, err := transactAndWaitWithReceipt(ctx, backend, auth, c, method, args...)
	return txHash, err
}

func transactAndWaitWithReceipt(ctx context.Context, backend txBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, args ...any) (common.Hash, *types.Receipt, error) {
	for attempt := 1; attempt <= 4; attempt++ {
		txAuth := transactAuthWithDefaults(auth, 1_000_000)
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
	if auth == nil {
		return
	}
	if auth.Nonce == nil {
		return
	}
	auth.Nonce = new(big.Int).Add(auth.Nonce, big.NewInt(1))
}

func waitMined(ctx context.Context, backend bind.DeployBackend, tx *types.Transaction) (*types.Receipt, error) {
	return bind.WaitMined(ctx, backend, tx)
}

func signDigestSorted(digest common.Hash, keys []*ecdsa.PrivateKey) ([][]byte, error) {
	type pair struct {
		addr common.Address
		sig  []byte
	}
	pairs := make([]pair, 0, len(keys))
	for _, k := range keys {
		sig, err := checkpoint.SignDigest(k, digest)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair{addr: crypto.PubkeyToAddress(k.PublicKey), sig: sig})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].addr.Bytes(), pairs[j].addr.Bytes()) < 0
	})
	out := make([][]byte, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.sig)
	}
	return out, nil
}

type depositUsedCaller interface {
	Call(opts *bind.CallOpts, results *[]any, method string, params ...any) error
}

func waitDepositUsedAtBlock(ctx context.Context, bridge depositUsedCaller, depositID common.Hash, blockNumber *big.Int, attempts int, interval time.Duration) (bool, error) {
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		used, err := callDepositUsed(ctx, bridge, depositID, blockNumber)
		if err == nil {
			if used {
				return true, nil
			}
			lastErr = nil
		} else {
			lastErr = err
		}

		if i == attempts-1 || interval <= 0 {
			continue
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}

	if lastErr != nil {
		return false, fmt.Errorf("depositUsed check failed after %d attempts: %w", attempts, lastErr)
	}
	return false, nil
}

func callDepositUsed(ctx context.Context, bridge depositUsedCaller, depositID common.Hash, blockNumber *big.Int) (bool, error) {
	var res []any
	opts := &bind.CallOpts{Context: ctx}
	if blockNumber != nil {
		opts.BlockNumber = new(big.Int).Set(blockNumber)
	}
	if err := bridge.Call(opts, &res, "depositUsed", depositID); err != nil {
		return false, err
	}
	if len(res) != 1 {
		return false, fmt.Errorf("unexpected depositUsed result count: %d", len(res))
	}
	used, ok := res[0].(bool)
	if !ok {
		return false, fmt.Errorf("unexpected depositUsed type: %T", res[0])
	}
	return used, nil
}

func callBalanceOf(ctx context.Context, token *bind.BoundContract, who common.Address) (*big.Int, error) {
	var res []any
	if err := token.Call(&bind.CallOpts{Context: ctx}, &res, "balanceOf", who); err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, fmt.Errorf("unexpected balanceOf result count: %d", len(res))
	}
	out, ok := res[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("unexpected balanceOf type: %T", res[0])
	}
	if out == nil {
		return big.NewInt(0), nil
	}
	return out, nil
}

func parseWithdrawRequested(bridgeABI abi.ABI, rcpt *types.Receipt) (common.Hash, uint64, error) {
	type withdrawRequestedEvent struct {
		Amount      *big.Int
		RecipientUA []byte
		Expiry      uint64
		FeeBps      *big.Int
	}

	ev, ok := bridgeABI.Events["WithdrawRequested"]
	if !ok {
		return common.Hash{}, 0, errors.New("missing WithdrawRequested event in abi")
	}
	for _, lg := range rcpt.Logs {
		if len(lg.Topics) == 0 || lg.Topics[0] != ev.ID {
			continue
		}
		var out withdrawRequestedEvent
		if err := bridgeABI.UnpackIntoInterface(&out, "WithdrawRequested", lg.Data); err != nil {
			return common.Hash{}, 0, err
		}
		if len(lg.Topics) < 2 {
			return common.Hash{}, 0, errors.New("WithdrawRequested missing indexed withdrawalId")
		}
		fee := uint64(0)
		if out.FeeBps != nil {
			fee = out.FeeBps.Uint64()
		}
		return lg.Topics[1], fee, nil
	}
	return common.Hash{}, 0, errors.New("WithdrawRequested event not found")
}
