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
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	"github.com/juno-intents/intents-juno/internal/proverinput"
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
	VerifierAddress  common.Address
	VerifierSet      bool
	DepositImageID   common.Hash
	WithdrawImageID  common.Hash
	DepositSeal      []byte
	WithdrawSeal     []byte
	PrepareOnly      bool
	ProofInputsOut   string
	OutputPath       string
	RunTimeout       time.Duration
	Boundless        boundlessConfig
}

type boundlessConfig struct {
	Auto bool

	Bin                string
	RPCURL             string
	RequestorKeyHex    string
	DepositProgramURL  string
	WithdrawProgramURL string

	MinPriceWei  *big.Int
	MaxPriceWei  *big.Int
	LockStakeWei *big.Int

	BiddingDelaySeconds uint64
	RampUpPeriodSeconds uint64
	LockTimeoutSeconds  uint64
	TimeoutSeconds      uint64
}

type boundlessWaitResult struct {
	RequestIDHex string
	JournalHex   string
	SealHex      string
}

const (
	defaultDepositImageIDHex  = "0x000000000000000000000000000000000000000000000000000000000000aa01"
	defaultWithdrawImageIDHex = "0x000000000000000000000000000000000000000000000000000000000000aa02"

	defaultBoundlessMinPriceWei  = "100000000000000"
	defaultBoundlessMaxPriceWei  = "250000000000000"
	defaultBoundlessLockStakeWei = "20000000000000000000"
)

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
		PredictedID  string `json:"predicted_withdrawal_id"`
		FeeBps       uint64 `json:"fee_bps"`
	} `json:"withdraw"`

	Balances struct {
		RecipientWJuno string `json:"recipient_wjuno"`
		FeeDistributor string `json:"fee_distributor"`
	} `json:"balances"`

	Proof struct {
		PrepareOnly       bool   `json:"prepare_only"`
		ProofInputsPath   string `json:"proof_inputs_path,omitempty"`
		DepositImageID    string `json:"deposit_image_id"`
		WithdrawImageID   string `json:"withdraw_image_id"`
		DepositSealBytes  int    `json:"deposit_seal_bytes"`
		WithdrawSealBytes int    `json:"withdraw_seal_bytes"`

		Boundless struct {
			Enabled           bool   `json:"enabled"`
			RPCURL            string `json:"rpc_url,omitempty"`
			DepositRequestID  string `json:"deposit_request_id,omitempty"`
			WithdrawRequestID string `json:"withdraw_request_id,omitempty"`
			MinPriceWei       string `json:"min_price_wei,omitempty"`
			MaxPriceWei       string `json:"max_price_wei,omitempty"`
			LockStakeWei      string `json:"lock_stake_wei,omitempty"`
			BiddingDelaySec   uint64 `json:"bidding_delay_seconds,omitempty"`
			RampUpPeriodSec   uint64 `json:"ramp_up_period_seconds,omitempty"`
			LockTimeoutSec    uint64 `json:"lock_timeout_seconds,omitempty"`
			TimeoutSec        uint64 `json:"timeout_seconds,omitempty"`
		} `json:"boundless,omitempty"`
	} `json:"proof"`
}

type proofInputsFile struct {
	Version        string `json:"version"`
	GeneratedAtUTC string `json:"generated_at_utc"`
	ChainID        uint64 `json:"chain_id"`
	BridgeContract string `json:"bridge_contract"`

	Checkpoint checkpoint.Checkpoint `json:"checkpoint"`

	OperatorSignatures []string `json:"operator_signatures"`

	Deposit struct {
		ProofInput struct {
			Pipeline     string `json:"pipeline"`
			ImageID      string `json:"image_id"`
			Journal      string `json:"journal"`
			PrivateInput string `json:"private_input"`
		} `json:"proof_input"`
		DepositID string `json:"deposit_id"`
		Recipient string `json:"recipient"`
		Amount    string `json:"amount"`
	} `json:"deposit"`

	Withdraw struct {
		ProofInput struct {
			Pipeline     string `json:"pipeline"`
			ImageID      string `json:"image_id"`
			Journal      string `json:"journal"`
			PrivateInput string `json:"private_input"`
		} `json:"proof_input"`
		RecipientUAHex string `json:"recipient_ua_hex"`
		WithdrawalID   string `json:"withdrawal_id"`
		NetAmount      string `json:"net_amount"`
	} `json:"withdraw"`
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
	var deployerKeyFile string
	var operatorKeyFiles stringListFlag
	var recipientHex string
	var verifierAddressHex string
	var depositImageIDHex string
	var withdrawImageIDHex string
	var depositSealHex string
	var withdrawSealHex string
	var boundlessRequestorKeyFile string
	var boundlessRequestorKeyHex string
	var boundlessMinPriceWei string
	var boundlessMaxPriceWei string
	var boundlessLockStakeWei string

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
	fs.StringVar(&verifierAddressHex, "verifier-address", "", "optional verifier router address (uses no-op verifier when unset)")
	fs.StringVar(&depositImageIDHex, "deposit-image-id", defaultDepositImageIDHex, "deposit image ID (bytes32)")
	fs.StringVar(&withdrawImageIDHex, "withdraw-image-id", defaultWithdrawImageIDHex, "withdraw image ID (bytes32)")
	fs.StringVar(&depositSealHex, "deposit-seal-hex", "", "optional mintBatch proof seal hex")
	fs.StringVar(&withdrawSealHex, "withdraw-seal-hex", "", "optional finalizeWithdrawBatch proof seal hex")
	fs.BoolVar(&cfg.PrepareOnly, "prepare-only", false, "prepare proof input artifacts only; skip mint/finalize transactions")
	fs.StringVar(&cfg.ProofInputsOut, "proof-inputs-output", "", "optional path to write proof input artifact bundle")
	fs.StringVar(&cfg.OutputPath, "output", "-", "output report path or '-' for stdout")
	fs.DurationVar(&cfg.RunTimeout, "run-timeout", 8*time.Minute, "overall command timeout (e.g. 8m, 90m)")

	fs.BoolVar(&cfg.Boundless.Auto, "boundless-auto", false, "automatically submit/wait proofs via Boundless and use returned seals")
	fs.StringVar(&cfg.Boundless.Bin, "boundless-bin", "boundless", "Boundless CLI binary path used by --boundless-auto")
	fs.StringVar(&cfg.Boundless.RPCURL, "boundless-rpc-url", "https://mainnet.base.org", "Boundless submission RPC URL")
	fs.StringVar(&boundlessRequestorKeyFile, "boundless-requestor-key-file", "", "file containing requestor private key hex for Boundless")
	fs.StringVar(&boundlessRequestorKeyHex, "boundless-requestor-key-hex", "", "requestor private key hex for Boundless")
	fs.StringVar(&cfg.Boundless.DepositProgramURL, "boundless-deposit-program-url", "", "deposit guest program URL for Boundless proof requests")
	fs.StringVar(&cfg.Boundless.WithdrawProgramURL, "boundless-withdraw-program-url", "", "withdraw guest program URL for Boundless proof requests")
	fs.StringVar(&boundlessMinPriceWei, "boundless-min-price-wei", defaultBoundlessMinPriceWei, "Boundless min price in wei")
	fs.StringVar(&boundlessMaxPriceWei, "boundless-max-price-wei", defaultBoundlessMaxPriceWei, "Boundless max price in wei")
	fs.StringVar(&boundlessLockStakeWei, "boundless-lock-stake-wei", defaultBoundlessLockStakeWei, "Boundless lock stake amount in wei")
	fs.Uint64Var(&cfg.Boundless.BiddingDelaySeconds, "boundless-bidding-delay-seconds", 85, "seconds after submission before bidding starts")
	fs.Uint64Var(&cfg.Boundless.RampUpPeriodSeconds, "boundless-ramp-up-period-seconds", 170, "auction ramp-up period in seconds")
	fs.Uint64Var(&cfg.Boundless.LockTimeoutSeconds, "boundless-lock-timeout-seconds", 625, "auction lock timeout in seconds")
	fs.Uint64Var(&cfg.Boundless.TimeoutSeconds, "boundless-timeout-seconds", 1500, "auction timeout in seconds")

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
	if cfg.RunTimeout <= 0 {
		return cfg, errors.New("--run-timeout must be > 0")
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
	if verifierAddressHex != "" {
		if !common.IsHexAddress(verifierAddressHex) {
			return cfg, errors.New("--verifier-address must be a valid hex address")
		}
		cfg.VerifierAddress = common.HexToAddress(verifierAddressHex)
		cfg.VerifierSet = true
	}

	var err error
	cfg.DepositImageID, err = parseHash32Flag("--deposit-image-id", depositImageIDHex)
	if err != nil {
		return cfg, err
	}
	cfg.WithdrawImageID, err = parseHash32Flag("--withdraw-image-id", withdrawImageIDHex)
	if err != nil {
		return cfg, err
	}

	cfg.DepositSeal, err = parseHexBytesFlag("--deposit-seal-hex", depositSealHex)
	if err != nil {
		return cfg, err
	}
	cfg.WithdrawSeal, err = parseHexBytesFlag("--withdraw-seal-hex", withdrawSealHex)
	if err != nil {
		return cfg, err
	}

	if boundlessRequestorKeyFile != "" && boundlessRequestorKeyHex != "" {
		return cfg, errors.New("use only one of --boundless-requestor-key-file or --boundless-requestor-key-hex")
	}
	if boundlessRequestorKeyFile != "" {
		keyBytes, err := os.ReadFile(boundlessRequestorKeyFile)
		if err != nil {
			return cfg, fmt.Errorf("read boundless requestor key file: %w", err)
		}
		boundlessRequestorKeyHex = strings.TrimSpace(string(keyBytes))
	}
	cfg.Boundless.RequestorKeyHex = strings.TrimSpace(boundlessRequestorKeyHex)

	cfg.Boundless.MinPriceWei, err = parseUint256Flag("--boundless-min-price-wei", boundlessMinPriceWei)
	if err != nil {
		return cfg, err
	}
	cfg.Boundless.MaxPriceWei, err = parseUint256Flag("--boundless-max-price-wei", boundlessMaxPriceWei)
	if err != nil {
		return cfg, err
	}
	cfg.Boundless.LockStakeWei, err = parseUint256Flag("--boundless-lock-stake-wei", boundlessLockStakeWei)
	if err != nil {
		return cfg, err
	}
	if cfg.Boundless.MinPriceWei.Cmp(cfg.Boundless.MaxPriceWei) > 0 {
		return cfg, errors.New("--boundless-min-price-wei must be <= --boundless-max-price-wei")
	}
	if cfg.Boundless.RampUpPeriodSeconds == 0 {
		return cfg, errors.New("--boundless-ramp-up-period-seconds must be > 0")
	}
	if cfg.Boundless.LockTimeoutSeconds == 0 {
		return cfg, errors.New("--boundless-lock-timeout-seconds must be > 0")
	}
	if cfg.Boundless.TimeoutSeconds == 0 {
		return cfg, errors.New("--boundless-timeout-seconds must be > 0")
	}
	if cfg.Boundless.LockTimeoutSeconds > cfg.Boundless.TimeoutSeconds {
		return cfg, errors.New("--boundless-lock-timeout-seconds must be <= --boundless-timeout-seconds")
	}
	if cfg.Boundless.Auto {
		if cfg.PrepareOnly {
			return cfg, errors.New("--boundless-auto cannot be used with --prepare-only")
		}
		if strings.TrimSpace(cfg.Boundless.Bin) == "" {
			return cfg, errors.New("--boundless-bin is required when --boundless-auto is set")
		}
		if strings.TrimSpace(cfg.Boundless.RPCURL) == "" {
			return cfg, errors.New("--boundless-rpc-url is required when --boundless-auto is set")
		}
		if strings.TrimSpace(cfg.Boundless.RequestorKeyHex) == "" {
			return cfg, errors.New("--boundless-requestor-key-file or --boundless-requestor-key-hex is required when --boundless-auto is set")
		}
		if strings.TrimSpace(cfg.Boundless.DepositProgramURL) == "" {
			return cfg, errors.New("--boundless-deposit-program-url is required when --boundless-auto is set")
		}
		if strings.TrimSpace(cfg.Boundless.WithdrawProgramURL) == "" {
			return cfg, errors.New("--boundless-withdraw-program-url is required when --boundless-auto is set")
		}
		if !cfg.VerifierSet {
			return cfg, errors.New("--boundless-auto requires --verifier-address")
		}
	}

	if cfg.PrepareOnly && strings.TrimSpace(cfg.ProofInputsOut) == "" {
		return cfg, errors.New("--prepare-only requires --proof-inputs-output")
	}

	if !cfg.PrepareOnly {
		if cfg.VerifierSet {
			if cfg.Boundless.Auto {
				if len(cfg.DepositSeal) != 0 || len(cfg.WithdrawSeal) != 0 {
					return cfg, errors.New("--boundless-auto cannot be combined with --deposit-seal-hex or --withdraw-seal-hex")
				}
			} else if len(cfg.DepositSeal) == 0 || len(cfg.WithdrawSeal) == 0 {
				return cfg, errors.New("--verifier-address requires --deposit-seal-hex and --withdraw-seal-hex unless --prepare-only is set")
			}
		} else {
			if cfg.Boundless.Auto {
				return cfg, errors.New("--boundless-auto requires --verifier-address")
			}
			if len(cfg.DepositSeal) == 0 {
				cfg.DepositSeal = []byte{0x99}
			}
			if len(cfg.WithdrawSeal) == 0 {
				cfg.WithdrawSeal = []byte{0x99}
			}
		}
	}

	return cfg, nil
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

func parseHash32Flag(flagName, raw string) (common.Hash, error) {
	b, err := parseHexBytesFlag(flagName, raw)
	if err != nil {
		return common.Hash{}, err
	}
	if len(b) != 32 {
		return common.Hash{}, fmt.Errorf("%s must be 32 bytes hex", flagName)
	}
	return common.BytesToHash(b), nil
}

func parseUint256Flag(flagName, raw string) (*big.Int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, fmt.Errorf("%s must be set", flagName)
	}
	out, ok := new(big.Int).SetString(v, 10)
	if !ok {
		return nil, fmt.Errorf("%s must be a base-10 integer", flagName)
	}
	if out.Sign() < 0 {
		return nil, fmt.Errorf("%s must be >= 0", flagName)
	}
	return out, nil
}

func writeJSONArtifact(path string, value any) (string, error) {
	out, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return abs, nil
}

func encodeSignaturesHex(sigs [][]byte) []string {
	out := make([]string, 0, len(sigs))
	for _, sig := range sigs {
		out = append(out, hexutil.Encode(sig))
	}
	return out
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

	verifierAddr := cfg.VerifierAddress
	if !cfg.VerifierSet {
		verifierAddr, _, err = deployNoopVerifier(ctx, client, auth)
		if err != nil {
			return nil, fmt.Errorf("deploy verifier: %w", err)
		}
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

	depositImageID := cfg.DepositImageID
	withdrawImageID := cfg.WithdrawImageID
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

	depositAmount := new(big.Int).SetUint64(cfg.DepositAmount)
	depositID := crypto.Keccak256Hash([]byte("bridge-e2e-deposit-1"))
	mintItems := []bridgeabi.MintItem{
		{
			DepositId: depositID,
			Recipient: recipient,
			Amount:    depositAmount,
		},
	}
	depositJournal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items:            mintItems,
	})
	if err != nil {
		return nil, fmt.Errorf("encode deposit journal: %w", err)
	}
	depositPrivateInput, err := proverinput.EncodeDepositPrivateInputV1(cp, cpSigs, mintItems)
	if err != nil {
		return nil, fmt.Errorf("encode deposit private input: %w", err)
	}

	withdrawAmount := new(big.Int).SetUint64(cfg.WithdrawAmount)
	recipientUA := []byte{0x01, 0x02, 0x03}

	nonceBefore, err := callUint64(ctx, bridge, "withdrawNonce")
	if err != nil {
		return nil, fmt.Errorf("withdrawNonce: %w", err)
	}
	predictedWithdrawalID, err := computePredictedWithdrawalID(cfg.ChainID, bridgeAddr, nonceBefore+1, owner, withdrawAmount, recipientUA)
	if err != nil {
		return nil, fmt.Errorf("compute predicted withdrawal id: %w", err)
	}

	var (
		mintBatchTx        common.Hash
		mintBatchRcpt      *types.Receipt
		approveWithdrawTx  common.Hash
		requestWithdrawTx  common.Hash
		finalizeWithdrawTx common.Hash
		withdrawalID       common.Hash
		feeBpsAtReq        uint64
		depositRequestID   string
		withdrawRequestID  string
	)

	if cfg.PrepareOnly {
		feeBpsAtReq, err = callUint64(ctx, bridge, "feeBps")
		if err != nil {
			return nil, fmt.Errorf("feeBps: %w", err)
		}
		withdrawalID = predictedWithdrawalID
	} else {
		if cfg.Boundless.Auto {
			cfg.DepositSeal, depositRequestID, err = requestBoundlessProof(
				ctx,
				cfg.Boundless,
				"deposit",
				cfg.Boundless.DepositProgramURL,
				depositPrivateInput,
				depositJournal,
			)
			if err != nil {
				return nil, err
			}
		}

		mintBatchTx, mintBatchRcpt, err = transactAndWaitWithReceipt(ctx, client, auth, bridge, "mintBatch", cpABI, cpSigs, cfg.DepositSeal, depositJournal)
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

		approveWithdrawTx, err = transactAndWait(ctx, client, auth, wjuno, "approve", bridgeAddr, withdrawAmount)
		if err != nil {
			return nil, fmt.Errorf("approve withdraw: %w", err)
		}

		var requestRcpt *types.Receipt
		requestWithdrawTx, requestRcpt, err = transactAndWaitWithReceipt(ctx, client, auth, bridge, "requestWithdraw", withdrawAmount, recipientUA)
		if err != nil {
			return nil, fmt.Errorf("requestWithdraw: %w", err)
		}
		withdrawalID, feeBpsAtReq, err = parseWithdrawRequested(bridgeABI, requestRcpt)
		if err != nil {
			return nil, fmt.Errorf("parse WithdrawRequested: %w", err)
		}
		if withdrawalID != predictedWithdrawalID {
			return nil, fmt.Errorf("predicted withdrawal id mismatch: predicted=%s actual=%s", predictedWithdrawalID.Hex(), withdrawalID.Hex())
		}
	}

	fee := new(big.Int).Mul(withdrawAmount, new(big.Int).SetUint64(feeBpsAtReq))
	fee.Div(fee, big.NewInt(10_000))
	net := new(big.Int).Sub(withdrawAmount, fee)

	finalizeItems := []bridgeabi.FinalizeItem{
		{
			WithdrawalId:    withdrawalID,
			RecipientUAHash: crypto.Keccak256Hash(recipientUA),
			NetAmount:       net,
		},
	}

	withdrawJournal, err := bridgeabi.EncodeWithdrawJournal(bridgeabi.WithdrawJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items:            finalizeItems,
	})
	if err != nil {
		return nil, fmt.Errorf("encode withdraw journal: %w", err)
	}
	withdrawPrivateInput, err := proverinput.EncodeWithdrawPrivateInputV1(cp, cpSigs, finalizeItems)
	if err != nil {
		return nil, fmt.Errorf("encode withdraw private input: %w", err)
	}

	var proofInputsPath string
	if strings.TrimSpace(cfg.ProofInputsOut) != "" {
		proofBundle := proofInputsFile{
			Version:            "bridge-e2e.proof_inputs.v1",
			GeneratedAtUTC:     time.Now().UTC().Format(time.RFC3339),
			ChainID:            cfg.ChainID,
			BridgeContract:     bridgeAddr.Hex(),
			Checkpoint:         cp,
			OperatorSignatures: encodeSignaturesHex(cpSigs),
		}

		proofBundle.Deposit.ProofInput.Pipeline = "deposit"
		proofBundle.Deposit.ProofInput.ImageID = depositImageID.Hex()
		proofBundle.Deposit.ProofInput.Journal = hexutil.Encode(depositJournal)
		proofBundle.Deposit.ProofInput.PrivateInput = hexutil.Encode(depositPrivateInput)
		proofBundle.Deposit.DepositID = depositID.Hex()
		proofBundle.Deposit.Recipient = recipient.Hex()
		proofBundle.Deposit.Amount = depositAmount.String()

		proofBundle.Withdraw.ProofInput.Pipeline = "withdraw"
		proofBundle.Withdraw.ProofInput.ImageID = withdrawImageID.Hex()
		proofBundle.Withdraw.ProofInput.Journal = hexutil.Encode(withdrawJournal)
		proofBundle.Withdraw.ProofInput.PrivateInput = hexutil.Encode(withdrawPrivateInput)
		proofBundle.Withdraw.RecipientUAHex = hexutil.Encode(recipientUA)
		proofBundle.Withdraw.WithdrawalID = withdrawalID.Hex()
		proofBundle.Withdraw.NetAmount = net.String()

		proofInputsPath, err = writeJSONArtifact(cfg.ProofInputsOut, proofBundle)
		if err != nil {
			return nil, err
		}
	}

	if !cfg.PrepareOnly && cfg.Boundless.Auto {
		cfg.WithdrawSeal, withdrawRequestID, err = requestBoundlessProof(
			ctx,
			cfg.Boundless,
			"withdraw",
			cfg.Boundless.WithdrawProgramURL,
			withdrawPrivateInput,
			withdrawJournal,
		)
		if err != nil {
			return nil, err
		}
	}

	if !cfg.PrepareOnly {
		finalizeWithdrawTx, err = transactAndWait(ctx, client, auth, bridge, "finalizeWithdrawBatch", cpABI, cpSigs, cfg.WithdrawSeal, withdrawJournal)
		if err != nil {
			return nil, fmt.Errorf("finalizeWithdrawBatch: %w", err)
		}
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
	if mintBatchTx != (common.Hash{}) {
		rep.Transactions.MintBatch = mintBatchTx.Hex()
	}
	if approveWithdrawTx != (common.Hash{}) {
		rep.Transactions.ApproveWithdraw = approveWithdrawTx.Hex()
	}
	if requestWithdrawTx != (common.Hash{}) {
		rep.Transactions.RequestWithdraw = requestWithdrawTx.Hex()
		rep.Withdraw.WithdrawalID = withdrawalID.Hex()
	}
	if finalizeWithdrawTx != (common.Hash{}) {
		rep.Transactions.FinalizeWithdraw = finalizeWithdrawTx.Hex()
	}

	rep.Withdraw.PredictedID = predictedWithdrawalID.Hex()
	rep.Withdraw.FeeBps = feeBpsAtReq

	rep.Balances.RecipientWJuno = recipientBal.String()
	rep.Balances.FeeDistributor = fdBal.String()

	rep.Proof.PrepareOnly = cfg.PrepareOnly
	rep.Proof.ProofInputsPath = proofInputsPath
	rep.Proof.DepositImageID = depositImageID.Hex()
	rep.Proof.WithdrawImageID = withdrawImageID.Hex()
	rep.Proof.DepositSealBytes = len(cfg.DepositSeal)
	rep.Proof.WithdrawSealBytes = len(cfg.WithdrawSeal)
	rep.Proof.Boundless.Enabled = cfg.Boundless.Auto
	if cfg.Boundless.Auto {
		rep.Proof.Boundless.RPCURL = cfg.Boundless.RPCURL
		rep.Proof.Boundless.DepositRequestID = depositRequestID
		rep.Proof.Boundless.WithdrawRequestID = withdrawRequestID
		rep.Proof.Boundless.MinPriceWei = cfg.Boundless.MinPriceWei.String()
		rep.Proof.Boundless.MaxPriceWei = cfg.Boundless.MaxPriceWei.String()
		rep.Proof.Boundless.LockStakeWei = cfg.Boundless.LockStakeWei.String()
		rep.Proof.Boundless.BiddingDelaySec = cfg.Boundless.BiddingDelaySeconds
		rep.Proof.Boundless.RampUpPeriodSec = cfg.Boundless.RampUpPeriodSeconds
		rep.Proof.Boundless.LockTimeoutSec = cfg.Boundless.LockTimeoutSeconds
		rep.Proof.Boundless.TimeoutSec = cfg.Boundless.TimeoutSeconds
	}

	return &rep, nil
}

func requestBoundlessProof(
	ctx context.Context,
	cfg boundlessConfig,
	pipeline string,
	programURL string,
	privateInput []byte,
	expectedJournal []byte,
) ([]byte, string, error) {
	tmp, err := os.CreateTemp("", "bridge-e2e-"+pipeline+"-input-*.bin")
	if err != nil {
		return nil, "", fmt.Errorf("create boundless input file for %s: %w", pipeline, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Close(); err != nil {
		return nil, "", fmt.Errorf("close boundless input file for %s: %w", pipeline, err)
	}
	if err := os.WriteFile(tmpPath, privateInput, 0o600); err != nil {
		return nil, "", fmt.Errorf("write boundless input file for %s: %w", pipeline, err)
	}

	privateKey := strings.TrimPrefix(strings.TrimSpace(cfg.RequestorKeyHex), "0x")
	biddingStart := time.Now().UTC().Unix() + int64(cfg.BiddingDelaySeconds)

	args := []string{
		"--rpc-url", cfg.RPCURL,
		"--private-key", privateKey,
		"request", "submit-offer",
		"--program-url", programURL,
		"--input-file", tmpPath,
		"--proof-type", "groth16",
		"--wait",
		"--min-price", cfg.MinPriceWei.String(),
		"--max-price", cfg.MaxPriceWei.String(),
		"--lock-stake", cfg.LockStakeWei.String(),
		"--bidding-start", strconv.FormatInt(biddingStart, 10),
		"--ramp-up-period", strconv.FormatUint(cfg.RampUpPeriodSeconds, 10),
		"--lock-timeout", strconv.FormatUint(cfg.LockTimeoutSeconds, 10),
		"--timeout", strconv.FormatUint(cfg.TimeoutSeconds, 10),
	}

	out, err := exec.CommandContext(ctx, cfg.Bin, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, "", fmt.Errorf("boundless submit-offer failed for %s: %s", pipeline, msg)
	}

	parsed, err := parseBoundlessWaitOutput(out)
	if err != nil {
		return nil, "", fmt.Errorf("parse boundless output for %s: %w", pipeline, err)
	}

	journal, err := parseHexBytesFlag("boundless journal", parsed.JournalHex)
	if err != nil {
		return nil, "", fmt.Errorf("decode boundless journal for %s: %w", pipeline, err)
	}
	if !bytes.Equal(journal, expectedJournal) {
		return nil, "", fmt.Errorf("boundless journal mismatch for %s", pipeline)
	}

	seal, err := parseHexBytesFlag("boundless seal", parsed.SealHex)
	if err != nil {
		return nil, "", fmt.Errorf("decode boundless seal for %s: %w", pipeline, err)
	}
	if len(seal) == 0 {
		return nil, "", fmt.Errorf("boundless returned empty seal for %s", pipeline)
	}

	return seal, parsed.RequestIDHex, nil
}

var (
	boundlessRequestIDRegex = regexp.MustCompile(`Submitted request\s+(0x[0-9a-fA-F]+)`)
	boundlessProofRegex     = regexp.MustCompile(`Journal:\s*\"(0x[0-9a-fA-F]*)\"\s*-\s*Seal:\s*\"(0x[0-9a-fA-F]+)\"`)
)

func parseBoundlessWaitOutput(output []byte) (boundlessWaitResult, error) {
	raw := string(output)

	requestMatches := boundlessRequestIDRegex.FindAllStringSubmatch(raw, -1)
	if len(requestMatches) == 0 || len(requestMatches[len(requestMatches)-1]) < 2 {
		return boundlessWaitResult{}, errors.New("boundless output missing request id")
	}
	requestID := strings.ToLower(strings.TrimSpace(requestMatches[len(requestMatches)-1][1]))

	proofMatches := boundlessProofRegex.FindAllStringSubmatch(raw, -1)
	if len(proofMatches) == 0 || len(proofMatches[len(proofMatches)-1]) < 3 {
		return boundlessWaitResult{}, errors.New("boundless output missing journal/seal")
	}
	last := proofMatches[len(proofMatches)-1]
	journalHex := strings.ToLower(strings.TrimSpace(last[1]))
	sealHex := strings.ToLower(strings.TrimSpace(last[2]))
	if sealHex == "" {
		return boundlessWaitResult{}, errors.New("boundless output missing seal")
	}

	return boundlessWaitResult{
		RequestIDHex: requestID,
		JournalHex:   journalHex,
		SealHex:      sealHex,
	}, nil
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
