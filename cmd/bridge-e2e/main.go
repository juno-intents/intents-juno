package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
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
	InputMode          string
	MarketAddress      common.Address
	VerifierRouterAddr common.Address
	SetVerifierAddr    common.Address
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
	defaultBoundlessMarketAddr   = "0xFd152dADc5183870710FE54f939Eae3aB9F0fE82"
	defaultBoundlessRouterAddr   = "0x0b144e07a0826182b6b59788c34b32bfa86fb711"
	defaultBoundlessSetVerAddr   = "0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104"
	defaultRetryGasPriceWei      = int64(5_000_000_000)
	defaultRetryGasTipCapWei     = int64(2_000_000_000)

	boundlessInputModePrivate        = "private-input"
	boundlessInputModeJournalBytesV1 = "journal-bytes-v1"
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
			InputMode         string `json:"input_mode,omitempty"`
			MarketAddress     string `json:"market_address,omitempty"`
			VerifierRouter    string `json:"verifier_router_address,omitempty"`
			SetVerifier       string `json:"set_verifier_address,omitempty"`
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

	Invariants struct {
		Registry struct {
			OperatorCount uint64 `json:"operator_count"`
			Threshold     uint64 `json:"threshold"`
			AllActive     bool   `json:"all_active"`
		} `json:"registry"`
		DepositUsed bool `json:"deposit_used"`
		Withdrawal  struct {
			Exists    bool   `json:"exists"`
			Finalized bool   `json:"finalized"`
			Refunded  bool   `json:"refunded"`
			FeeBps    uint64 `json:"fee_bps"`
			Amount    string `json:"amount"`
			Expiry    uint64 `json:"expiry"`
		} `json:"withdrawal"`
		Fees struct {
			Deposit struct {
				Fee              string `json:"fee"`
				Tip              string `json:"tip"`
				FeeToDistributor string `json:"fee_to_distributor"`
				Net              string `json:"net"`
			} `json:"deposit"`
			Withdraw struct {
				Fee              string `json:"fee"`
				Tip              string `json:"tip"`
				FeeToDistributor string `json:"fee_to_distributor"`
				Net              string `json:"net"`
			} `json:"withdraw"`
		} `json:"fees"`
		BalanceDeltas struct {
			OwnerExpected          string `json:"owner_expected"`
			OwnerActual            string `json:"owner_actual"`
			RecipientExpected      string `json:"recipient_expected"`
			RecipientActual        string `json:"recipient_actual"`
			FeeDistributorExpected string `json:"fee_distributor_expected"`
			FeeDistributorActual   string `json:"fee_distributor_actual"`
			BridgeExpected         string `json:"bridge_expected"`
			BridgeActual           string `json:"bridge_actual"`
			Matches                bool   `json:"matches"`
		} `json:"balance_deltas"`
	} `json:"invariants"`
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
		Amount         string `json:"amount,omitempty"`
		NetAmount      string `json:"net_amount"`
	} `json:"withdraw"`
}

type feeBreakdown struct {
	Fee              *big.Int
	Tip              *big.Int
	FeeToDistributor *big.Int
	Net              *big.Int
}

type expectedBalanceDeltaInput struct {
	DepositAmount        *big.Int
	WithdrawAmount       *big.Int
	DepositFeeBps        uint64
	WithdrawFeeBps       uint64
	RelayerTipBps        uint64
	RecipientEqualsOwner bool
}

type expectedBalanceDelta struct {
	Owner          *big.Int
	Recipient      *big.Int
	FeeDistributor *big.Int
	Bridge         *big.Int
}

type withdrawalView struct {
	Requester common.Address
	Amount    *big.Int
	Expiry    uint64
	FeeBps    uint64
	Finalized bool
	Refunded  bool
	Recipient []byte
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
	fs.StringVar(&cfg.Boundless.InputMode, "boundless-input-mode", boundlessInputModePrivate, "Boundless input mode: private-input or journal-bytes-v1")
	var boundlessMarketAddressHex string
	var boundlessVerifierRouterHex string
	var boundlessSetVerifierHex string
	fs.StringVar(&boundlessMarketAddressHex, "boundless-market-address", defaultBoundlessMarketAddr, "Boundless market contract address")
	fs.StringVar(&boundlessVerifierRouterHex, "boundless-verifier-router-address", defaultBoundlessRouterAddr, "Boundless verifier router contract address")
	fs.StringVar(&boundlessSetVerifierHex, "boundless-set-verifier-address", defaultBoundlessSetVerAddr, "Boundless set verifier contract address")
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
	cfg.Boundless.InputMode, err = parseBoundlessInputMode(cfg.Boundless.InputMode)
	if err != nil {
		return cfg, err
	}
	if !common.IsHexAddress(boundlessMarketAddressHex) {
		return cfg, errors.New("--boundless-market-address must be a valid hex address")
	}
	cfg.Boundless.MarketAddress = common.HexToAddress(boundlessMarketAddressHex)
	if !common.IsHexAddress(boundlessVerifierRouterHex) {
		return cfg, errors.New("--boundless-verifier-router-address must be a valid hex address")
	}
	cfg.Boundless.VerifierRouterAddr = common.HexToAddress(boundlessVerifierRouterHex)
	if !common.IsHexAddress(boundlessSetVerifierHex) {
		return cfg, errors.New("--boundless-set-verifier-address must be a valid hex address")
	}
	cfg.Boundless.SetVerifierAddr = common.HexToAddress(boundlessSetVerifierHex)
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

func parseBoundlessInputMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "", boundlessInputModePrivate:
		return boundlessInputModePrivate, nil
	case boundlessInputModeJournalBytesV1:
		return boundlessInputModeJournalBytesV1, nil
	default:
		return "", errors.New("--boundless-input-mode must be one of: private-input, journal-bytes-v1")
	}
}

func encodeBoundlessJournalInput(journal []byte) ([]byte, error) {
	if len(journal) > math.MaxUint32 {
		return nil, fmt.Errorf("journal too large for boundless input: %d bytes", len(journal))
	}
	out := make([]byte, 4+len(journal))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(journal)))
	copy(out[4:], journal)
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

	registryOperatorCount, err := callUint64(ctx, reg, "operatorCount")
	if err != nil {
		return nil, fmt.Errorf("operatorCount: %w", err)
	}
	if registryOperatorCount != uint64(len(operatorAddrs)) {
		return nil, fmt.Errorf("operatorCount mismatch: got=%d want=%d", registryOperatorCount, len(operatorAddrs))
	}
	registryThreshold, err := callUint64(ctx, reg, "threshold")
	if err != nil {
		return nil, fmt.Errorf("threshold: %w", err)
	}
	if registryThreshold != uint64(cfg.Threshold) {
		return nil, fmt.Errorf("registry threshold mismatch: got=%d want=%d", registryThreshold, cfg.Threshold)
	}
	allOperatorsActive := true
	for _, op := range operatorAddrs {
		isActive, err := callBool(ctx, reg, "isOperator", op)
		if err != nil {
			return nil, fmt.Errorf("isOperator(%s): %w", op.Hex(), err)
		}
		if !isActive {
			allOperatorsActive = false
			break
		}
	}
	if !allOperatorsActive {
		return nil, errors.New("operator registry invariant failed: not all operators are active")
	}

	feeBpsOnChain, err := callUint64(ctx, bridge, "feeBps")
	if err != nil {
		return nil, fmt.Errorf("bridge feeBps: %w", err)
	}
	relayerTipBpsOnChain, err := callUint64(ctx, bridge, "relayerTipBps")
	if err != nil {
		return nil, fmt.Errorf("bridge relayerTipBps: %w", err)
	}
	if feeBpsOnChain != feeBps {
		return nil, fmt.Errorf("bridge feeBps mismatch: got=%d want=%d", feeBpsOnChain, feeBps)
	}
	if relayerTipBpsOnChain != tipBps {
		return nil, fmt.Errorf("bridge relayerTipBps mismatch: got=%d want=%d", relayerTipBpsOnChain, tipBps)
	}

	ownerBalBefore, err := callBalanceOf(ctx, wjuno, owner)
	if err != nil {
		return nil, fmt.Errorf("owner balance before: %w", err)
	}
	recipientBalBefore, err := callBalanceOf(ctx, wjuno, recipient)
	if err != nil {
		return nil, fmt.Errorf("recipient balance before: %w", err)
	}
	fdBalBefore, err := callBalanceOf(ctx, wjuno, fdAddr)
	if err != nil {
		return nil, fmt.Errorf("fee distributor balance before: %w", err)
	}
	bridgeBalBefore, err := callBalanceOf(ctx, wjuno, bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("bridge balance before: %w", err)
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
	depositFees := computeFeeBreakdown(depositAmount, feeBpsOnChain, relayerTipBpsOnChain)
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
	depositBoundlessInput := depositPrivateInput
	if cfg.Boundless.InputMode == boundlessInputModeJournalBytesV1 {
		depositBoundlessInput, err = encodeBoundlessJournalInput(depositJournal)
		if err != nil {
			return nil, fmt.Errorf("encode deposit boundless input: %w", err)
		}
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
		feeBpsAtReq = feeBpsOnChain
		withdrawalID = predictedWithdrawalID
	} else {
		if cfg.Boundless.Auto {
			cfg.DepositSeal, depositRequestID, err = requestBoundlessProof(
				ctx,
				cfg.Boundless,
				"deposit",
				cfg.Boundless.DepositProgramURL,
				depositBoundlessInput,
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

	withdrawFees := computeFeeBreakdown(withdrawAmount, feeBpsAtReq, relayerTipBpsOnChain)
	net := new(big.Int).Set(withdrawFees.Net)

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
	withdrawBoundlessInput := withdrawPrivateInput
	if cfg.Boundless.InputMode == boundlessInputModeJournalBytesV1 {
		withdrawBoundlessInput, err = encodeBoundlessJournalInput(withdrawJournal)
		if err != nil {
			return nil, fmt.Errorf("encode withdraw boundless input: %w", err)
		}
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
		proofBundle.Withdraw.Amount = withdrawAmount.String()
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
			withdrawBoundlessInput,
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

	ownerBalAfter, err := callBalanceOf(ctx, wjuno, owner)
	if err != nil {
		return nil, fmt.Errorf("owner balance after: %w", err)
	}
	recipientBalAfter, err := callBalanceOf(ctx, wjuno, recipient)
	if err != nil {
		return nil, fmt.Errorf("recipient balance after: %w", err)
	}
	fdBalAfter, err := callBalanceOf(ctx, wjuno, fdAddr)
	if err != nil {
		return nil, fmt.Errorf("fee distributor balance after: %w", err)
	}
	bridgeBalAfter, err := callBalanceOf(ctx, wjuno, bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("bridge balance after: %w", err)
	}

	depositUsedInvariant := false
	withdrawInvariant := withdrawalView{Amount: big.NewInt(0)}
	if !cfg.PrepareOnly {
		depositUsedInvariant, err = callDepositUsed(ctx, bridge, depositID, nil)
		if err != nil {
			return nil, fmt.Errorf("depositUsed invariant call: %w", err)
		}
		if !depositUsedInvariant {
			return nil, errors.New("depositUsed invariant failed: expected true after mintBatch")
		}

		withdrawInvariant, err = callWithdrawal(ctx, bridge, withdrawalID)
		if err != nil {
			return nil, fmt.Errorf("getWithdrawal invariant call: %w", err)
		}
		if withdrawInvariant.Requester != owner {
			return nil, fmt.Errorf("withdraw requester mismatch: got=%s want=%s", withdrawInvariant.Requester.Hex(), owner.Hex())
		}
		if withdrawInvariant.Amount.Cmp(withdrawAmount) != 0 {
			return nil, fmt.Errorf("withdraw amount mismatch: got=%s want=%s", withdrawInvariant.Amount.String(), withdrawAmount.String())
		}
		if withdrawInvariant.FeeBps != feeBpsAtReq {
			return nil, fmt.Errorf("withdraw fee bps mismatch: got=%d want=%d", withdrawInvariant.FeeBps, feeBpsAtReq)
		}
		if !withdrawInvariant.Finalized {
			return nil, errors.New("withdraw invariant failed: expected finalized=true")
		}
		if withdrawInvariant.Refunded {
			return nil, errors.New("withdraw invariant failed: expected refunded=false")
		}
		if !bytes.Equal(withdrawInvariant.Recipient, recipientUA) {
			return nil, errors.New("withdraw invariant failed: recipient UA mismatch")
		}
	}

	recipientEqualsOwner := recipient == owner
	expectedDeltas := expectedBalanceDeltas(expectedBalanceDeltaInput{
		DepositAmount:        depositAmount,
		WithdrawAmount:       withdrawAmount,
		DepositFeeBps:        feeBpsOnChain,
		WithdrawFeeBps:       feeBpsAtReq,
		RelayerTipBps:        relayerTipBpsOnChain,
		RecipientEqualsOwner: recipientEqualsOwner,
	})
	if cfg.PrepareOnly {
		expectedDeltas = expectedBalanceDelta{
			Owner:          big.NewInt(0),
			Recipient:      big.NewInt(0),
			FeeDistributor: big.NewInt(0),
			Bridge:         big.NewInt(0),
		}
	}

	ownerDeltaActual := new(big.Int).Sub(ownerBalAfter, ownerBalBefore)
	recipientDeltaRaw := new(big.Int).Sub(recipientBalAfter, recipientBalBefore)
	recipientDeltaActual := normalizeRecipientDeltaActual(recipientDeltaRaw, recipientEqualsOwner)
	fdDeltaActual := new(big.Int).Sub(fdBalAfter, fdBalBefore)
	bridgeDeltaActual := new(big.Int).Sub(bridgeBalAfter, bridgeBalBefore)

	balanceDeltaMatches := ownerDeltaActual.Cmp(expectedDeltas.Owner) == 0 &&
		recipientDeltaActual.Cmp(expectedDeltas.Recipient) == 0 &&
		fdDeltaActual.Cmp(expectedDeltas.FeeDistributor) == 0 &&
		bridgeDeltaActual.Cmp(expectedDeltas.Bridge) == 0
	if !balanceDeltaMatches {
		return nil, fmt.Errorf(
			"balance delta invariant failed: owner got=%s want=%s recipient got=%s raw=%s want=%s feeDistributor got=%s want=%s bridge got=%s want=%s",
			ownerDeltaActual.String(),
			expectedDeltas.Owner.String(),
			recipientDeltaActual.String(),
			recipientDeltaRaw.String(),
			expectedDeltas.Recipient.String(),
			fdDeltaActual.String(),
			expectedDeltas.FeeDistributor.String(),
			bridgeDeltaActual.String(),
			expectedDeltas.Bridge.String(),
		)
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

	rep.Balances.RecipientWJuno = recipientBalAfter.String()
	rep.Balances.FeeDistributor = fdBalAfter.String()

	rep.Proof.PrepareOnly = cfg.PrepareOnly
	rep.Proof.ProofInputsPath = proofInputsPath
	rep.Proof.DepositImageID = depositImageID.Hex()
	rep.Proof.WithdrawImageID = withdrawImageID.Hex()
	rep.Proof.DepositSealBytes = len(cfg.DepositSeal)
	rep.Proof.WithdrawSealBytes = len(cfg.WithdrawSeal)
	rep.Proof.Boundless.Enabled = cfg.Boundless.Auto
	if cfg.Boundless.Auto {
		rep.Proof.Boundless.RPCURL = cfg.Boundless.RPCURL
		rep.Proof.Boundless.InputMode = cfg.Boundless.InputMode
		rep.Proof.Boundless.MarketAddress = cfg.Boundless.MarketAddress.Hex()
		rep.Proof.Boundless.VerifierRouter = cfg.Boundless.VerifierRouterAddr.Hex()
		rep.Proof.Boundless.SetVerifier = cfg.Boundless.SetVerifierAddr.Hex()
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

	rep.Invariants.Registry.OperatorCount = registryOperatorCount
	rep.Invariants.Registry.Threshold = registryThreshold
	rep.Invariants.Registry.AllActive = allOperatorsActive
	rep.Invariants.DepositUsed = depositUsedInvariant
	rep.Invariants.Withdrawal.Exists = !cfg.PrepareOnly
	rep.Invariants.Withdrawal.Finalized = withdrawInvariant.Finalized
	rep.Invariants.Withdrawal.Refunded = withdrawInvariant.Refunded
	rep.Invariants.Withdrawal.FeeBps = withdrawInvariant.FeeBps
	rep.Invariants.Withdrawal.Amount = withdrawInvariant.Amount.String()
	rep.Invariants.Withdrawal.Expiry = withdrawInvariant.Expiry

	rep.Invariants.Fees.Deposit.Fee = depositFees.Fee.String()
	rep.Invariants.Fees.Deposit.Tip = depositFees.Tip.String()
	rep.Invariants.Fees.Deposit.FeeToDistributor = depositFees.FeeToDistributor.String()
	rep.Invariants.Fees.Deposit.Net = depositFees.Net.String()
	rep.Invariants.Fees.Withdraw.Fee = withdrawFees.Fee.String()
	rep.Invariants.Fees.Withdraw.Tip = withdrawFees.Tip.String()
	rep.Invariants.Fees.Withdraw.FeeToDistributor = withdrawFees.FeeToDistributor.String()
	rep.Invariants.Fees.Withdraw.Net = withdrawFees.Net.String()

	rep.Invariants.BalanceDeltas.OwnerExpected = expectedDeltas.Owner.String()
	rep.Invariants.BalanceDeltas.OwnerActual = ownerDeltaActual.String()
	rep.Invariants.BalanceDeltas.RecipientExpected = expectedDeltas.Recipient.String()
	rep.Invariants.BalanceDeltas.RecipientActual = recipientDeltaActual.String()
	rep.Invariants.BalanceDeltas.FeeDistributorExpected = expectedDeltas.FeeDistributor.String()
	rep.Invariants.BalanceDeltas.FeeDistributorActual = fdDeltaActual.String()
	rep.Invariants.BalanceDeltas.BridgeExpected = expectedDeltas.Bridge.String()
	rep.Invariants.BalanceDeltas.BridgeActual = bridgeDeltaActual.String()
	rep.Invariants.BalanceDeltas.Matches = balanceDeltaMatches

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
		"requestor", "submit",
		"--program-url", programURL,
		"--input-file", tmpPath,
		"--proof-type", "groth16",
		"--wait",
		"--requestor-rpc-url", cfg.RPCURL,
		"--requestor-private-key", privateKey,
		"--boundless-market-address", cfg.MarketAddress.Hex(),
		"--verifier-router-address", cfg.VerifierRouterAddr.Hex(),
		"--set-verifier-address", cfg.SetVerifierAddr.Hex(),
		"--min-price", cfg.MinPriceWei.String(),
		"--max-price", cfg.MaxPriceWei.String(),
		"--lock-collateral", cfg.LockStakeWei.String(),
		"--bidding-start", strconv.FormatInt(biddingStart, 10),
		"--ramp-up-period", strconv.FormatUint(cfg.RampUpPeriodSeconds, 10),
		"--lock-timeout", strconv.FormatUint(cfg.LockTimeoutSeconds, 10),
		"--timeout", strconv.FormatUint(cfg.TimeoutSeconds, 10),
	}

	cmd := exec.CommandContext(ctx, cfg.Bin, args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if version := boundlessPrivateInputVersion(privateInput); version != "" {
			msg += " (input_version=" + version + ")"
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

func boundlessPrivateInputVersion(privateInput []byte) string {
	trimmed := bytes.TrimSpace(privateInput)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ""
	}

	var envelope struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return ""
	}
	return strings.TrimSpace(envelope.Version)
}

var (
	boundlessRequestIDRegex   = regexp.MustCompile(`(?:Assigned Request ID:|Request ID:|Submitted request)\s*(0x[0-9a-fA-F]+)`)
	boundlessLegacyProofRegex = regexp.MustCompile(`Journal:\s*\"(0x[0-9a-fA-F]*)\"\s*-\s*Seal:\s*\"(0x[0-9a-fA-F]+)\"`)
	boundlessFulfillmentRegex = regexp.MustCompile(`(?s)Fulfillment Data:\s*(\{.*?\})\s*Seal:`)
	boundlessSealOnlyRegex    = regexp.MustCompile(`Seal:\s*\"(0x[0-9a-fA-F]+)\"`)
)

func parseBoundlessWaitOutput(output []byte) (boundlessWaitResult, error) {
	raw := string(output)

	requestMatches := boundlessRequestIDRegex.FindAllStringSubmatch(raw, -1)
	if len(requestMatches) == 0 || len(requestMatches[len(requestMatches)-1]) < 2 {
		return boundlessWaitResult{}, errors.New("boundless output missing request id")
	}
	requestID := strings.ToLower(strings.TrimSpace(requestMatches[len(requestMatches)-1][1]))

	if legacyMatches := boundlessLegacyProofRegex.FindAllStringSubmatch(raw, -1); len(legacyMatches) > 0 {
		last := legacyMatches[len(legacyMatches)-1]
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

	fulfillmentMatch := boundlessFulfillmentRegex.FindStringSubmatch(raw)
	if len(fulfillmentMatch) < 2 {
		return boundlessWaitResult{}, errors.New("boundless output missing journal/seal")
	}

	var fulfillment struct {
		ImageIDAndJournal []json.RawMessage `json:"ImageIdAndJournal"`
	}
	if err := json.Unmarshal([]byte(fulfillmentMatch[1]), &fulfillment); err != nil {
		return boundlessWaitResult{}, fmt.Errorf("decode fulfillment data: %w", err)
	}
	if len(fulfillment.ImageIDAndJournal) < 2 {
		return boundlessWaitResult{}, errors.New("boundless output missing journal/seal")
	}

	var journalHex string
	if err := json.Unmarshal(fulfillment.ImageIDAndJournal[1], &journalHex); err != nil {
		return boundlessWaitResult{}, fmt.Errorf("decode fulfillment journal: %w", err)
	}
	journalHex = strings.ToLower(strings.TrimSpace(journalHex))
	if journalHex == "" {
		return boundlessWaitResult{}, errors.New("boundless output missing journal")
	}

	sealMatch := boundlessSealOnlyRegex.FindStringSubmatch(raw)
	if len(sealMatch) < 2 {
		return boundlessWaitResult{}, errors.New("boundless output missing seal")
	}
	sealHex := strings.ToLower(strings.TrimSpace(sealMatch[1]))
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
		applyRetryGasBump(ctx, backend, txAuth, attempt)
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
		applyRetryGasBump(ctx, backend, txAuth, attempt)
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

type gasPriceSuggester interface {
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
}

type gasTipCapSuggester interface {
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
}

func applyRetryGasBump(ctx context.Context, backend any, txAuth *bind.TransactOpts, attempt int) {
	if txAuth == nil || attempt <= 1 {
		return
	}

	multiplier := retryGasMultiplier(attempt)

	gasPriceBase := big.NewInt(defaultRetryGasPriceWei)
	if suggester, ok := backend.(gasPriceSuggester); ok {
		if suggested, err := suggester.SuggestGasPrice(ctx); err == nil && suggested != nil && suggested.Sign() > 0 {
			gasPriceBase = new(big.Int).Set(suggested)
		}
	}
	if txAuth.GasPrice != nil && txAuth.GasPrice.Sign() > 0 && txAuth.GasPrice.Cmp(gasPriceBase) > 0 {
		gasPriceBase = new(big.Int).Set(txAuth.GasPrice)
	}

	if suggester, ok := backend.(gasTipCapSuggester); ok {
		tipBase := big.NewInt(defaultRetryGasTipCapWei)
		if suggested, err := suggester.SuggestGasTipCap(ctx); err == nil && suggested != nil && suggested.Sign() > 0 {
			tipBase = new(big.Int).Set(suggested)
		}
		if txAuth.GasTipCap != nil && txAuth.GasTipCap.Sign() > 0 && txAuth.GasTipCap.Cmp(tipBase) > 0 {
			tipBase = new(big.Int).Set(txAuth.GasTipCap)
		}

		feeCapBase := new(big.Int).Set(gasPriceBase)
		if txAuth.GasFeeCap != nil && txAuth.GasFeeCap.Sign() > 0 && txAuth.GasFeeCap.Cmp(feeCapBase) > 0 {
			feeCapBase = new(big.Int).Set(txAuth.GasFeeCap)
		}
		tipFloor := new(big.Int).Mul(tipBase, big.NewInt(2))
		if feeCapBase.Cmp(tipFloor) < 0 {
			feeCapBase = tipFloor
		}

		txAuth.GasTipCap = new(big.Int).Mul(tipBase, multiplier)
		txAuth.GasFeeCap = new(big.Int).Mul(feeCapBase, multiplier)
		tipMinFee := new(big.Int).Mul(txAuth.GasTipCap, big.NewInt(2))
		if txAuth.GasFeeCap.Cmp(tipMinFee) < 0 {
			txAuth.GasFeeCap = tipMinFee
		}
		txAuth.GasPrice = nil
		return
	}

	txAuth.GasPrice = new(big.Int).Mul(gasPriceBase, multiplier)
	txAuth.GasTipCap = nil
	txAuth.GasFeeCap = nil
}

func retryGasMultiplier(attempt int) *big.Int {
	if attempt <= 1 {
		return big.NewInt(1)
	}
	shift := attempt - 1
	if shift > 6 {
		shift = 6
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(shift))
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

func callBool(ctx context.Context, c *bind.BoundContract, method string, args ...any) (bool, error) {
	var res []any
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, method, args...); err != nil {
		return false, err
	}
	if len(res) != 1 {
		return false, fmt.Errorf("unexpected %s result count: %d", method, len(res))
	}
	v, ok := res[0].(bool)
	if !ok {
		return false, fmt.Errorf("unexpected %s type: %T", method, res[0])
	}
	return v, nil
}

func callWithdrawal(ctx context.Context, bridge *bind.BoundContract, withdrawalID common.Hash) (withdrawalView, error) {
	var res []any
	if err := bridge.Call(&bind.CallOpts{Context: ctx}, &res, "getWithdrawal", withdrawalID); err != nil {
		return withdrawalView{}, err
	}
	if len(res) != 7 {
		return withdrawalView{}, fmt.Errorf("unexpected getWithdrawal result count: %d", len(res))
	}

	requester, ok := res[0].(common.Address)
	if !ok {
		return withdrawalView{}, fmt.Errorf("unexpected getWithdrawal requester type: %T", res[0])
	}

	amount, ok := res[1].(*big.Int)
	if !ok || amount == nil {
		return withdrawalView{}, fmt.Errorf("unexpected getWithdrawal amount type: %T", res[1])
	}

	expiry, err := anyToUint64(res[2])
	if err != nil {
		return withdrawalView{}, fmt.Errorf("decode getWithdrawal expiry: %w", err)
	}
	feeBps, err := anyToUint64(res[3])
	if err != nil {
		return withdrawalView{}, fmt.Errorf("decode getWithdrawal feeBps: %w", err)
	}

	finalized, ok := res[4].(bool)
	if !ok {
		return withdrawalView{}, fmt.Errorf("unexpected getWithdrawal finalized type: %T", res[4])
	}
	refunded, ok := res[5].(bool)
	if !ok {
		return withdrawalView{}, fmt.Errorf("unexpected getWithdrawal refunded type: %T", res[5])
	}
	recipient, ok := res[6].([]byte)
	if !ok {
		return withdrawalView{}, fmt.Errorf("unexpected getWithdrawal recipient type: %T", res[6])
	}

	return withdrawalView{
		Requester: requester,
		Amount:    new(big.Int).Set(amount),
		Expiry:    expiry,
		FeeBps:    feeBps,
		Finalized: finalized,
		Refunded:  refunded,
		Recipient: append([]byte(nil), recipient...),
	}, nil
}

func anyToUint64(v any) (uint64, error) {
	switch x := v.(type) {
	case uint64:
		return x, nil
	case uint32:
		return uint64(x), nil
	case uint16:
		return uint64(x), nil
	case uint8:
		return uint64(x), nil
	case int64:
		if x < 0 {
			return 0, fmt.Errorf("negative int64: %d", x)
		}
		return uint64(x), nil
	case *big.Int:
		if x == nil {
			return 0, nil
		}
		if x.Sign() < 0 {
			return 0, fmt.Errorf("negative big.Int: %s", x.String())
		}
		return x.Uint64(), nil
	default:
		return 0, fmt.Errorf("unsupported type %T", v)
	}
}

func computeFeeBreakdown(amount *big.Int, feeBps uint64, tipBps uint64) feeBreakdown {
	safeAmount := big.NewInt(0)
	if amount != nil {
		safeAmount = new(big.Int).Set(amount)
	}

	fee := new(big.Int).Mul(safeAmount, new(big.Int).SetUint64(feeBps))
	fee.Div(fee, big.NewInt(10_000))

	tip := new(big.Int).Mul(fee, new(big.Int).SetUint64(tipBps))
	tip.Div(tip, big.NewInt(10_000))

	feeToDistributor := new(big.Int).Sub(fee, tip)
	net := new(big.Int).Sub(safeAmount, fee)

	return feeBreakdown{
		Fee:              fee,
		Tip:              tip,
		FeeToDistributor: feeToDistributor,
		Net:              net,
	}
}

func expectedBalanceDeltas(in expectedBalanceDeltaInput) expectedBalanceDelta {
	withdrawAmount := big.NewInt(0)
	if in.WithdrawAmount != nil {
		withdrawAmount = new(big.Int).Set(in.WithdrawAmount)
	}

	deposit := computeFeeBreakdown(in.DepositAmount, in.DepositFeeBps, in.RelayerTipBps)
	withdraw := computeFeeBreakdown(in.WithdrawAmount, in.WithdrawFeeBps, in.RelayerTipBps)

	owner := big.NewInt(0)
	if in.RecipientEqualsOwner {
		owner.Add(owner, deposit.Net)
	}
	owner.Add(owner, deposit.Tip)
	owner.Sub(owner, withdrawAmount)
	owner.Add(owner, withdraw.Tip)

	recipient := big.NewInt(0)
	if !in.RecipientEqualsOwner {
		recipient = new(big.Int).Set(deposit.Net)
	}

	feeDistributor := new(big.Int).Add(deposit.FeeToDistributor, withdraw.FeeToDistributor)
	bridge := big.NewInt(0)

	return expectedBalanceDelta{
		Owner:          owner,
		Recipient:      recipient,
		FeeDistributor: feeDistributor,
		Bridge:         bridge,
	}
}

func normalizeRecipientDeltaActual(raw *big.Int, recipientEqualsOwner bool) *big.Int {
	if recipientEqualsOwner {
		return big.NewInt(0)
	}
	if raw == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(raw)
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
