package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/proverexec"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/queue"
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
	RPCURL                      string
	ChainID                     uint64
	DeployOnly                  bool
	ReuseDeployedContracts      bool
	DeployerKeyHex              string
	OperatorKeyFiles            []string
	OperatorAddresses           []common.Address
	OperatorSignerBin           string
	OperatorSignerEndpoints     []string
	OperatorSignerMaxRespBytes  int
	Threshold                   int
	ContractsOut                string
	DepositAmount               uint64
	WithdrawAmount              uint64
	DepositCheckpointHeight     uint64
	DepositCheckpointBlockHash  common.Hash
	WithdrawCheckpointHeight    uint64
	WithdrawCheckpointBlockHash common.Hash
	DepositFinalOrchardRoot     common.Hash
	WithdrawFinalOrchardRoot    common.Hash
	Recipient                   common.Address
	RecipientSet                bool
	VerifierAddress             common.Address
	VerifierSet                 bool
	ExistingWJunoAddress        common.Address
	ExistingOperatorRegAddress  common.Address
	ExistingFeeDistributor      common.Address
	ExistingBridgeAddress       common.Address
	DepositImageID              common.Hash
	WithdrawImageID             common.Hash
	DepositSeal                 []byte
	WithdrawSeal                []byte
	ProofInputsOut              string
	JunoExecutionTxHash         string
	OutputPath                  string
	RunTimeout                  time.Duration
	SP1                   sp1Config
}

type sp1Config struct {
	Auto bool

	Bin                     string
	RPCURL                  string
	InputMode               string
	DepositOWalletIVKBytes  []byte
	WithdrawOWalletOVKBytes []byte
	DepositWitnessItems     [][]byte
	WithdrawWitnessItems    [][]byte
	MarketAddress           common.Address
	VerifierRouterAddr      common.Address
	SetVerifierAddr         common.Address
	RequestorKeyHex         string
	DepositProgramURL       string
	WithdrawProgramURL      string
	InputS3Bucket           string
	InputS3Prefix           string
	InputS3Region           string
	InputS3PresignTTL       time.Duration

	MaxPricePerPGU   uint64
	MinAuctionPeriod uint64
	AuctionTimeout   time.Duration
	RequestTimeout   time.Duration

	RequestorAddress common.Address

	ProofSubmissionMode string
	ProofQueueBrokers   []string
	ProofRequestTopic   string
	ProofResultTopic    string
	ProofFailureTopic   string
	ProofConsumerGroup  string
	ProofQueueMaxBytes  int
	ProofAckTimeout     time.Duration
	ProofDeadline       time.Duration
}

type sp1WaitResult struct {
	RequestIDHex string
	JournalHex   string
	SealHex      string
}

const (
	defaultDepositImageIDHex  = "0x000000000000000000000000000000000000000000000000000000000000aa01"
	defaultWithdrawImageIDHex = "0x000000000000000000000000000000000000000000000000000000000000aa02"

	defaultSP1MaxPricePerPGU         = uint64(50000000000000)
	defaultSP1MinAuctionPeriod       = uint64(85)
	defaultSP1AuctionTimeout         = 625 * time.Second
	defaultSP1RequestTimeout         = 1500 * time.Second
	defaultSP1MarketAddr             = "0xFd152dADc5183870710FE54f939Eae3aB9F0fE82"
	defaultSP1RouterAddr             = "0x0b144e07a0826182b6b59788c34b32bfa86fb711"
	defaultSP1SetVerAddr             = "0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104"
	defaultSP1InputS3Prefix          = "bridge-e2e/sp1-input"
	defaultSP1InputS3PresignTTL      = 2 * time.Hour
	defaultSP1ProofAttemptGrace      = 2 * time.Minute
	defaultRetryGasPriceWei                = int64(2_000_000_000)
	defaultRetryGasTipCapWei               = int64(500_000_000)

	sp1InputModeGuestWitnessV1  = "guest-witness-v1"
	sp1ProofSubmissionDirectCLI = "direct-cli"
	sp1ProofSubmissionQueue     = "queue"
	defaultProofRequestTopic          = "proof.requests.v1"
	defaultProofResultTopic           = "proof.fulfillments.v1"
	defaultProofFailureTopic          = "proof.failures.v1"
	defaultProofConsumerGroupPrefix   = "bridge-e2e-proof"
	defaultProofQueueMaxBytes         = 10 << 20
	defaultProofAckTimeout            = 5 * time.Second
	defaultProofDeadline              = 15 * time.Minute
	defaultOperatorSignerMaxRespBytes = 1 << 20
	junoProofSourceInputExecutionTx   = "input.juno_execution_tx_hash"
	txMinedWaitTimeout                = 180 * time.Second
	txMinedGraceTimeout               = 240 * time.Second
	deployCodeRecoveryTimeout         = 8 * time.Minute
	deployCodeRecoveryPollInterval    = 5 * time.Second
	withdrawalFinalizedWaitTimeout    = 60 * time.Second
	withdrawalFinalizedPollInterval   = 2 * time.Second
	postFinalizeInvariantWaitTimeout  = 60 * time.Second
	postFinalizeInvariantPollInterval = 2 * time.Second
	sp1MarketBalanceOfABIJSON   = `[{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]`

	depositWitnessLeafIndexOffset = 0
	depositWitnessAuthPathOffset  = depositWitnessLeafIndexOffset + 4
	depositWitnessAuthPathLen     = 32 * 32
	depositWitnessActionOffset    = depositWitnessAuthPathOffset + depositWitnessAuthPathLen
	depositWitnessCMXOffset       = depositWitnessActionOffset + 32 + 32

	withdrawWitnessIDOffset        = 0
	withdrawWitnessIDLen           = 32
	withdrawWitnessRecipientOffset = withdrawWitnessIDOffset + withdrawWitnessIDLen
	withdrawWitnessRecipientRawLen = 43
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
		ExtendWithdraw    string `json:"extend_withdraw"`
		FinalizeWithdraw  string `json:"finalize_withdraw"`
	} `json:"transactions"`

	Juno struct {
		TxHash string `json:"tx_hash"`
		TxID   string `json:"txid"`

		ProofOfExecution struct {
			Available bool   `json:"available"`
			TxHash    string `json:"tx_hash"`
			Source    string `json:"source"`
		} `json:"proof_of_execution"`
	} `json:"juno"`

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
		ProofInputsPath   string `json:"proof_inputs_path,omitempty"`
		DepositImageID    string `json:"deposit_image_id"`
		WithdrawImageID   string `json:"withdraw_image_id"`
		DepositSealBytes  int    `json:"deposit_seal_bytes"`
		WithdrawSealBytes int    `json:"withdraw_seal_bytes"`

		SP1 struct {
			Enabled                bool   `json:"enabled"`
			SubmissionMode         string `json:"submission_mode,omitempty"`
			RPCURL                 string `json:"rpc_url,omitempty"`
			InputMode              string `json:"input_mode,omitempty"`
			MarketAddress          string `json:"market_address,omitempty"`
			VerifierRouter         string `json:"verifier_router_address,omitempty"`
			SetVerifier            string `json:"set_verifier_address,omitempty"`
			DepositRequestID       string `json:"deposit_request_id,omitempty"`
			WithdrawRequestID      string `json:"withdraw_request_id,omitempty"`
			MaxPricePerPGU         uint64 `json:"max_price_per_pgu,omitempty"`
			MinAuctionPeriodSec    uint64 `json:"min_auction_period_seconds,omitempty"`
			AuctionTimeoutSec      uint64 `json:"auction_timeout_seconds,omitempty"`
			RequestTimeoutSec      uint64 `json:"request_timeout_seconds,omitempty"`
		} `json:"sp1,omitempty"`
	} `json:"proof"`

	Invariants struct {
		Registry struct {
			OperatorCount uint64 `json:"operator_count"`
			Threshold     uint64 `json:"threshold"`
			AllActive     bool   `json:"all_active"`
		} `json:"registry"`
		DepositUsed bool `json:"deposit_used"`
		Withdrawal  struct {
			Exists         bool   `json:"exists"`
			Finalized      bool   `json:"finalized"`
			Refunded       bool   `json:"refunded"`
			Extended       bool   `json:"extended"`
			FeeBps         uint64 `json:"fee_bps"`
			Amount         string `json:"amount"`
			Expiry         uint64 `json:"expiry"`
			ExpectedExpiry uint64 `json:"expected_expiry"`
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

	Checkpoint         checkpoint.Checkpoint  `json:"checkpoint"`
	WithdrawCheckpoint *checkpoint.Checkpoint `json:"withdraw_checkpoint,omitempty"`

	OperatorSignatures         []string `json:"operator_signatures"`
	WithdrawOperatorSignatures []string `json:"withdraw_operator_signatures,omitempty"`

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
	var operatorAddressFlags stringListFlag
	var operatorSignerEndpoints stringListFlag
	var recipientHex string
	var verifierAddressHex string
	var depositImageIDHex string
	var withdrawImageIDHex string
	var depositCheckpointBlockHashHex string
	var withdrawCheckpointBlockHashHex string
	var depositFinalOrchardRootHex string
	var withdrawFinalOrchardRootHex string
	var sp1RequestorKeyFile string
	var sp1RequestorKeyHex string
	var sp1DepositOWalletIVKHex string
	var sp1WithdrawOWalletOVKHex string
	var sp1DepositWitnessItemFiles stringListFlag
	var sp1WithdrawWitnessItemFiles stringListFlag
	var sp1InputS3Bucket string
	var sp1InputS3Prefix string
	var sp1InputS3Region string
	var sp1ProofQueueBrokers string
	var existingWJunoAddressHex string
	var existingOperatorRegAddressHex string
	var existingFeeDistributorHex string
	var existingBridgeAddressHex string
	var junoExecutionTxHash string

	filteredArgs, operatorKeyFiles, err := consumeOperatorKeyFileFlags(args)
	if err != nil {
		return cfg, err
	}

	fs := flag.NewFlagSet("bridge-e2e", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.RPCURL, "rpc-url", "", "Base testnet RPC URL")
	fs.Uint64Var(&cfg.ChainID, "chain-id", 0, "Base chain ID")
	fs.StringVar(&deployerKeyFile, "deployer-key-file", "", "file containing deployer private key hex")
	fs.StringVar(&cfg.DeployerKeyHex, "deployer-key-hex", "", "deployer private key hex")
	fs.Var(&operatorAddressFlags, "operator-address", "operator address (repeat; required with --operator-signer-bin)")
	fs.StringVar(&cfg.OperatorSignerBin, "operator-signer-bin", "", "external operator signer binary path (must support `sign-digest --digest <0x..> --json`)")
	fs.Var(&operatorSignerEndpoints, "operator-signer-endpoint", "operator signer endpoint (repeat; forwarded to --operator-signer-bin when set)")
	fs.IntVar(&cfg.OperatorSignerMaxRespBytes, "operator-signer-max-response-bytes", defaultOperatorSignerMaxRespBytes, "maximum bytes allowed in operator signer response")
	fs.IntVar(&cfg.Threshold, "threshold", 3, "operator quorum threshold")
	fs.StringVar(&cfg.ContractsOut, "contracts-out", "contracts/out", "path to foundry build output directory")
	fs.Uint64Var(&cfg.DepositAmount, "deposit-amount", 100_000, "mintBatch item amount (wJUNO base units)")
	fs.Uint64Var(&cfg.WithdrawAmount, "withdraw-amount", 10_000, "request/finalize amount (wJUNO base units)")
	fs.Uint64Var(&cfg.DepositCheckpointHeight, "deposit-checkpoint-height", 0, "Juno checkpoint height used for deposit checkpoint signing")
	fs.StringVar(&depositCheckpointBlockHashHex, "deposit-checkpoint-block-hash", "", "Juno checkpoint block hash for deposit checkpoint signing (bytes32 hex)")
	fs.Uint64Var(&cfg.WithdrawCheckpointHeight, "withdraw-checkpoint-height", 0, "Juno checkpoint height used for withdraw checkpoint signing (defaults to --deposit-checkpoint-height)")
	fs.StringVar(&withdrawCheckpointBlockHashHex, "withdraw-checkpoint-block-hash", "", "Juno checkpoint block hash for withdraw checkpoint signing (bytes32 hex; defaults to --deposit-checkpoint-block-hash)")
	fs.StringVar(&recipientHex, "recipient", "", "optional recipient address for mint (defaults to deployer)")
	fs.StringVar(&verifierAddressHex, "verifier-address", "", "verifier router address (required)")
	fs.StringVar(&depositImageIDHex, "deposit-image-id", defaultDepositImageIDHex, "deposit image ID (bytes32)")
	fs.StringVar(&withdrawImageIDHex, "withdraw-image-id", defaultWithdrawImageIDHex, "withdraw image ID (bytes32)")
	fs.StringVar(&depositFinalOrchardRootHex, "deposit-final-orchard-root", "", "Juno final orchard root for deposit checkpoint (bytes32 hex)")
	fs.StringVar(&withdrawFinalOrchardRootHex, "withdraw-final-orchard-root", "", "Juno final orchard root for withdraw checkpoint (bytes32 hex; defaults to --deposit-final-orchard-root)")
	fs.StringVar(&cfg.ProofInputsOut, "proof-inputs-output", "", "optional path to write proof input artifact bundle")
	fs.StringVar(&junoExecutionTxHash, "juno-execution-tx-hash", "", "canonical Juno execution tx hash to report under juno.proof_of_execution")
	fs.StringVar(&cfg.OutputPath, "output", "-", "output report path or '-' for stdout")
	fs.DurationVar(&cfg.RunTimeout, "run-timeout", 8*time.Minute, "overall command timeout (e.g. 8m, 90m)")
	fs.BoolVar(&cfg.DeployOnly, "deploy-only", false, "deploy/configure contracts only; skip deposit/withdraw/finalize flow")
	fs.StringVar(&existingWJunoAddressHex, "existing-wjuno-address", "", "reuse predeployed WJuno contract address (requires all --existing-*-address flags)")
	fs.StringVar(&existingOperatorRegAddressHex, "existing-operator-registry-address", "", "reuse predeployed OperatorRegistry contract address (requires all --existing-*-address flags)")
	fs.StringVar(&existingFeeDistributorHex, "existing-fee-distributor-address", "", "reuse predeployed FeeDistributor contract address (requires all --existing-*-address flags)")
	fs.StringVar(&existingBridgeAddressHex, "existing-bridge-address", "", "reuse predeployed Bridge contract address (requires all --existing-*-address flags)")

	fs.BoolVar(&cfg.SP1.Auto, "sp1-auto", false, "automatically submit/wait proofs via SP1 and use returned seals")
	fs.StringVar(&cfg.SP1.Bin, "sp1-bin", "sp1", "SP1 CLI binary path used by --sp1-auto")
	fs.StringVar(&cfg.SP1.RPCURL, "sp1-rpc-url", "https://mainnet.base.org", "SP1 submission RPC URL")
	fs.StringVar(&cfg.SP1.InputMode, "sp1-input-mode", sp1InputModeGuestWitnessV1, "SP1 input mode (required): guest-witness-v1")
	var sp1MarketAddressHex string
	var sp1VerifierRouterHex string
	var sp1SetVerifierHex string
	fs.StringVar(&sp1MarketAddressHex, "sp1-market-address", defaultSP1MarketAddr, "SP1 market contract address")
	fs.StringVar(&sp1VerifierRouterHex, "sp1-verifier-router-address", defaultSP1RouterAddr, "SP1 verifier router contract address")
	fs.StringVar(&sp1SetVerifierHex, "sp1-set-verifier-address", defaultSP1SetVerAddr, "SP1 set verifier contract address")
	fs.StringVar(&sp1RequestorKeyFile, "sp1-requestor-key-file", "", "file containing requestor private key hex for SP1")
	fs.StringVar(&sp1RequestorKeyHex, "sp1-requestor-key-hex", "", "requestor private key hex for SP1")
	fs.StringVar(&sp1DepositOWalletIVKHex, "sp1-deposit-owallet-ivk-hex", "", "64-byte oWallet IVK hex for guest-witness-v1 deposit input mode")
	fs.StringVar(&sp1WithdrawOWalletOVKHex, "sp1-withdraw-owallet-ovk-hex", "", "32-byte oWallet OVK hex for guest-witness-v1 withdraw input mode")
	fs.Var(&sp1DepositWitnessItemFiles, "sp1-deposit-witness-item-file", "deposit guest witness item file path (repeat for guest-witness-v1)")
	fs.Var(&sp1WithdrawWitnessItemFiles, "sp1-withdraw-witness-item-file", "withdraw guest witness item file path (repeat for guest-witness-v1)")
	fs.StringVar(&cfg.SP1.DepositProgramURL, "sp1-deposit-program-url", "", "deposit guest program URL for SP1 proof requests")
	fs.StringVar(&cfg.SP1.WithdrawProgramURL, "sp1-withdraw-program-url", "", "withdraw guest program URL for SP1 proof requests")
	fs.StringVar(&sp1InputS3Bucket, "sp1-input-s3-bucket", "", "S3 bucket used for oversized sp1 private inputs (>2048 bytes)")
	fs.StringVar(&sp1InputS3Prefix, "sp1-input-s3-prefix", defaultSP1InputS3Prefix, "S3 key prefix used for oversized sp1 private inputs")
	fs.StringVar(&sp1InputS3Region, "sp1-input-s3-region", "", "optional AWS region override for sp1 oversized input uploads")
	fs.DurationVar(&cfg.SP1.InputS3PresignTTL, "sp1-input-s3-presign-ttl", defaultSP1InputS3PresignTTL, "presigned URL TTL for oversized sp1 private inputs")
	fs.Uint64Var(&cfg.SP1.MaxPricePerPGU, "sp1-max-price-per-pgu", defaultSP1MaxPricePerPGU, "SP1 max price per PGU (wei)")
	fs.Uint64Var(&cfg.SP1.MinAuctionPeriod, "sp1-min-auction-period", defaultSP1MinAuctionPeriod, "SP1 minimum auction period in seconds")
	fs.DurationVar(&cfg.SP1.AuctionTimeout, "sp1-auction-timeout", defaultSP1AuctionTimeout, "SP1 auction timeout duration")
	fs.DurationVar(&cfg.SP1.RequestTimeout, "sp1-request-timeout", defaultSP1RequestTimeout, "SP1 request timeout duration")
	fs.StringVar(&cfg.SP1.ProofSubmissionMode, "sp1-proof-submission-mode", sp1ProofSubmissionDirectCLI, "proof submission mode: direct-cli|queue")
	fs.StringVar(&sp1ProofQueueBrokers, "sp1-proof-queue-brokers", "", "comma-separated Kafka brokers used by centralized proof-requestor")
	fs.StringVar(&cfg.SP1.ProofRequestTopic, "sp1-proof-request-topic", defaultProofRequestTopic, "Kafka proof request topic")
	fs.StringVar(&cfg.SP1.ProofResultTopic, "sp1-proof-result-topic", defaultProofResultTopic, "Kafka proof fulfillment topic")
	fs.StringVar(&cfg.SP1.ProofFailureTopic, "sp1-proof-failure-topic", defaultProofFailureTopic, "Kafka proof failure topic")
	fs.StringVar(&cfg.SP1.ProofConsumerGroup, "sp1-proof-consumer-group", "", "Kafka consumer group used by bridge-e2e for proof results/failures")
	fs.IntVar(&cfg.SP1.ProofQueueMaxBytes, "sp1-proof-queue-max-bytes", defaultProofQueueMaxBytes, "max Kafka message size for proof queue consumer")
	fs.DurationVar(&cfg.SP1.ProofAckTimeout, "sp1-proof-ack-timeout", defaultProofAckTimeout, "proof queue ack timeout")
	fs.DurationVar(&cfg.SP1.ProofDeadline, "sp1-proof-deadline", defaultProofDeadline, "default deadline passed to centralized proof-requestor")

	if err := fs.Parse(filteredArgs); err != nil {
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
	cfg.JunoExecutionTxHash = strings.TrimSpace(junoExecutionTxHash)

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
	cfg.OperatorSignerBin = strings.TrimSpace(cfg.OperatorSignerBin)
	cfg.OperatorSignerEndpoints = append(cfg.OperatorSignerEndpoints, operatorSignerEndpoints...)
	if cfg.OperatorSignerMaxRespBytes <= 0 {
		return cfg, errors.New("--operator-signer-max-response-bytes must be > 0")
	}

	cfg.OperatorAddresses = make([]common.Address, 0, len(operatorAddressFlags))
	seenOperators := make(map[common.Address]struct{}, len(operatorAddressFlags))
	for _, rawAddr := range operatorAddressFlags {
		if !common.IsHexAddress(rawAddr) {
			return cfg, fmt.Errorf("--operator-address must be a valid hex address: %q", rawAddr)
		}
		op := common.HexToAddress(rawAddr)
		if _, exists := seenOperators[op]; exists {
			return cfg, fmt.Errorf("duplicate --operator-address: %s", op.Hex())
		}
		seenOperators[op] = struct{}{}
		cfg.OperatorAddresses = append(cfg.OperatorAddresses, op)
	}

	if cfg.OperatorSignerBin != "" {
		if len(cfg.OperatorAddresses) < cfg.Threshold {
			return cfg, fmt.Errorf("need at least %d operator addresses (--operator-address), got %d", cfg.Threshold, len(cfg.OperatorAddresses))
		}
	} else if len(cfg.OperatorKeyFiles) < cfg.Threshold {
		return cfg, fmt.Errorf("need at least %d operator keys, got %d", cfg.Threshold, len(cfg.OperatorKeyFiles))
	}
	if len(cfg.OperatorAddresses) > 0 && len(cfg.OperatorAddresses) < cfg.Threshold {
		return cfg, fmt.Errorf("need at least %d operator addresses (--operator-address), got %d", cfg.Threshold, len(cfg.OperatorAddresses))
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
	existingContractFlags := []struct {
		flagName string
		raw      string
		out      *common.Address
	}{
		{
			flagName: "--existing-wjuno-address",
			raw:      existingWJunoAddressHex,
			out:      &cfg.ExistingWJunoAddress,
		},
		{
			flagName: "--existing-operator-registry-address",
			raw:      existingOperatorRegAddressHex,
			out:      &cfg.ExistingOperatorRegAddress,
		},
		{
			flagName: "--existing-fee-distributor-address",
			raw:      existingFeeDistributorHex,
			out:      &cfg.ExistingFeeDistributor,
		},
		{
			flagName: "--existing-bridge-address",
			raw:      existingBridgeAddressHex,
			out:      &cfg.ExistingBridgeAddress,
		},
	}
	providedExistingContractFlags := 0
	for _, contractFlag := range existingContractFlags {
		if strings.TrimSpace(contractFlag.raw) != "" {
			providedExistingContractFlags++
		}
	}
	if providedExistingContractFlags != 0 && providedExistingContractFlags != len(existingContractFlags) {
		return cfg, errors.New("all existing contract address flags must be set together: --existing-wjuno-address, --existing-operator-registry-address, --existing-fee-distributor-address, --existing-bridge-address")
	}
	if providedExistingContractFlags == len(existingContractFlags) {
		for _, contractFlag := range existingContractFlags {
			if !common.IsHexAddress(contractFlag.raw) {
				return cfg, fmt.Errorf("%s must be a valid hex address", contractFlag.flagName)
			}
			*contractFlag.out = common.HexToAddress(contractFlag.raw)
		}
		cfg.ReuseDeployedContracts = true
	}

	cfg.DepositImageID, err = parseHash32Flag("--deposit-image-id", depositImageIDHex)
	if err != nil {
		return cfg, err
	}
	cfg.WithdrawImageID, err = parseHash32Flag("--withdraw-image-id", withdrawImageIDHex)
	if err != nil {
		return cfg, err
	}

	if sp1RequestorKeyFile != "" && sp1RequestorKeyHex != "" {
		return cfg, errors.New("use only one of --sp1-requestor-key-file or --sp1-requestor-key-hex")
	}
	if sp1RequestorKeyFile != "" {
		keyBytes, err := os.ReadFile(sp1RequestorKeyFile)
		if err != nil {
			return cfg, fmt.Errorf("read sp1 requestor key file: %w", err)
		}
		sp1RequestorKeyHex = strings.TrimSpace(string(keyBytes))
	}
	cfg.SP1.InputMode, err = parseSP1InputMode(cfg.SP1.InputMode)
	if err != nil {
		return cfg, err
	}
	cfg.SP1.ProofSubmissionMode, err = parseSP1ProofSubmissionMode(cfg.SP1.ProofSubmissionMode)
	if err != nil {
		return cfg, err
	}
	cfg.SP1.ProofQueueBrokers = queue.SplitCommaList(sp1ProofQueueBrokers)
	if !common.IsHexAddress(sp1MarketAddressHex) {
		return cfg, errors.New("--sp1-market-address must be a valid hex address")
	}
	cfg.SP1.MarketAddress = common.HexToAddress(sp1MarketAddressHex)
	if !common.IsHexAddress(sp1VerifierRouterHex) {
		return cfg, errors.New("--sp1-verifier-router-address must be a valid hex address")
	}
	cfg.SP1.VerifierRouterAddr = common.HexToAddress(sp1VerifierRouterHex)
	if !common.IsHexAddress(sp1SetVerifierHex) {
		return cfg, errors.New("--sp1-set-verifier-address must be a valid hex address")
	}
	cfg.SP1.SetVerifierAddr = common.HexToAddress(sp1SetVerifierHex)
	cfg.SP1.RequestorKeyHex = strings.TrimSpace(sp1RequestorKeyHex)
	if cfg.SP1.RequestorKeyHex != "" {
		sp1Key, err := parsePrivateKeyHex(cfg.SP1.RequestorKeyHex)
		if err != nil {
			return cfg, fmt.Errorf("parse --sp1-requestor-key-*: %w", err)
		}
		cfg.SP1.RequestorAddress = crypto.PubkeyToAddress(sp1Key.PublicKey)
	}
	cfg.SP1.InputS3Bucket = strings.TrimSpace(sp1InputS3Bucket)
	cfg.SP1.InputS3Prefix = strings.Trim(strings.TrimSpace(sp1InputS3Prefix), "/")
	cfg.SP1.InputS3Region = strings.TrimSpace(sp1InputS3Region)
	if cfg.SP1.InputS3Prefix == "" {
		cfg.SP1.InputS3Prefix = defaultSP1InputS3Prefix
	}
	if cfg.SP1.InputS3PresignTTL <= 0 {
		return cfg, errors.New("--sp1-input-s3-presign-ttl must be > 0")
	}
	if cfg.SP1.MaxPricePerPGU == 0 {
		return cfg, errors.New("--sp1-max-price-per-pgu must be > 0")
	}
	if cfg.SP1.MinAuctionPeriod == 0 {
		return cfg, errors.New("--sp1-min-auction-period must be > 0")
	}
	if cfg.SP1.AuctionTimeout <= 0 {
		return cfg, errors.New("--sp1-auction-timeout must be > 0")
	}
	if cfg.SP1.RequestTimeout <= 0 {
		return cfg, errors.New("--sp1-request-timeout must be > 0")
	}
	if cfg.SP1.ProofQueueMaxBytes <= 0 {
		return cfg, errors.New("--sp1-proof-queue-max-bytes must be > 0")
	}
	if cfg.SP1.ProofAckTimeout <= 0 {
		return cfg, errors.New("--sp1-proof-ack-timeout must be > 0")
	}
	if cfg.SP1.ProofDeadline <= 0 {
		return cfg, errors.New("--sp1-proof-deadline must be > 0")
	}
	if cfg.SP1.ProofSubmissionMode == sp1ProofSubmissionQueue {
		if len(cfg.SP1.ProofQueueBrokers) == 0 {
			return cfg, errors.New("--sp1-proof-queue-brokers is required when --sp1-proof-submission-mode=queue")
		}
		if strings.TrimSpace(cfg.SP1.ProofRequestTopic) == "" {
			return cfg, errors.New("--sp1-proof-request-topic is required when --sp1-proof-submission-mode=queue")
		}
		if strings.TrimSpace(cfg.SP1.ProofResultTopic) == "" {
			return cfg, errors.New("--sp1-proof-result-topic is required when --sp1-proof-submission-mode=queue")
		}
		if strings.TrimSpace(cfg.SP1.ProofFailureTopic) == "" {
			return cfg, errors.New("--sp1-proof-failure-topic is required when --sp1-proof-submission-mode=queue")
		}
	}
	if !cfg.VerifierSet {
		return cfg, errors.New("--verifier-address is required")
	}
	if !cfg.SP1.Auto {
		return cfg, errors.New("--sp1-auto is required")
	}
	if strings.TrimSpace(cfg.SP1.Bin) == "" {
		return cfg, errors.New("--sp1-bin is required when --sp1-auto is set")
	}
	if strings.TrimSpace(cfg.SP1.RPCURL) == "" {
		return cfg, errors.New("--sp1-rpc-url is required when --sp1-auto is set")
	}
	if cfg.SP1.ProofSubmissionMode == sp1ProofSubmissionDirectCLI &&
		strings.TrimSpace(cfg.SP1.RequestorKeyHex) == "" {
		return cfg, errors.New("--sp1-requestor-key-file or --sp1-requestor-key-hex is required when --sp1-auto is set")
	}
	if strings.TrimSpace(cfg.SP1.DepositProgramURL) == "" {
		return cfg, errors.New("--sp1-deposit-program-url is required when --sp1-auto is set")
	}
	if strings.TrimSpace(cfg.SP1.WithdrawProgramURL) == "" {
		return cfg, errors.New("--sp1-withdraw-program-url is required when --sp1-auto is set")
	}
	if cfg.SP1.InputS3Bucket == "" {
		return cfg, errors.New("--sp1-input-s3-bucket is required when --sp1-input-mode guest-witness-v1")
	}
	manualIVKSet := strings.TrimSpace(sp1DepositOWalletIVKHex) != ""
	manualOVKSet := strings.TrimSpace(sp1WithdrawOWalletOVKHex) != ""
	manualDepositItemsSet := len(sp1DepositWitnessItemFiles) > 0
	manualWithdrawItemsSet := len(sp1WithdrawWitnessItemFiles) > 0
	manualAny := manualIVKSet || manualOVKSet || manualDepositItemsSet || manualWithdrawItemsSet
	manualAll := manualIVKSet && manualOVKSet && manualDepositItemsSet && manualWithdrawItemsSet

	if manualAny && !manualAll {
		return cfg, errors.New("all guest witness manual inputs must be set together: --sp1-deposit-owallet-ivk-hex, --sp1-withdraw-owallet-ovk-hex, --sp1-deposit-witness-item-file, --sp1-withdraw-witness-item-file")
	}
	if !manualAll && !cfg.DeployOnly {
		return cfg, errors.New("guest witness auto generation is disabled; provide --sp1-deposit-owallet-ivk-hex, --sp1-withdraw-owallet-ovk-hex, --sp1-deposit-witness-item-file, and --sp1-withdraw-witness-item-file")
	}
	if manualAll {
		cfg.SP1.DepositOWalletIVKBytes, err = parseHexFixedLength(
			"--sp1-deposit-owallet-ivk-hex",
			sp1DepositOWalletIVKHex,
			64,
		)
		if err != nil {
			return cfg, err
		}
		cfg.SP1.WithdrawOWalletOVKBytes, err = parseHexFixedLength(
			"--sp1-withdraw-owallet-ovk-hex",
			sp1WithdrawOWalletOVKHex,
			32,
		)
		if err != nil {
			return cfg, err
		}
		cfg.SP1.DepositWitnessItems, err = readWitnessItemsFromFiles(
			"--sp1-deposit-witness-item-file",
			sp1DepositWitnessItemFiles,
			proverinput.DepositWitnessItemLen,
		)
		if err != nil {
			return cfg, err
		}
		cfg.SP1.WithdrawWitnessItems, err = readWitnessItemsFromFiles(
			"--sp1-withdraw-witness-item-file",
			sp1WithdrawWitnessItemFiles,
			proverinput.WithdrawWitnessItemLen,
		)
		if err != nil {
			return cfg, err
		}
	}
	if strings.TrimSpace(depositFinalOrchardRootHex) == "" {
		return cfg, errors.New("--deposit-final-orchard-root is required")
	}
	cfg.DepositFinalOrchardRoot, err = parseHash32Flag("--deposit-final-orchard-root", depositFinalOrchardRootHex)
	if err != nil {
		return cfg, err
	}
	if strings.TrimSpace(withdrawFinalOrchardRootHex) == "" {
		cfg.WithdrawFinalOrchardRoot = cfg.DepositFinalOrchardRoot
	} else {
		cfg.WithdrawFinalOrchardRoot, err = parseHash32Flag("--withdraw-final-orchard-root", withdrawFinalOrchardRootHex)
		if err != nil {
			return cfg, err
		}
	}
	if cfg.DepositCheckpointHeight == 0 {
		return cfg, errors.New("--deposit-checkpoint-height is required and must be > 0")
	}
	if strings.TrimSpace(depositCheckpointBlockHashHex) == "" {
		return cfg, errors.New("--deposit-checkpoint-block-hash is required")
	}
	cfg.DepositCheckpointBlockHash, err = parseHash32Flag("--deposit-checkpoint-block-hash", depositCheckpointBlockHashHex)
	if err != nil {
		return cfg, err
	}
	withdrawCheckpointHeightSet := cfg.WithdrawCheckpointHeight != 0
	withdrawCheckpointHashSet := strings.TrimSpace(withdrawCheckpointBlockHashHex) != ""
	if withdrawCheckpointHeightSet != withdrawCheckpointHashSet {
		return cfg, errors.New("--withdraw-checkpoint-height and --withdraw-checkpoint-block-hash must be set together")
	}
	if !withdrawCheckpointHeightSet {
		cfg.WithdrawCheckpointHeight = cfg.DepositCheckpointHeight
		cfg.WithdrawCheckpointBlockHash = cfg.DepositCheckpointBlockHash
	} else {
		cfg.WithdrawCheckpointBlockHash, err = parseHash32Flag("--withdraw-checkpoint-block-hash", withdrawCheckpointBlockHashHex)
		if err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

func consumeOperatorKeyFileFlags(args []string) ([]string, []string, error) {
	remaining := make([]string, 0, len(args))
	keyFiles := make([]string, 0)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--operator-key-file":
			if i+1 >= len(args) {
				return nil, nil, errors.New("missing value for --operator-key-file")
			}
			keyFiles = append(keyFiles, args[i+1])
			i++
		case strings.HasPrefix(arg, "--operator-key-file="):
			value := strings.TrimPrefix(arg, "--operator-key-file=")
			if strings.TrimSpace(value) == "" {
				return nil, nil, errors.New("missing value for --operator-key-file")
			}
			keyFiles = append(keyFiles, value)
		default:
			remaining = append(remaining, arg)
		}
	}

	return remaining, keyFiles, nil
}

func parseSP1InputMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "", sp1InputModeGuestWitnessV1:
		return sp1InputModeGuestWitnessV1, nil
	default:
		return "", errors.New("--sp1-input-mode must be guest-witness-v1")
	}
}

func parseSP1ProofSubmissionMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "", sp1ProofSubmissionDirectCLI:
		return sp1ProofSubmissionDirectCLI, nil
	case sp1ProofSubmissionQueue:
		return sp1ProofSubmissionQueue, nil
	default:
		return "", errors.New("--sp1-proof-submission-mode must be one of: direct-cli, queue")
	}
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

func parseHexFixedLength(flagName, raw string, wantLen int) ([]byte, error) {
	out, err := parseHexBytesFlag(flagName, raw)
	if err != nil {
		return nil, err
	}
	if len(out) != wantLen {
		return nil, fmt.Errorf("%s must be %d bytes hex", flagName, wantLen)
	}
	return out, nil
}

func readWitnessItemsFromFiles(flagName string, files []string, wantLen int) ([][]byte, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("%s requires at least one file", flagName)
	}

	out := make([][]byte, 0, len(files))
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s %q: %w", flagName, path, err)
		}
		if len(b) != wantLen {
			return nil, fmt.Errorf("%s %q has len %d, want %d", flagName, path, len(b), wantLen)
		}
		out = append(out, append([]byte(nil), b...))
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

type withdrawWitnessIdentity struct {
	WithdrawalID common.Hash
	RecipientUA  []byte
}

func deriveDepositIDFromWitnessItem(item []byte) (common.Hash, error) {
	if len(item) != proverinput.DepositWitnessItemLen {
		return common.Hash{}, fmt.Errorf("deposit witness item len mismatch: got=%d want=%d", len(item), proverinput.DepositWitnessItemLen)
	}
	leafIndex := binary.LittleEndian.Uint32(item[depositWitnessLeafIndexOffset : depositWitnessLeafIndexOffset+4])
	var cm [32]byte
	copy(cm[:], item[depositWitnessCMXOffset:depositWitnessCMXOffset+32])
	depositID := idempotency.DepositIDV1(cm, uint64(leafIndex))
	return common.Hash(depositID), nil
}

func parseWithdrawWitnessIdentity(item []byte) (withdrawWitnessIdentity, error) {
	if len(item) != proverinput.WithdrawWitnessItemLen {
		return withdrawWitnessIdentity{}, fmt.Errorf("withdraw witness item len mismatch: got=%d want=%d", len(item), proverinput.WithdrawWitnessItemLen)
	}
	withdrawalID := common.BytesToHash(item[withdrawWitnessIDOffset : withdrawWitnessIDOffset+withdrawWitnessIDLen])
	recipientUA := append([]byte(nil), item[withdrawWitnessRecipientOffset:withdrawWitnessRecipientOffset+withdrawWitnessRecipientRawLen]...)
	return withdrawWitnessIdentity{
		WithdrawalID: withdrawalID,
		RecipientUA:  recipientUA,
	}, nil
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
	cfg.OperatorSignerBin = strings.TrimSpace(cfg.OperatorSignerBin)
	if cfg.OperatorSignerBin == "" {
		return nil, errors.New("--operator-signer-bin is required")
	}

	logProgress("start chain_id=%d rpc=%s", cfg.ChainID, cfg.RPCURL)
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
	logProgress("deployer=%s start_nonce=%d", owner.Hex(), startNonce)

	var (
		operatorAddrs []common.Address
		digestSigner  operatorDigestSigner
	)
	operatorAddrs = append(operatorAddrs, cfg.OperatorAddresses...)
	signer, err := newExecOperatorDigestSigner(
		cfg.OperatorSignerBin,
		cfg.OperatorSignerEndpoints,
		cfg.OperatorSignerMaxRespBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("configure operator signer: %w", err)
	}
	digestSigner = signer
	if len(operatorAddrs) < cfg.Threshold {
		return nil, fmt.Errorf("operator set smaller than threshold: operators=%d threshold=%d", len(operatorAddrs), cfg.Threshold)
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
	depositImageID := cfg.DepositImageID
	withdrawImageID := cfg.WithdrawImageID
	const feeBps uint64 = 50
	const tipBps uint64 = 1000
	const refundWindowSeconds uint64 = 24 * 60 * 60
	const maxExtendSeconds uint64 = 12 * 60 * 60

	var wjunoAddr common.Address
	var regAddr common.Address
	var fdAddr common.Address
	var bridgeAddr common.Address
	var setFeeDistributorTx common.Hash
	var setThresholdTx common.Hash
	var setBridgeWJunoTx common.Hash
	var setBridgeFeesTx common.Hash

	if cfg.ReuseDeployedContracts {
		wjunoAddr = cfg.ExistingWJunoAddress
		regAddr = cfg.ExistingOperatorRegAddress
		fdAddr = cfg.ExistingFeeDistributor
		bridgeAddr = cfg.ExistingBridgeAddress
		logProgress("reusing deployed wjuno=%s", wjunoAddr.Hex())
		logProgress("reusing deployed operator_registry=%s", regAddr.Hex())
		logProgress("reusing deployed fee_distributor=%s", fdAddr.Hex())
		logProgress("reusing deployed bridge=%s", bridgeAddr.Hex())
	} else {
		wjunoAddr, _, err = deployContract(ctx, client, auth, wjunoABI, wjunoBin, owner)
		if err != nil {
			return nil, fmt.Errorf("deploy wjuno: %w", err)
		}
		logProgress("deployed wjuno=%s", wjunoAddr.Hex())
		regAddr, _, err = deployContract(ctx, client, auth, regABI, regBin, owner)
		if err != nil {
			return nil, fmt.Errorf("deploy operator registry: %w", err)
		}
		logProgress("deployed operator_registry=%s", regAddr.Hex())
		fdAddr, _, err = deployContract(ctx, client, auth, fdABI, fdBin, owner, wjunoAddr, regAddr)
		if err != nil {
			return nil, fmt.Errorf("deploy fee distributor: %w", err)
		}
		logProgress("deployed fee_distributor=%s", fdAddr.Hex())

		bridgeAddr, _, err = deployContract(
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
		logProgress("deployed bridge=%s", bridgeAddr.Hex())
	}

	reg := bind.NewBoundContract(regAddr, regABI, client, client, client)
	fd := bind.NewBoundContract(fdAddr, fdABI, client, client, client)
	wjuno := bind.NewBoundContract(wjunoAddr, wjunoABI, client, client, client)
	bridge := bind.NewBoundContract(bridgeAddr, bridgeABI, client, client, client)

	if cfg.ReuseDeployedContracts {
		if err := validateReusedBridgeConfig(ctx, bridge, verifierAddr, depositImageID, withdrawImageID); err != nil {
			return nil, err
		}
	}

	if !cfg.ReuseDeployedContracts {
		setFeeDistributorTx, err = transactAndWait(ctx, client, auth, reg, "setFeeDistributor", fdAddr)
		if err != nil {
			return nil, fmt.Errorf("setFeeDistributor: %w", err)
		}

		for _, op := range operatorAddrs {
			if _, err := transactAndWait(ctx, client, auth, reg, "setOperator", op, op, big.NewInt(1), true); err != nil {
				return nil, fmt.Errorf("setOperator(%s): %w", op.Hex(), err)
			}
		}

		setThresholdTx, err = transactAndWait(ctx, client, auth, reg, "setThreshold", big.NewInt(int64(cfg.Threshold)))
		if err != nil {
			return nil, fmt.Errorf("setThreshold: %w", err)
		}

		setBridgeWJunoTx, err = transactAndWait(ctx, client, auth, wjuno, "setBridge", bridgeAddr)
		if err != nil {
			return nil, fmt.Errorf("wjuno.setBridge: %w", err)
		}
		setBridgeFeesTx, err = transactAndWait(ctx, client, auth, fd, "setBridge", bridgeAddr)
		if err != nil {
			return nil, fmt.Errorf("feeDistributor.setBridge: %w", err)
		}
		logProgress("setBridge tx=%s", setBridgeFeesTx.Hex())
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
	if cfg.DeployOnly {
		rep := &report{
			GeneratedAtUTC: time.Now().UTC().Format(time.RFC3339),
			RPCURL:         cfg.RPCURL,
			ChainID:        cfg.ChainID,
			OwnerAddress:   owner.Hex(),
			Recipient:      recipient.Hex(),
			Operators:      make([]string, 0, len(operatorAddrs)),
			Threshold:      cfg.Threshold,
		}
		rep.Contracts.Verifier = verifierAddr.Hex()
		rep.Contracts.WJuno = wjunoAddr.Hex()
		rep.Contracts.OperatorRegistry = regAddr.Hex()
		rep.Contracts.FeeDistributor = fdAddr.Hex()
		rep.Contracts.Bridge = bridgeAddr.Hex()
		rep.Checkpoint.Height = cfg.DepositCheckpointHeight
		rep.Checkpoint.BlockHash = cfg.DepositCheckpointBlockHash.Hex()
		rep.Checkpoint.FinalOrchardRoot = cfg.DepositFinalOrchardRoot.Hex()
		if setFeeDistributorTx != (common.Hash{}) {
			rep.Transactions.SetFeeDistributor = setFeeDistributorTx.Hex()
		}
		if setThresholdTx != (common.Hash{}) {
			rep.Transactions.SetThreshold = setThresholdTx.Hex()
		}
		if setBridgeWJunoTx != (common.Hash{}) {
			rep.Transactions.SetBridgeWJuno = setBridgeWJunoTx.Hex()
		}
		if setBridgeFeesTx != (common.Hash{}) {
			rep.Transactions.SetBridgeFees = setBridgeFeesTx.Hex()
		}
		rep.Proof.DepositImageID = cfg.DepositImageID.Hex()
		rep.Proof.WithdrawImageID = cfg.WithdrawImageID.Hex()
		rep.Proof.SP1.Enabled = cfg.SP1.Auto
		rep.Proof.SP1.SubmissionMode = cfg.SP1.ProofSubmissionMode
		rep.Proof.SP1.RPCURL = cfg.SP1.RPCURL
		rep.Proof.SP1.InputMode = cfg.SP1.InputMode
		rep.Proof.SP1.MarketAddress = cfg.SP1.MarketAddress.Hex()
		rep.Proof.SP1.VerifierRouter = cfg.SP1.VerifierRouterAddr.Hex()
		rep.Proof.SP1.SetVerifier = cfg.SP1.SetVerifierAddr.Hex()
		for _, op := range operatorAddrs {
			rep.Operators = append(rep.Operators, op.Hex())
		}
		if cfg.JunoExecutionTxHash != "" {
			rep.Juno.TxHash = cfg.JunoExecutionTxHash
			rep.Juno.ProofOfExecution.Available = true
			rep.Juno.ProofOfExecution.TxHash = cfg.JunoExecutionTxHash
			rep.Juno.ProofOfExecution.Source = junoProofSourceInputExecutionTx
		}
		logProgress("deploy-only mode completed bridge=%s", bridgeAddr.Hex())
		return rep, nil
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
	if len(cfg.SP1.DepositWitnessItems) == 0 {
		return nil, errors.New("missing deposit witness items")
	}
	if len(cfg.SP1.WithdrawWitnessItems) == 0 {
		return nil, errors.New("missing withdraw witness items")
	}
	depositID, err := deriveDepositIDFromWitnessItem(cfg.SP1.DepositWitnessItems[0])
	if err != nil {
		return nil, fmt.Errorf("derive deposit id from witness: %w", err)
	}
	withdrawWitnessIdentity, err := parseWithdrawWitnessIdentity(cfg.SP1.WithdrawWitnessItems[0])
	if err != nil {
		return nil, fmt.Errorf("parse withdraw witness identity: %w", err)
	}
	recipientUA := withdrawWitnessIdentity.RecipientUA

	type checkpointABI struct {
		Height           uint64
		BlockHash        common.Hash
		FinalOrchardRoot common.Hash
		BaseChainId      *big.Int
		BridgeContract   common.Address
	}
	toCheckpointABI := func(cp checkpoint.Checkpoint) checkpointABI {
		return checkpointABI{
			Height:           cp.Height,
			BlockHash:        cp.BlockHash,
			FinalOrchardRoot: cp.FinalOrchardRoot,
			BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
			BridgeContract:   cp.BridgeContract,
		}
	}

	depositAmount := new(big.Int).SetUint64(cfg.DepositAmount)
	depositFees := computeFeeBreakdown(depositAmount, feeBpsOnChain, relayerTipBpsOnChain)
	withdrawAmount := new(big.Int).SetUint64(cfg.WithdrawAmount)

	cpDeposit := checkpoint.Checkpoint{
		Height:           cfg.DepositCheckpointHeight,
		BlockHash:        cfg.DepositCheckpointBlockHash,
		FinalOrchardRoot: cfg.DepositFinalOrchardRoot,
		BaseChainID:      cfg.ChainID,
		BridgeContract:   bridgeAddr,
	}
	cpWithdraw := checkpoint.Checkpoint{
		Height:           cfg.WithdrawCheckpointHeight,
		BlockHash:        cfg.WithdrawCheckpointBlockHash,
		FinalOrchardRoot: cfg.WithdrawFinalOrchardRoot,
		BaseChainID:      cfg.ChainID,
		BridgeContract:   bridgeAddr,
	}

	nonceBefore, err := callUint64(ctx, bridge, "withdrawNonce")
	if err != nil {
		return nil, fmt.Errorf("withdrawNonce: %w", err)
	}

	depositDigest := checkpoint.Digest(cpDeposit)
	cpDepositSigs, err := signDigestQuorum(ctx, digestSigner, depositDigest, operatorAddrs, cfg.Threshold)
	if err != nil {
		return nil, fmt.Errorf("sign deposit checkpoint digest: %w", err)
	}
	cpDepositABI := toCheckpointABI(cpDeposit)

	mintItems := []bridgeabi.MintItem{
		{
			DepositId: depositID,
			Recipient: recipient,
			Amount:    depositAmount,
		},
	}
	depositJournal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: cpDeposit.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cpDeposit.BaseChainID),
		BridgeContract:   cpDeposit.BridgeContract,
		Items:            mintItems,
	})
	if err != nil {
		return nil, fmt.Errorf("encode deposit journal: %w", err)
	}
	depositPrivateInput, err := proverinput.EncodeDepositPrivateInputV1(cpDeposit, cpDepositSigs, mintItems)
	if err != nil {
		return nil, fmt.Errorf("encode deposit private input: %w", err)
	}
	if len(cfg.SP1.DepositWitnessItems) != len(mintItems) {
		return nil, fmt.Errorf(
			"deposit witness item count mismatch: got=%d want=%d",
			len(cfg.SP1.DepositWitnessItems),
			len(mintItems),
		)
	}
	var ivk [64]byte
	copy(ivk[:], cfg.SP1.DepositOWalletIVKBytes)
	depositSP1Input, err := proverinput.EncodeDepositGuestPrivateInput(cpDeposit, ivk, cfg.SP1.DepositWitnessItems)
	if err != nil {
		return nil, fmt.Errorf("encode deposit guest private input: %w", err)
	}

	predictedWithdrawalID, err := computePredictedWithdrawalID(cfg.ChainID, bridgeAddr, nonceBefore+1, owner, withdrawAmount, recipientUA)
	if err != nil {
		return nil, fmt.Errorf("compute predicted withdrawal id: %w", err)
	}

	var (
		mintBatchTx          common.Hash
		mintBatchRcpt        *types.Receipt
		approveWithdrawTx    common.Hash
		requestWithdrawTx    common.Hash
		extendWithdrawTx     common.Hash
		finalizeWithdrawTx   common.Hash
		withdrawalID         common.Hash
		feeBpsAtReq          uint64
		withdrawalExpiryWant uint64
		depositRequestID     string
		withdrawRequestID    string
	)

	logProgress("requesting sp1 deposit proof")
	cfg.DepositSeal, depositRequestID, err = requestSP1Proof(
		ctx,
		cfg.SP1,
		"deposit",
		depositID,
		cfg.SP1.DepositProgramURL,
		depositImageID,
		depositSP1Input,
		depositJournal,
	)
	if err != nil {
		return nil, err
	}

	mintBatchTx, mintBatchRcpt, err = transactAndWaitWithReceipt(ctx, client, auth, bridge, "mintBatch", cpDepositABI, cpDepositSigs, cfg.DepositSeal, depositJournal)
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
	if withdrawalID != withdrawWitnessIdentity.WithdrawalID {
		return nil, fmt.Errorf(
			"withdraw witness withdrawal id mismatch: witness=%s actual=%s",
			withdrawWitnessIdentity.WithdrawalID.Hex(),
			withdrawalID.Hex(),
		)
	}

	withdrawView, err := callWithdrawal(ctx, bridge, withdrawalID)
	if err != nil {
		return nil, fmt.Errorf("getWithdrawal before extend: %w", err)
	}
	if withdrawView.Expiry == 0 {
		return nil, errors.New("withdraw expiry is zero before extend")
	}
	withdrawalExpiryWant = withdrawView.Expiry + 60
	idsHash := crypto.Keccak256Hash(withdrawalID[:])
	extendDigest, err := callHash(ctx, bridge, "extendWithdrawDigest", idsHash, withdrawalExpiryWant)
	if err != nil {
		return nil, fmt.Errorf("extendWithdrawDigest: %w", err)
	}
	extendSigs, err := signDigestQuorum(ctx, digestSigner, extendDigest, operatorAddrs, cfg.Threshold)
	if err != nil {
		return nil, fmt.Errorf("sign extend digest: %w", err)
	}
	extendWithdrawTx, err = transactAndWait(
		ctx,
		client,
		auth,
		bridge,
		"extendWithdrawExpiryBatch",
		[]common.Hash{withdrawalID},
		withdrawalExpiryWant,
		extendSigs,
	)
	if err != nil {
		return nil, fmt.Errorf("extendWithdrawExpiryBatch: %w", err)
	}

	withdrawFees := computeFeeBreakdown(withdrawAmount, feeBpsAtReq, relayerTipBpsOnChain)
	net := new(big.Int).Set(withdrawFees.Net)

	withdrawDigest := checkpoint.Digest(cpWithdraw)
	cpWithdrawSigs, err := signDigestQuorum(ctx, digestSigner, withdrawDigest, operatorAddrs, cfg.Threshold)
	if err != nil {
		return nil, fmt.Errorf("sign withdraw checkpoint digest: %w", err)
	}
	cpWithdrawABI := toCheckpointABI(cpWithdraw)

	finalizeItems := []bridgeabi.FinalizeItem{
		{
			WithdrawalId:    withdrawalID,
			RecipientUAHash: crypto.Keccak256Hash(recipientUA),
			NetAmount:       net,
		},
	}

	withdrawJournal, err := bridgeabi.EncodeWithdrawJournal(bridgeabi.WithdrawJournal{
		FinalOrchardRoot: cpWithdraw.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cpWithdraw.BaseChainID),
		BridgeContract:   cpWithdraw.BridgeContract,
		Items:            finalizeItems,
	})
	if err != nil {
		return nil, fmt.Errorf("encode withdraw journal: %w", err)
	}
	withdrawPrivateInput, err := proverinput.EncodeWithdrawPrivateInputV1(cpWithdraw, cpWithdrawSigs, finalizeItems)
	if err != nil {
		return nil, fmt.Errorf("encode withdraw private input: %w", err)
	}
	if len(cfg.SP1.WithdrawWitnessItems) != len(finalizeItems) {
		return nil, fmt.Errorf(
			"withdraw witness item count mismatch: got=%d want=%d",
			len(cfg.SP1.WithdrawWitnessItems),
			len(finalizeItems),
		)
	}
	var ovk [32]byte
	copy(ovk[:], cfg.SP1.WithdrawOWalletOVKBytes)
	withdrawSP1Input, err := proverinput.EncodeWithdrawGuestPrivateInput(cpWithdraw, ovk, cfg.SP1.WithdrawWitnessItems)
	if err != nil {
		return nil, fmt.Errorf("encode withdraw guest private input: %w", err)
	}

	var proofInputsPath string
	if strings.TrimSpace(cfg.ProofInputsOut) != "" {
		proofBundle := proofInputsFile{
			Version:            "bridge-e2e.proof_inputs.v1",
			GeneratedAtUTC:     time.Now().UTC().Format(time.RFC3339),
			ChainID:            cfg.ChainID,
			BridgeContract:     bridgeAddr.Hex(),
			Checkpoint:         cpDeposit,
			OperatorSignatures: encodeSignaturesHex(cpDepositSigs),
		}
		if cpWithdraw != cpDeposit {
			cp := cpWithdraw
			proofBundle.WithdrawCheckpoint = &cp
			proofBundle.WithdrawOperatorSignatures = encodeSignaturesHex(cpWithdrawSigs)
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

	logProgress("requesting sp1 withdraw proof")
	cfg.WithdrawSeal, withdrawRequestID, err = requestSP1Proof(
		ctx,
		cfg.SP1,
		"withdraw",
		withdrawalID,
		cfg.SP1.WithdrawProgramURL,
		withdrawImageID,
		withdrawSP1Input,
		withdrawJournal,
	)
	if err != nil {
		return nil, err
	}

	finalizeWithdrawTx, err = transactAndWait(ctx, client, auth, bridge, "finalizeWithdrawBatch", cpWithdrawABI, cpWithdrawSigs, cfg.WithdrawSeal, withdrawJournal)
	if err != nil {
		return nil, fmt.Errorf("finalizeWithdrawBatch: %w", err)
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
	var (
		ownerBalAfter        *big.Int
		recipientBalAfter    *big.Int
		fdBalAfter           *big.Int
		bridgeBalAfter       *big.Int
		depositUsedInvariant bool
		withdrawInvariant    = withdrawalView{Amount: big.NewInt(0)}
		ownerDeltaActual     *big.Int
		recipientDeltaRaw    *big.Int
		recipientDeltaActual *big.Int
		fdDeltaActual        *big.Int
		bridgeDeltaActual    *big.Int
		balanceDeltaMatches  bool
	)

	checkInvariants := func() error {
		var checkErr error

		ownerBalAfter, checkErr = callBalanceOf(ctx, wjuno, owner)
		if checkErr != nil {
			return fmt.Errorf("owner balance after: %w", checkErr)
		}
		recipientBalAfter, checkErr = callBalanceOf(ctx, wjuno, recipient)
		if checkErr != nil {
			return fmt.Errorf("recipient balance after: %w", checkErr)
		}
		fdBalAfter, checkErr = callBalanceOf(ctx, wjuno, fdAddr)
		if checkErr != nil {
			return fmt.Errorf("fee distributor balance after: %w", checkErr)
		}
		bridgeBalAfter, checkErr = callBalanceOf(ctx, wjuno, bridgeAddr)
		if checkErr != nil {
			return fmt.Errorf("bridge balance after: %w", checkErr)
		}

		depositUsedInvariant, checkErr = callDepositUsed(ctx, bridge, depositID, nil)
		if checkErr != nil {
			return fmt.Errorf("depositUsed invariant call: %w", checkErr)
		}
		if !depositUsedInvariant {
			return errors.New("depositUsed invariant failed: expected true after mintBatch")
		}

		withdrawInvariant, checkErr = callWithdrawal(ctx, bridge, withdrawalID)
		if checkErr != nil {
			return fmt.Errorf("getWithdrawal invariant call: %w", checkErr)
		}
		if withdrawInvariant.Requester != owner {
			return fmt.Errorf("withdraw requester mismatch: got=%s want=%s", withdrawInvariant.Requester.Hex(), owner.Hex())
		}
		if withdrawInvariant.Amount.Cmp(withdrawAmount) != 0 {
			return fmt.Errorf("withdraw amount mismatch: got=%s want=%s", withdrawInvariant.Amount.String(), withdrawAmount.String())
		}
		if withdrawInvariant.FeeBps != feeBpsAtReq {
			return fmt.Errorf("withdraw fee bps mismatch: got=%d want=%d", withdrawInvariant.FeeBps, feeBpsAtReq)
		}
		if !withdrawInvariant.Finalized {
			return errors.New("withdraw invariant failed: expected finalized=true")
		}
		if withdrawInvariant.Refunded {
			return errors.New("withdraw invariant failed: expected refunded=false")
		}
		if !bytes.Equal(withdrawInvariant.Recipient, recipientUA) {
			return errors.New("withdraw invariant failed: recipient UA mismatch")
		}
		if withdrawInvariant.Expiry != withdrawalExpiryWant {
			return fmt.Errorf("withdraw expiry mismatch: got=%d want=%d", withdrawInvariant.Expiry, withdrawalExpiryWant)
		}

		ownerDeltaActual = new(big.Int).Sub(ownerBalAfter, ownerBalBefore)
		recipientDeltaRaw = new(big.Int).Sub(recipientBalAfter, recipientBalBefore)
		recipientDeltaActual = normalizeRecipientDeltaActual(recipientDeltaRaw, recipientEqualsOwner)
		fdDeltaActual = new(big.Int).Sub(fdBalAfter, fdBalBefore)
		bridgeDeltaActual = new(big.Int).Sub(bridgeBalAfter, bridgeBalBefore)

		balanceDeltaMatches = ownerDeltaActual.Cmp(expectedDeltas.Owner) == 0 &&
			recipientDeltaActual.Cmp(expectedDeltas.Recipient) == 0 &&
			fdDeltaActual.Cmp(expectedDeltas.FeeDistributor) == 0 &&
			bridgeDeltaActual.Cmp(expectedDeltas.Bridge) == 0
		if !balanceDeltaMatches {
			return fmt.Errorf(
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
		return nil
	}

	err = waitForInvariantConvergence(ctx, postFinalizeInvariantWaitTimeout, postFinalizeInvariantPollInterval, checkInvariants)
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
	rep.Checkpoint.Height = cpDeposit.Height
	rep.Checkpoint.BlockHash = cpDeposit.BlockHash.Hex()
	rep.Checkpoint.FinalOrchardRoot = cpDeposit.FinalOrchardRoot.Hex()

	if setFeeDistributorTx != (common.Hash{}) {
		rep.Transactions.SetFeeDistributor = setFeeDistributorTx.Hex()
	}
	if setThresholdTx != (common.Hash{}) {
		rep.Transactions.SetThreshold = setThresholdTx.Hex()
	}
	if setBridgeWJunoTx != (common.Hash{}) {
		rep.Transactions.SetBridgeWJuno = setBridgeWJunoTx.Hex()
	}
	if setBridgeFeesTx != (common.Hash{}) {
		rep.Transactions.SetBridgeFees = setBridgeFeesTx.Hex()
	}
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
	if extendWithdrawTx != (common.Hash{}) {
		rep.Transactions.ExtendWithdraw = extendWithdrawTx.Hex()
	}
	if finalizeWithdrawTx != (common.Hash{}) {
		rep.Transactions.FinalizeWithdraw = finalizeWithdrawTx.Hex()
	}
	junoProofTxHash, junoProofSource := junoExecutionProofFromInputTxHash(cfg.JunoExecutionTxHash)
	rep.Juno.TxHash = junoProofTxHash
	rep.Juno.TxID = junoProofTxHash
	rep.Juno.ProofOfExecution.Available = junoProofTxHash != ""
	rep.Juno.ProofOfExecution.TxHash = junoProofTxHash
	rep.Juno.ProofOfExecution.Source = junoProofSource

	rep.Withdraw.PredictedID = predictedWithdrawalID.Hex()
	rep.Withdraw.FeeBps = feeBpsAtReq

	rep.Balances.RecipientWJuno = recipientBalAfter.String()
	rep.Balances.FeeDistributor = fdBalAfter.String()

	rep.Proof.ProofInputsPath = proofInputsPath
	rep.Proof.DepositImageID = depositImageID.Hex()
	rep.Proof.WithdrawImageID = withdrawImageID.Hex()
	rep.Proof.DepositSealBytes = len(cfg.DepositSeal)
	rep.Proof.WithdrawSealBytes = len(cfg.WithdrawSeal)
	rep.Proof.SP1.Enabled = cfg.SP1.Auto
	if cfg.SP1.Auto {
		rep.Proof.SP1.SubmissionMode = cfg.SP1.ProofSubmissionMode
		rep.Proof.SP1.RPCURL = cfg.SP1.RPCURL
		rep.Proof.SP1.InputMode = cfg.SP1.InputMode
		rep.Proof.SP1.MarketAddress = cfg.SP1.MarketAddress.Hex()
		rep.Proof.SP1.VerifierRouter = cfg.SP1.VerifierRouterAddr.Hex()
		rep.Proof.SP1.SetVerifier = cfg.SP1.SetVerifierAddr.Hex()
		rep.Proof.SP1.DepositRequestID = depositRequestID
		rep.Proof.SP1.WithdrawRequestID = withdrawRequestID
		rep.Proof.SP1.MaxPricePerPGU = cfg.SP1.MaxPricePerPGU
		rep.Proof.SP1.MinAuctionPeriodSec = cfg.SP1.MinAuctionPeriod
		rep.Proof.SP1.AuctionTimeoutSec = uint64(cfg.SP1.AuctionTimeout.Seconds())
		rep.Proof.SP1.RequestTimeoutSec = uint64(cfg.SP1.RequestTimeout.Seconds())
	}

	rep.Invariants.Registry.OperatorCount = registryOperatorCount
	rep.Invariants.Registry.Threshold = registryThreshold
	rep.Invariants.Registry.AllActive = allOperatorsActive
	rep.Invariants.DepositUsed = depositUsedInvariant
	rep.Invariants.Withdrawal.Exists = true
	rep.Invariants.Withdrawal.Finalized = withdrawInvariant.Finalized
	rep.Invariants.Withdrawal.Refunded = withdrawInvariant.Refunded
	rep.Invariants.Withdrawal.Extended = withdrawalExpiryWant > 0
	rep.Invariants.Withdrawal.FeeBps = withdrawInvariant.FeeBps
	rep.Invariants.Withdrawal.Amount = withdrawInvariant.Amount.String()
	rep.Invariants.Withdrawal.Expiry = withdrawInvariant.Expiry
	rep.Invariants.Withdrawal.ExpectedExpiry = withdrawalExpiryWant

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

func junoExecutionProofFromInputTxHash(junoExecutionTxHash string) (string, string) {
	junoExecutionTxHash = strings.TrimSpace(junoExecutionTxHash)
	if junoExecutionTxHash == "" {
		return "", ""
	}
	return junoExecutionTxHash, junoProofSourceInputExecutionTx
}

func requestSP1Proof(
	ctx context.Context,
	cfg sp1Config,
	pipeline string,
	batchID common.Hash,
	programURL string,
	imageID common.Hash,
	privateInput []byte,
	expectedJournal []byte,
) ([]byte, string, error) {
	if cfg.ProofSubmissionMode == sp1ProofSubmissionQueue {
		return requestSP1ProofViaQueue(ctx, cfg, pipeline, batchID, imageID, privateInput, expectedJournal)
	}
	return requestSP1ProofOnce(
		ctx,
		cfg,
		pipeline,
		programURL,
		imageID,
		privateInput,
		expectedJournal,
	)
}

func requestSP1ProofViaQueue(
	ctx context.Context,
	cfg sp1Config,
	pipeline string,
	batchID common.Hash,
	imageID common.Hash,
	privateInput []byte,
	expectedJournal []byte,
) ([]byte, string, error) {
	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver:  queue.DriverKafka,
		Brokers: cfg.ProofQueueBrokers,
	})
	if err != nil {
		return nil, "", fmt.Errorf("init proof queue producer for %s: %w", pipeline, err)
	}
	defer producer.Close()

	// Ensure response topics exist before creating the consumer to avoid transient
	// unknown-topic errors on fresh Kafka clusters.
	probe := []byte(`{"version":"bridge-e2e.proof.queue.probe.v1"}`)
	for _, topic := range []string{cfg.ProofResultTopic, cfg.ProofFailureTopic} {
		if err := producer.Publish(ctx, topic, probe); err != nil {
			return nil, "", fmt.Errorf("publish proof queue topic probe for %s topic=%s: %w", pipeline, topic, err)
		}
	}

	group := strings.TrimSpace(cfg.ProofConsumerGroup)
	if group == "" {
		group = fmt.Sprintf("%s-%s-%d", defaultProofConsumerGroupPrefix, pipeline, time.Now().UTC().UnixNano())
	}
	consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
		Driver:        queue.DriverKafka,
		Brokers:       cfg.ProofQueueBrokers,
		Group:         group,
		Topics:        []string{cfg.ProofResultTopic, cfg.ProofFailureTopic},
		KafkaMaxBytes: cfg.ProofQueueMaxBytes,
	})
	if err != nil {
		return nil, "", fmt.Errorf("init proof queue consumer for %s: %w", pipeline, err)
	}
	defer consumer.Close()

	client, err := proofclient.NewQueueClient(proofclient.QueueConfig{
		RequestTopic:    cfg.ProofRequestTopic,
		ResultTopic:     cfg.ProofResultTopic,
		FailureTopic:    cfg.ProofFailureTopic,
		Producer:        producer,
		Consumer:        consumer,
		AckTimeout:      cfg.ProofAckTimeout,
		DefaultDeadline: cfg.ProofDeadline,
	})
	if err != nil {
		return nil, "", fmt.Errorf("init proof queue client for %s: %w", pipeline, err)
	}

	jobID := idempotency.ProofJobIDV1(pipeline, batchID, imageID, expectedJournal, privateInput)
	logProgress(
		"sp1 %s mode=queue request_topic=%s result_topic=%s failure_topic=%s group=%s job_id=%s",
		pipeline,
		cfg.ProofRequestTopic,
		cfg.ProofResultTopic,
		cfg.ProofFailureTopic,
		group,
		jobID.Hex(),
	)
	result, err := client.RequestProof(ctx, proofclient.Request{
		JobID:        jobID,
		Pipeline:     pipeline,
		ImageID:      imageID,
		Journal:      append([]byte(nil), expectedJournal...),
		PrivateInput: append([]byte(nil), privateInput...),
		Deadline:     time.Now().UTC().Add(cfg.ProofDeadline),
	})
	if err != nil {
		return nil, "", fmt.Errorf("sp1 queue proof request failed for %s: %w", pipeline, err)
	}
	if err := validateQueueProofFulfillment(pipeline, expectedJournal, result); err != nil {
		return nil, "", err
	}

	return result.Seal, extractQueueProofRequestID(result.Metadata), nil
}

func validateQueueProofFulfillment(pipeline string, expectedJournal []byte, result proofclient.Result) error {
	if len(result.Seal) == 0 {
		return fmt.Errorf("sp1 queue proof returned empty seal for %s", pipeline)
	}
	if len(result.Journal) == 0 {
		return fmt.Errorf("sp1 queue proof returned empty journal for %s", pipeline)
	}
	if !bytes.Equal(result.Journal, expectedJournal) {
		return fmt.Errorf("sp1 queue proof journal mismatch for %s", pipeline)
	}
	return nil
}

func extractQueueProofRequestID(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}

	for _, key := range []string{"request_id", "requestId", "requestID"} {
		value := strings.TrimSpace(metadata[key])
		if value == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(value), "0x") {
			return strings.ToLower(value)
		}
		if n, err := strconv.ParseUint(value, 10, 64); err == nil {
			return fmt.Sprintf("0x%x", n)
		}
		return value
	}
	return ""
}

func requestSP1ProofOnce(
	ctx context.Context,
	cfg sp1Config,
	pipeline string,
	_ string,
	imageID common.Hash,
	privateInput []byte,
	expectedJournal []byte,
) ([]byte, string, error) {
	maxResponseBytes := cfg.ProofQueueMaxBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultProofQueueMaxBytes
	}
	prover, err := proverexec.New(cfg.Bin, maxResponseBytes)
	if err != nil {
		return nil, "", fmt.Errorf("init prover adapter for %s: %w", pipeline, err)
	}
	if cfg.RequestorKeyHex != "" {
		if err := os.Setenv("NETWORK_PRIVATE_KEY", cfg.RequestorKeyHex); err != nil {
			return nil, "", fmt.Errorf("set NETWORK_PRIVATE_KEY for %s: %w", pipeline, err)
		}
	}
	if err := os.Setenv("SP1_NETWORK_RPC_URL", cfg.RPCURL); err != nil {
		return nil, "", fmt.Errorf("set SP1_NETWORK_RPC_URL for %s: %w", pipeline, err)
	}
	if err := os.Setenv("SP1_MAX_PRICE_PER_PGU", strconv.FormatUint(cfg.MaxPricePerPGU, 10)); err != nil {
		return nil, "", fmt.Errorf("set SP1_MAX_PRICE_PER_PGU for %s: %w", pipeline, err)
	}
	if err := os.Setenv("SP1_MIN_AUCTION_PERIOD", strconv.FormatUint(cfg.MinAuctionPeriod, 10)); err != nil {
		return nil, "", fmt.Errorf("set SP1_MIN_AUCTION_PERIOD for %s: %w", pipeline, err)
	}
	if err := os.Setenv("SP1_AUCTION_TIMEOUT_SECONDS", strconv.FormatInt(int64(cfg.AuctionTimeout.Seconds()), 10)); err != nil {
		return nil, "", fmt.Errorf("set SP1_AUCTION_TIMEOUT_SECONDS for %s: %w", pipeline, err)
	}
	if err := os.Setenv("SP1_REQUEST_TIMEOUT_SECONDS", strconv.FormatInt(int64(cfg.RequestTimeout.Seconds()), 10)); err != nil {
		return nil, "", fmt.Errorf("set SP1_REQUEST_TIMEOUT_SECONDS for %s: %w", pipeline, err)
	}
	logProgress(
		"sp1 %s cmd=%s mode=sp1-network-mainnet max_price_per_pgu=%d min_auction_period=%d auction_timeout=%s request_timeout=%s",
		pipeline,
		cfg.Bin,
		cfg.MaxPricePerPGU,
		cfg.MinAuctionPeriod,
		cfg.AuctionTimeout.String(),
		cfg.RequestTimeout.String(),
	)
	seal, err := prover.Prove(ctx, imageID, expectedJournal, privateInput)
	if err != nil {
		return nil, "", fmt.Errorf("sp1 prove failed for %s: %w", pipeline, err)
	}
	requestID := fmt.Sprintf("sp1-network-%d", time.Now().UTC().UnixNano())
	return seal, requestID, nil
}

func prependPathEntries(pathValue string, entries ...string) string {
	parts := strings.Split(pathValue, ":")
	existing := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		existing[part] = struct{}{}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		if entry == "" {
			continue
		}
		if _, ok := existing[entry]; ok {
			continue
		}
		parts = append([]string{entry}, parts...)
		existing[entry] = struct{}{}
	}
	return strings.Join(parts, ":")
}

func upsertEnvVar(env []string, key, value string) []string {
	prefix := key + "="
	for i, item := range env {
		if strings.HasPrefix(item, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func sp1ProofAttemptTimeout(cfg sp1Config) time.Duration {
	if cfg.RequestTimeout <= 0 {
		return defaultProofDeadline
	}
	return cfg.RequestTimeout + defaultSP1ProofAttemptGrace
}

func nextSP1MaxPriceWei(current *big.Int, multiplier uint64, cap *big.Int) (*big.Int, bool) {
	currentPrice := big.NewInt(0)
	if current != nil {
		currentPrice = new(big.Int).Set(current)
	}
	if multiplier < 2 || currentPrice.Sign() <= 0 {
		return currentPrice, false
	}
	nextPrice := new(big.Int).Mul(currentPrice, new(big.Int).SetUint64(multiplier))
	if cap != nil && cap.Sign() > 0 && nextPrice.Cmp(cap) > 0 {
		nextPrice = new(big.Int).Set(cap)
	}
	if nextPrice.Cmp(currentPrice) <= 0 {
		return nextPrice, false
	}
	return nextPrice, true
}

func isRetriableSP1GetProofError(msg string) bool {
	lowered := strings.ToLower(msg)
	return strings.Contains(lowered, "request timed out") ||
		strings.Contains(lowered, "query_fulfilled_event") ||
		strings.Contains(lowered, "decoding err") ||
		strings.Contains(lowered, "not fulfilled") ||
		strings.Contains(lowered, "not found") ||
		strings.Contains(lowered, "missing data") ||
		strings.Contains(lowered, "429") ||
		strings.Contains(lowered, "rate limit")
}

func isRetriableSP1LockFailure(msg string) bool {
	lowered := strings.ToLower(msg)
	return strings.Contains(lowered, "request timed out") ||
		strings.Contains(lowered, "not fulfilled") ||
		strings.Contains(lowered, "get-proof timeout") ||
		strings.Contains(lowered, "lock timeout") ||
		strings.Contains(lowered, "request expired") ||
		strings.Contains(lowered, "expired without fulfillment") ||
		strings.Contains(lowered, "unable to lock")
}

var (
	sp1RequestIDRegex   = regexp.MustCompile(`(?:Assigned Request ID:|Request ID:|Submitted request)\s*(0x[0-9a-fA-F]+)`)
	sp1LegacyProofRegex = regexp.MustCompile(`Journal:\s*\"(0x[0-9a-fA-F]*)\"\s*-\s*Seal:\s*\"(0x[0-9a-fA-F]+)\"`)
	sp1FulfillmentRegex = regexp.MustCompile(`(?s)Fulfillment Data:\s*(\{.*?\})\s*Seal:`)
	sp1SealOnlyRegex    = regexp.MustCompile(`Seal:\s*\"(0x[0-9a-fA-F]+)\"`)
)

func extractSP1RequestID(output []byte) string {
	matches := sp1RequestIDRegex.FindAllStringSubmatch(string(output), -1)
	if len(matches) == 0 {
		return ""
	}
	last := matches[len(matches)-1]
	if len(last) < 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(last[1]))
}

func parseSP1WaitOutput(output []byte) (sp1WaitResult, error) {
	raw := string(output)

	requestMatches := sp1RequestIDRegex.FindAllStringSubmatch(raw, -1)
	if len(requestMatches) == 0 || len(requestMatches[len(requestMatches)-1]) < 2 {
		return sp1WaitResult{}, errors.New("sp1 output missing request id")
	}
	requestID := strings.ToLower(strings.TrimSpace(requestMatches[len(requestMatches)-1][1]))

	if legacyMatches := sp1LegacyProofRegex.FindAllStringSubmatch(raw, -1); len(legacyMatches) > 0 {
		last := legacyMatches[len(legacyMatches)-1]
		journalHex := strings.ToLower(strings.TrimSpace(last[1]))
		sealHex := strings.ToLower(strings.TrimSpace(last[2]))
		if sealHex == "" {
			return sp1WaitResult{}, errors.New("sp1 output missing seal")
		}
		return sp1WaitResult{
			RequestIDHex: requestID,
			JournalHex:   journalHex,
			SealHex:      sealHex,
		}, nil
	}

	fulfillmentMatch := sp1FulfillmentRegex.FindStringSubmatch(raw)
	if len(fulfillmentMatch) < 2 {
		return sp1WaitResult{}, errors.New("sp1 output missing journal/seal")
	}

	var fulfillment struct {
		ImageIDAndJournal []json.RawMessage `json:"ImageIdAndJournal"`
	}
	if err := json.Unmarshal([]byte(fulfillmentMatch[1]), &fulfillment); err != nil {
		return sp1WaitResult{}, fmt.Errorf("decode fulfillment data: %w", err)
	}
	if len(fulfillment.ImageIDAndJournal) < 2 {
		return sp1WaitResult{}, errors.New("sp1 output missing journal/seal")
	}

	var journalHex string
	if err := json.Unmarshal(fulfillment.ImageIDAndJournal[1], &journalHex); err != nil {
		return sp1WaitResult{}, fmt.Errorf("decode fulfillment journal: %w", err)
	}
	journalHex = strings.ToLower(strings.TrimSpace(journalHex))
	if journalHex == "" {
		return sp1WaitResult{}, errors.New("sp1 output missing journal")
	}

	sealMatch := sp1SealOnlyRegex.FindStringSubmatch(raw)
	if len(sealMatch) < 2 {
		return sp1WaitResult{}, errors.New("sp1 output missing seal")
	}
	sealHex := strings.ToLower(strings.TrimSpace(sealMatch[1]))
	if sealHex == "" {
		return sp1WaitResult{}, errors.New("sp1 output missing seal")
	}

	return sp1WaitResult{
		RequestIDHex: requestID,
		JournalHex:   journalHex,
		SealHex:      sealHex,
	}, nil
}

func parseSP1ProofOutput(output []byte, pipeline string, expectedJournal []byte) ([]byte, string, error) {
	parsed, err := parseSP1WaitOutput(output)
	if err != nil {
		return nil, "", fmt.Errorf("parse sp1 output for %s: %w", pipeline, err)
	}

	journal, err := parseHexBytesFlag("sp1 journal", parsed.JournalHex)
	if err != nil {
		return nil, "", fmt.Errorf("decode sp1 journal for %s: %w", pipeline, err)
	}
	if !bytes.Equal(journal, expectedJournal) {
		return nil, "", fmt.Errorf("sp1 journal mismatch for %s", pipeline)
	}

	seal, err := parseHexBytesFlag("sp1 seal", parsed.SealHex)
	if err != nil {
		return nil, "", fmt.Errorf("decode sp1 seal for %s: %w", pipeline, err)
	}
	if len(seal) == 0 {
		return nil, "", fmt.Errorf("sp1 returned empty seal for %s", pipeline)
	}

	return seal, parsed.RequestIDHex, nil
}

func uploadSP1InputToS3(
	ctx context.Context,
	cfg sp1Config,
	pipeline string,
	privateInput []byte,
) (string, error) {
	if strings.TrimSpace(cfg.InputS3Bucket) == "" {
		return "", errors.New("sp1 input S3 bucket is required")
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if cfg.InputS3Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.InputS3Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return "", fmt.Errorf("load AWS config for sp1 oversized input upload: %w", err)
	}
	s3Client := awss3.NewFromConfig(awsCfg)

	digest := sha256.Sum256(privateInput)
	ts := time.Now().UTC().Format("20060102T150405Z")
	keyPrefix := strings.Trim(cfg.InputS3Prefix, "/")
	if keyPrefix == "" {
		keyPrefix = defaultSP1InputS3Prefix
	}
	key := fmt.Sprintf("%s/%s-%s-%x.bin", keyPrefix, pipeline, ts, digest[:8])

	_, err = s3Client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket:      aws.String(cfg.InputS3Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(privateInput),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return "", fmt.Errorf("upload sp1 oversized input to s3 bucket=%s key=%s: %w", cfg.InputS3Bucket, key, err)
	}

	presignTTL := cfg.InputS3PresignTTL
	if presignTTL <= 0 {
		presignTTL = defaultSP1InputS3PresignTTL
	}
	presigner := awss3.NewPresignClient(s3Client)
	req, err := presigner.PresignGetObject(
		ctx,
		&awss3.GetObjectInput{
			Bucket: aws.String(cfg.InputS3Bucket),
			Key:    aws.String(key),
		},
		func(options *awss3.PresignOptions) {
			options.Expires = presignTTL
		},
	)
	if err != nil {
		return "", fmt.Errorf("presign sp1 oversized input url bucket=%s key=%s: %w", cfg.InputS3Bucket, key, err)
	}

	logProgress(
		"sp1 %s oversized input uploaded bytes=%d bucket=%s key=%s presign_ttl=%s",
		pipeline,
		len(privateInput),
		cfg.InputS3Bucket,
		key,
		presignTTL.String(),
	)
	return req.URL, nil
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
		txAuth := transactAuthWithDefaults(auth, 4_000_000)
		applyRetryGasBump(ctx, backend, txAuth, attempt)
		nonce := "<nil>"
		if txAuth.Nonce != nil {
			nonce = txAuth.Nonce.String()
		}
		logProgress("deploy attempt=%d nonce=%s", attempt, nonce)
		addr, tx, _, err := bind.DeployContract(txAuth, a, bin, backend, args...)
		if err != nil {
			logProgress("deploy attempt=%d failed: %v", attempt, err)
			if attempt < 4 && isRetriableNonceError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Address{}, common.Hash{}, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Address{}, common.Hash{}, err
		}
		incrementAuthNonce(auth)
		logProgress("deploy submitted tx=%s", tx.Hash().Hex())
		rcpt, err := waitMinedWithGrace(ctx, backend, tx)
		if err != nil {
			logProgress("deploy wait mined failed tx=%s: %v", tx.Hash().Hex(), err)
			if ctx.Err() == nil && isRetriableWaitMinedError(err) {
				recovered, recoverErr := waitForCodeAtAddress(ctx, backend, addr, deployCodeRecoveryTimeout, deployCodeRecoveryPollInterval)
				if recoverErr != nil {
					logProgress("deploy code recovery failed addr=%s tx=%s: %v", addr.Hex(), tx.Hash().Hex(), recoverErr)
				}
				if recovered {
					logProgress("deploy recovered via on-chain code addr=%s tx=%s", addr.Hex(), tx.Hash().Hex())
					return addr, tx.Hash(), nil
				}
			}
			if ctx.Err() == nil && attempt < 4 && isRetriableWaitMinedError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Address{}, common.Hash{}, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Address{}, common.Hash{}, err
		}
		if rcpt.Status != 1 {
			return common.Address{}, common.Hash{}, fmt.Errorf("deployment reverted: %s", tx.Hash().Hex())
		}
		logProgress("deploy mined tx=%s", tx.Hash().Hex())
		return addr, tx.Hash(), nil
	}
	return common.Address{}, common.Hash{}, errors.New("deploy contract retries exhausted")
}

func transactAndWait(ctx context.Context, backend txBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, args ...any) (common.Hash, error) {
	txHash, _, err := transactAndWaitWithReceipt(ctx, backend, auth, c, method, args...)
	return txHash, err
}

func transactAndWaitWithReceipt(ctx context.Context, backend txBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, args ...any) (common.Hash, *types.Receipt, error) {
	for attempt := 1; attempt <= 4; attempt++ {
		txAuth := transactAuthWithDefaults(auth, 1_000_000)
		applyRetryGasBump(ctx, backend, txAuth, attempt)
		nonce := "<nil>"
		if txAuth.Nonce != nil {
			nonce = txAuth.Nonce.String()
		}
		logProgress("%s attempt=%d nonce=%s", method, attempt, nonce)
		tx, err := c.Transact(txAuth, method, args...)
		if err != nil {
			logProgress("%s attempt=%d failed: %v", method, attempt, err)
			if attempt < 4 && isRetriableNonceError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Hash{}, nil, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Hash{}, nil, err
		}
		incrementAuthNonce(auth)
		logProgress("%s submitted tx=%s", method, tx.Hash().Hex())
		rcpt, err := waitMinedWithGrace(ctx, backend, tx)
		if err != nil {
			logProgress("%s wait mined failed tx=%s: %v", method, tx.Hash().Hex(), err)
			if ctx.Err() == nil && attempt < 4 && isRetriableWaitMinedError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Hash{}, nil, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Hash{}, nil, err
		}
		if rcpt.Status != 1 {
			return common.Hash{}, nil, fmt.Errorf("%s reverted: %s", method, tx.Hash().Hex())
		}
		logProgress("%s mined tx=%s", method, tx.Hash().Hex())
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

func logProgress(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "bridge-e2e: "+format+"\n", args...)
}

type gasPriceSuggester interface {
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
}

type gasTipCapSuggester interface {
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
}

func applyRetryGasBump(ctx context.Context, backend any, txAuth *bind.TransactOpts, attempt int) {
	if txAuth == nil {
		return
	}
	if attempt < 1 {
		attempt = 1
	}

	multiplier := retryGasMultiplier(attempt)

	gasPriceBase := big.NewInt(defaultRetryGasPriceWei)
	if txAuth.GasPrice != nil && txAuth.GasPrice.Sign() > 0 {
		gasPriceBase = new(big.Int).Set(txAuth.GasPrice)
	}
	if suggester, ok := backend.(gasPriceSuggester); ok {
		if suggested, err := suggester.SuggestGasPrice(ctx); err == nil && suggested != nil && suggested.Cmp(gasPriceBase) > 0 {
			gasPriceBase = new(big.Int).Set(suggested)
		}
	}

	if suggester, ok := backend.(gasTipCapSuggester); ok {
		tipBase := big.NewInt(defaultRetryGasTipCapWei)
		if txAuth.GasTipCap != nil && txAuth.GasTipCap.Sign() > 0 {
			tipBase = new(big.Int).Set(txAuth.GasTipCap)
		}
		if suggested, err := suggester.SuggestGasTipCap(ctx); err == nil && suggested != nil && suggested.Sign() > 0 {
			if suggested.Cmp(tipBase) > 0 {
				tipBase = new(big.Int).Set(suggested)
			}
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

func isRetriableWaitMinedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "not indexed")
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

func waitMinedWithGrace(ctx context.Context, backend bind.DeployBackend, tx *types.Transaction) (*types.Receipt, error) {
	waitCtx, cancel := context.WithTimeout(ctx, txMinedWaitTimeout)
	rcpt, err := waitMined(waitCtx, backend, tx)
	cancel()
	if err == nil || ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded) {
		return rcpt, err
	}

	graceCtx, graceCancel := context.WithTimeout(ctx, txMinedGraceTimeout)
	defer graceCancel()
	return waitMined(graceCtx, backend, tx)
}

type codeAtBackend interface {
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

func waitForCodeAtAddress(ctx context.Context, backend codeAtBackend, addr common.Address, timeout time.Duration, pollInterval time.Duration) (bool, error) {
	if backend == nil {
		return false, errors.New("nil backend")
	}
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	if timeout <= 0 {
		timeout = pollInterval
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		code, err := backend.CodeAt(waitCtx, addr, nil)
		if err == nil && len(code) > 0 {
			return true, nil
		}

		select {
		case <-waitCtx.Done():
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return false, nil
			}
			return false, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

type operatorDigestSigner interface {
	SignDigest(ctx context.Context, digest common.Hash) ([][]byte, error)
}

type execOperatorDigestSignerCommandFn func(ctx context.Context, bin string, args []string) ([]byte, []byte, error)

type execOperatorDigestSigner struct {
	bin              string
	endpoints        []string
	maxResponseBytes int
	execCommand      execOperatorDigestSignerCommandFn
}

func newExecOperatorDigestSigner(bin string, endpoints []string, maxResponseBytes int) (*execOperatorDigestSigner, error) {
	if strings.TrimSpace(bin) == "" {
		return nil, errors.New("missing operator signer binary")
	}
	if maxResponseBytes <= 0 {
		return nil, errors.New("operator signer max response bytes must be > 0")
	}
	out := &execOperatorDigestSigner{
		bin:              strings.TrimSpace(bin),
		maxResponseBytes: maxResponseBytes,
		execCommand:      runExecOperatorDigestSignerCommand,
	}
	for _, endpoint := range endpoints {
		trimmed := strings.TrimSpace(endpoint)
		if trimmed == "" {
			continue
		}
		out.endpoints = append(out.endpoints, trimmed)
	}
	return out, nil
}

func (s *execOperatorDigestSigner) SignDigest(ctx context.Context, digest common.Hash) ([][]byte, error) {
	if s == nil || s.execCommand == nil {
		return nil, errors.New("nil operator signer")
	}
	args := []string{
		"sign-digest",
		"--digest", digest.Hex(),
		"--json",
	}
	for _, endpoint := range s.endpoints {
		args = append(args, "--operator-endpoint", endpoint)
	}

	stdout, stderr, err := s.execCommand(ctx, s.bin, args)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		if msg == "" {
			return nil, fmt.Errorf("execute operator signer: %w", err)
		}
		return nil, fmt.Errorf("execute operator signer: %w: %s", err, msg)
	}
	if len(stdout) > s.maxResponseBytes {
		return nil, errors.New("operator signer response too large")
	}

	var env struct {
		Version string          `json:"version"`
		Status  string          `json:"status"`
		Data    json.RawMessage `json:"data"`
		Error   *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(stdout, &env); err != nil {
		return nil, fmt.Errorf("decode operator signer response: %w", err)
	}
	if env.Version != "v1" {
		return nil, fmt.Errorf("unexpected operator signer response version %q", env.Version)
	}
	if env.Status == "err" {
		msg := "unknown operator signer error"
		code := ""
		if env.Error != nil {
			msg = strings.TrimSpace(env.Error.Message)
			code = strings.TrimSpace(env.Error.Code)
		}
		if msg == "" {
			msg = "unknown operator signer error"
		}
		if code != "" {
			return nil, fmt.Errorf("operator signer (%s): %s", code, msg)
		}
		return nil, fmt.Errorf("operator signer: %s", msg)
	}
	if env.Status != "ok" {
		return nil, fmt.Errorf("unexpected operator signer status %q", env.Status)
	}
	if len(env.Data) == 0 {
		return nil, errors.New("operator signer returned empty data")
	}

	var data struct {
		Signatures []string `json:"signatures"`
		Signature  string   `json:"signature"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return nil, fmt.Errorf("decode operator signer data: %w", err)
	}

	hexSigs := data.Signatures
	if len(hexSigs) == 0 && strings.TrimSpace(data.Signature) != "" {
		hexSigs = []string{data.Signature}
	}
	if len(hexSigs) == 0 {
		return nil, errors.New("operator signer returned no signatures")
	}

	out := make([][]byte, 0, len(hexSigs))
	for i, sHex := range hexSigs {
		sig, err := decodeHexBytesStrict(sHex)
		if err != nil {
			return nil, fmt.Errorf("decode signature[%d]: %w", i, err)
		}
		out = append(out, sig)
	}
	return out, nil
}

func runExecOperatorDigestSignerCommand(ctx context.Context, bin string, args []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func decodeHexBytesStrict(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, errors.New("empty hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func signDigestQuorum(
	ctx context.Context,
	signer operatorDigestSigner,
	digest common.Hash,
	operatorAddrs []common.Address,
	threshold int,
) ([][]byte, error) {
	if signer == nil {
		return nil, errors.New("nil operator signer")
	}
	rawSigs, err := signer.SignDigest(ctx, digest)
	if err != nil {
		return nil, err
	}
	return canonicalizeThresholdSignatures(digest, rawSigs, operatorAddrs, threshold)
}

func canonicalizeThresholdSignatures(
	digest common.Hash,
	sigs [][]byte,
	operatorAddrs []common.Address,
	threshold int,
) ([][]byte, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("threshold must be >= 1, got %d", threshold)
	}
	if len(operatorAddrs) < threshold {
		return nil, fmt.Errorf("operator set smaller than threshold: operators=%d threshold=%d", len(operatorAddrs), threshold)
	}
	if len(sigs) == 0 {
		return nil, errors.New("empty signature set")
	}

	allowed := make(map[common.Address]struct{}, len(operatorAddrs))
	for _, op := range operatorAddrs {
		allowed[op] = struct{}{}
	}

	type pair struct {
		addr common.Address
		sig  []byte
	}
	pairs := make([]pair, 0, len(sigs))
	for i, sig := range sigs {
		if len(sig) != 65 {
			return nil, fmt.Errorf("signature[%d] invalid length %d", i, len(sig))
		}
		signerAddr, err := checkpoint.RecoverSigner(digest, sig)
		if err != nil {
			return nil, fmt.Errorf("recover signer for signature[%d]: %w", i, err)
		}
		if _, ok := allowed[signerAddr]; !ok {
			return nil, fmt.Errorf("signature[%d] recovered unknown operator %s", i, signerAddr.Hex())
		}
		pairs = append(pairs, pair{
			addr: signerAddr,
			sig:  append([]byte(nil), sig...),
		})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].addr.Bytes(), pairs[j].addr.Bytes()) < 0
	})
	for i := 1; i < len(pairs); i++ {
		if pairs[i].addr == pairs[i-1].addr {
			return nil, fmt.Errorf("duplicate operator signature: %s", pairs[i].addr.Hex())
		}
	}
	if len(pairs) < threshold {
		return nil, fmt.Errorf("insufficient operator signatures: got=%d want=%d", len(pairs), threshold)
	}

	out := make([][]byte, 0, threshold)
	for _, p := range pairs[:threshold] {
		out = append(out, p.sig)
	}
	return out, nil
}

type depositUsedCaller interface {
	Call(opts *bind.CallOpts, results *[]any, method string, params ...any) error
}

type contractCaller interface {
	Call(opts *bind.CallOpts, results *[]any, method string, params ...any) error
}

func validateReusedBridgeConfig(
	ctx context.Context,
	bridge contractCaller,
	expectedVerifier common.Address,
	expectedDepositImageID common.Hash,
	expectedWithdrawImageID common.Hash,
) error {
	onChainVerifier, err := callAddress(ctx, bridge, "verifier")
	if err != nil {
		return fmt.Errorf("read bridge verifier: %w", err)
	}
	if onChainVerifier != expectedVerifier {
		return fmt.Errorf(
			"reused bridge verifier mismatch: got=%s want=%s",
			onChainVerifier.Hex(),
			expectedVerifier.Hex(),
		)
	}

	onChainDepositImageID, err := callHashFromCaller(ctx, bridge, "depositImageId")
	if err != nil {
		return fmt.Errorf("read bridge depositImageId: %w", err)
	}
	if onChainDepositImageID != expectedDepositImageID {
		return fmt.Errorf(
			"reused bridge depositImageId mismatch: got=%s want=%s",
			onChainDepositImageID.Hex(),
			expectedDepositImageID.Hex(),
		)
	}

	onChainWithdrawImageID, err := callHashFromCaller(ctx, bridge, "withdrawImageId")
	if err != nil {
		return fmt.Errorf("read bridge withdrawImageId: %w", err)
	}
	if onChainWithdrawImageID != expectedWithdrawImageID {
		return fmt.Errorf(
			"reused bridge withdrawImageId mismatch: got=%s want=%s",
			onChainWithdrawImageID.Hex(),
			expectedWithdrawImageID.Hex(),
		)
	}
	return nil
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

func callAddress(ctx context.Context, c contractCaller, method string, args ...any) (common.Address, error) {
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
	case [20]byte:
		return common.BytesToAddress(v[:]), nil
	default:
		return common.Address{}, fmt.Errorf("unexpected %s type: %T", method, res[0])
	}
}

func callHashFromCaller(ctx context.Context, c contractCaller, method string, args ...any) (common.Hash, error) {
	var res []any
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, method, args...); err != nil {
		return common.Hash{}, err
	}
	if len(res) != 1 {
		return common.Hash{}, fmt.Errorf("unexpected %s result count: %d", method, len(res))
	}
	switch v := res[0].(type) {
	case common.Hash:
		return v, nil
	case [32]byte:
		return common.BytesToHash(v[:]), nil
	default:
		return common.Hash{}, fmt.Errorf("unexpected %s type: %T", method, res[0])
	}
}

func callHash(ctx context.Context, c *bind.BoundContract, method string, args ...any) (common.Hash, error) {
	var res []any
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, method, args...); err != nil {
		return common.Hash{}, err
	}
	if len(res) != 1 {
		return common.Hash{}, fmt.Errorf("unexpected %s result count: %d", method, len(res))
	}
	switch v := res[0].(type) {
	case common.Hash:
		return v, nil
	case [32]byte:
		return common.BytesToHash(v[:]), nil
	default:
		return common.Hash{}, fmt.Errorf("unexpected %s type: %T", method, res[0])
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

func waitForWithdrawalFinalized(ctx context.Context, pollInterval time.Duration, fetch func() (withdrawalView, error)) (withdrawalView, error) {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	waitCtx, cancel := context.WithTimeout(ctx, withdrawalFinalizedWaitTimeout)
	defer cancel()

	timer := time.NewTimer(0)
	defer timer.Stop()

	var last withdrawalView
	var haveLast bool
	var lastErr error

	for {
		select {
		case <-waitCtx.Done():
			const timeoutMsg = "timed out waiting for finalized withdrawal"
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				if lastErr != nil {
					return withdrawalView{}, fmt.Errorf("%s: %w", timeoutMsg, lastErr)
				}
				if haveLast {
					return last, fmt.Errorf("%s: finalized=%t refunded=%t", timeoutMsg, last.Finalized, last.Refunded)
				}
				return withdrawalView{}, errors.New(timeoutMsg)
			}
			return withdrawalView{}, waitCtx.Err()
		case <-timer.C:
		}

		view, err := fetch()
		if err != nil {
			lastErr = err
		} else {
			last = view
			haveLast = true
			lastErr = nil
			if view.Finalized {
				return view, nil
			}
		}

		timer.Reset(pollInterval)
	}
}

func waitForInvariantConvergence(
	ctx context.Context,
	timeout time.Duration,
	pollInterval time.Duration,
	check func() error,
) error {
	if timeout <= 0 {
		timeout = postFinalizeInvariantWaitTimeout
	}
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	timer := time.NewTimer(0)
	defer timer.Stop()

	var lastErr error
	for {
		select {
		case <-waitCtx.Done():
			const timeoutMsg = "timed out waiting for invariant convergence"
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				if lastErr != nil {
					return fmt.Errorf("%s: %w", timeoutMsg, lastErr)
				}
				return errors.New(timeoutMsg)
			}
			return waitCtx.Err()
		case <-timer.C:
		}

		if err := check(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		timer.Reset(pollInterval)
	}
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
