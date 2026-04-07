package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
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
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

const (
	defaultBridgeFeeBps                        = uint64(50)
	defaultBridgeRelayerTipBps                 = uint64(1000)
	defaultBridgeWithdrawalExpiryWindowSeconds = uint64(24 * 60 * 60)
	defaultBridgeMaxExpiryExtensionSeconds     = uint64(12 * 60 * 60)
	defaultBridgeMinDepositAmountZat           = uint64(201_005_025)
	defaultBridgeMinWithdrawAmountZat          = uint64(200_000_000)
	defaultTimelockMinDelaySeconds             = uint64(48 * 60 * 60)
	defaultBootstrapTimelockDelaySeconds       = uint64(0)
	bridgeBPSDenominator                       = uint64(10_000)
	txMinedWaitTimeout                         = 180 * time.Second
	txMinedGraceTimeout                        = 240 * time.Second
	deployCodeRecoveryTimeout                  = 8 * time.Minute
	deployCodeRecoveryPollInterval             = 5 * time.Second
	defaultRetryGasPriceWei                    = int64(10_000_000)
	defaultRetryGasTipCapWei                   = int64(1_000_000)
	defaultRunTimeout                          = 20 * time.Minute
	legacyValueTransferGasLimit                = uint64(21_000)
	ephemeralFundingReadRetries                = 8
	ephemeralFundingReadBackoff                = 500 * time.Millisecond
	sweepRetryAttempts                         = 5
	sweepRetryBackoff                          = 500 * time.Millisecond
	sweepValueSafetyBufferWei                  = int64(100_000)
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

type config struct {
	RPCURL                              string
	ChainID                             uint64
	ContractsOut                        string
	Threshold                           int
	OperatorAddresses                   []common.Address
	OperatorFeeRecipients               []common.Address
	VerifierAddress                     common.Address
	BridgeFeeBps                        uint64
	BridgeRelayerTipBps                 uint64
	BridgeWithdrawalExpiryWindowSeconds uint64
	BridgeMaxExpiryExtensionSeconds     uint64
	BridgeMinDepositAmount              uint64
	BridgeMinWithdrawAmount             uint64
	DepositImageID                      common.Hash
	WithdrawImageID                     common.Hash
	GovernanceSafe                      common.Address
	PauseGuardian                       common.Address
	MinDepositAdmin                     common.Address
	TimelockMinDelaySeconds             uint64
	DeployerKeyHex                      string
	FunderKeyHex                        string
	UseEphemeralDeployer                bool
	EphemeralFundingAmountWei           *big.Int
	SweepRecipient                      common.Address
	SweepRecipientSet                   bool
	OutputPath                          string
	RunTimeout                          time.Duration
}

type report struct {
	GeneratedAtUTC string `json:"generated_at_utc"`
	RPCURL         string `json:"rpc_url"`
	ChainID        uint64 `json:"chain_id"`

	Actors struct {
		DirectDeployerAddress    string `json:"direct_deployer_address,omitempty"`
		FunderAddress            string `json:"funder_address,omitempty"`
		EphemeralDeployerAddress string `json:"ephemeral_deployer_address,omitempty"`
		SweepRecipient           string `json:"sweep_recipient,omitempty"`
	} `json:"actors"`

	Contracts struct {
		Verifier         string `json:"verifier"`
		WJuno            string `json:"wjuno"`
		OperatorRegistry string `json:"operator_registry"`
		FeeDistributor   string `json:"fee_distributor"`
		Bridge           string `json:"bridge"`
		Timelock         string `json:"timelock"`
	} `json:"contracts"`

	Governance struct {
		GovernanceSafe    string   `json:"governance_safe"`
		PauseGuardian     string   `json:"pause_guardian"`
		MinDepositAdmin   string   `json:"min_deposit_admin"`
		BootstrapProposer string   `json:"bootstrap_proposer"`
		MinDelaySeconds   uint64   `json:"min_delay_seconds"`
		Proposers         []string `json:"proposers"`
		Cancellers        []string `json:"cancellers"`
		Executors         []string `json:"executors"`
		BridgeUpdateSteps []string `json:"bridge_update_steps"`
	} `json:"governance"`

	BridgeParams struct {
		FeeBps                        uint64 `json:"fee_bps"`
		RelayerTipBps                 uint64 `json:"relayer_tip_bps"`
		WithdrawalExpiryWindowSeconds uint64 `json:"withdrawal_expiry_window_seconds"`
		MaxExpiryExtensionSeconds     uint64 `json:"max_expiry_extension_seconds"`
		MinDepositAmount              uint64 `json:"min_deposit_amount"`
		MinWithdrawAmount             uint64 `json:"min_withdraw_amount"`
	} `json:"bridge_params"`

	Operators             []string `json:"operators"`
	OperatorFeeRecipients []string `json:"operator_fee_recipients"`
	Threshold             int      `json:"threshold"`

	Transactions struct {
		FundEphemeral          string `json:"fund_ephemeral,omitempty"`
		DeployWJuno            string `json:"deploy_wjuno"`
		DeployOperatorRegistry string `json:"deploy_operator_registry"`
		DeployFeeDistributor   string `json:"deploy_fee_distributor"`
		DeployBridge           string `json:"deploy_bridge"`
		SetFeeDistributor      string `json:"set_fee_distributor"`
		SetThreshold           string `json:"set_threshold"`
		SetBridgeWJuno         string `json:"set_bridge_wjuno"`
		SetBridgeFees          string `json:"set_bridge_fees"`
		SetMinDepositAdmin     string `json:"set_min_deposit_admin"`
		SetPauseGuardian       string `json:"set_pause_guardian"`
		DeployTimelock         string `json:"deploy_timelock"`
		TransferOwnerships     struct {
			WJuno            string `json:"wjuno"`
			FeeDistributor   string `json:"fee_distributor"`
			OperatorRegistry string `json:"operator_registry"`
			Bridge           string `json:"bridge"`
		} `json:"transfer_ownerships"`
		AcceptOwnerships struct {
			WJuno            string `json:"wjuno"`
			FeeDistributor   string `json:"fee_distributor"`
			OperatorRegistry string `json:"operator_registry"`
			Bridge           string `json:"bridge"`
		} `json:"accept_ownerships"`
		UpdateTimelockDelay  string `json:"update_timelock_delay"`
		RevokeBootstrapRoles struct {
			Proposer  string `json:"proposer"`
			Canceller string `json:"canceller"`
			Executor  string `json:"executor"`
			Admin     string `json:"admin"`
		} `json:"revoke_bootstrap_roles"`
		SweepEphemeral string `json:"sweep_ephemeral,omitempty"`
	} `json:"transactions"`
}

type operatorBinding struct {
	Operator     common.Address
	FeeRecipient common.Address
}

type foundryArtifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

type evmBackend interface {
	bind.ContractBackend
	bind.DeployBackend
}

type txBackend interface {
	bind.DeployBackend
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

type contractCaller interface {
	Call(opts *bind.CallOpts, results *[]any, method string, params ...any) error
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "bridge-deploy: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	cfg, err := parseArgs(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.RunTimeout)
	defer cancel()

	client, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("read chain id: %w", err)
	}
	if chainID.Uint64() != cfg.ChainID {
		return fmt.Errorf("chain id mismatch: rpc=%d flag=%d", chainID.Uint64(), cfg.ChainID)
	}

	rep, err := deploy(ctx, client, cfg)
	if err != nil {
		return err
	}
	return writeReport(cfg.OutputPath, rep, stdout)
}

func parseArgs(args []string) (config, error) {
	var cfg config
	var operatorAddressFlags stringListFlag
	var operatorFeeRecipientFlags stringListFlag
	var deployerKeyFile string
	var funderKeyFile string
	var verifierAddressHex string
	var governanceSafeHex string
	var pauseGuardianHex string
	var minDepositAdminHex string
	var sweepRecipientHex string
	var depositImageIDHex string
	var withdrawImageIDHex string
	var ephemeralFundingAmountWei string

	fs := flag.NewFlagSet("bridge-deploy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.RPCURL, "rpc-url", "", "Base RPC URL")
	fs.Uint64Var(&cfg.ChainID, "chain-id", 0, "Base chain ID")
	fs.StringVar(&cfg.ContractsOut, "contracts-out", "contracts/out", "path to foundry build output directory")
	fs.StringVar(&deployerKeyFile, "deployer-key-file", "", "file containing deployer private key hex")
	fs.StringVar(&cfg.DeployerKeyHex, "deployer-key-hex", "", "deployer private key hex")
	fs.StringVar(&funderKeyFile, "funder-key-file", "", "file containing funder private key hex used for ephemeral deployer funding")
	fs.StringVar(&cfg.FunderKeyHex, "funder-key-hex", "", "funder private key hex used for ephemeral deployer funding")
	fs.StringVar(&ephemeralFundingAmountWei, "ephemeral-funding-amount-wei", "", "wei amount to fund a generated ephemeral deployer")
	fs.Var(&operatorAddressFlags, "operator-address", "operator address (repeat)")
	fs.Var(&operatorFeeRecipientFlags, "operator-fee-recipient", "operator fee recipient address (repeat, aligns with --operator-address)")
	fs.IntVar(&cfg.Threshold, "threshold", 3, "operator quorum threshold")
	fs.StringVar(&verifierAddressHex, "verifier-address", "", "verifier router address")
	fs.Uint64Var(&cfg.BridgeFeeBps, "fee-bps", defaultBridgeFeeBps, "bridge fee in basis points")
	fs.Uint64Var(&cfg.BridgeRelayerTipBps, "relayer-tip-bps", defaultBridgeRelayerTipBps, "bridge relayer tip share in basis points of fee")
	fs.Uint64Var(
		&cfg.BridgeWithdrawalExpiryWindowSeconds,
		"withdrawal-expiry-window-seconds",
		defaultBridgeWithdrawalExpiryWindowSeconds,
		"bridge withdrawal expiry window in seconds",
	)
	fs.Uint64Var(&cfg.BridgeMaxExpiryExtensionSeconds, "max-expiry-extension-seconds", defaultBridgeMaxExpiryExtensionSeconds, "bridge max expiry extension in seconds")
	fs.Uint64Var(&cfg.BridgeMinDepositAmount, "min-deposit-amount", defaultBridgeMinDepositAmountZat, "bridge minimum deposit amount in Juno base units")
	fs.Uint64Var(&cfg.BridgeMinWithdrawAmount, "min-withdraw-amount", defaultBridgeMinWithdrawAmountZat, "bridge minimum withdrawal amount in wJUNO base units")
	fs.StringVar(&governanceSafeHex, "governance-safe", "", "governance safe address that retains proposer/canceller/executor rights")
	fs.StringVar(&pauseGuardianHex, "pause-guardian", "", "pause guardian address")
	fs.StringVar(&minDepositAdminHex, "min-deposit-admin-address", "", "dedicated minDepositAdmin address")
	fs.Uint64Var(&cfg.TimelockMinDelaySeconds, "timelock-min-delay-seconds", defaultTimelockMinDelaySeconds, "final timelock minimum delay in seconds")
	fs.StringVar(&sweepRecipientHex, "sweep-recipient", "", "recipient for sweeping ephemeral deployer ETH (defaults to funder address)")
	fs.StringVar(&depositImageIDHex, "deposit-image-id", "0x000000000000000000000000000000000000000000000000000000000000aa01", "deposit image ID (bytes32)")
	fs.StringVar(&withdrawImageIDHex, "withdraw-image-id", "0x000000000000000000000000000000000000000000000000000000000000aa02", "withdraw image ID (bytes32)")
	fs.StringVar(&cfg.OutputPath, "output", "-", "output report path or '-' for stdout")
	fs.DurationVar(&cfg.RunTimeout, "run-timeout", defaultRunTimeout, "overall command timeout")

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
	if cfg.BridgeFeeBps == 0 || cfg.BridgeFeeBps > bridgeBPSDenominator {
		return cfg, errors.New("--fee-bps must be between 1 and 10000")
	}
	if cfg.BridgeRelayerTipBps > bridgeBPSDenominator {
		return cfg, errors.New("--relayer-tip-bps must be <= 10000")
	}
	if cfg.BridgeWithdrawalExpiryWindowSeconds == 0 {
		return cfg, errors.New("--withdrawal-expiry-window-seconds must be > 0")
	}
	if cfg.BridgeMaxExpiryExtensionSeconds == 0 {
		return cfg, errors.New("--max-expiry-extension-seconds must be > 0")
	}
	if cfg.BridgeMinDepositAmount == 0 {
		return cfg, errors.New("--min-deposit-amount must be > 0")
	}
	if cfg.BridgeMinWithdrawAmount == 0 {
		return cfg, errors.New("--min-withdraw-amount must be > 0")
	}
	if cfg.TimelockMinDelaySeconds == 0 {
		return cfg, errors.New("--timelock-min-delay-seconds must be > 0")
	}
	if cfg.RunTimeout <= 0 {
		return cfg, errors.New("--run-timeout must be > 0")
	}

	if deployerKeyFile != "" && cfg.DeployerKeyHex != "" {
		return cfg, errors.New("use only one of --deployer-key-file or --deployer-key-hex")
	}
	if funderKeyFile != "" && cfg.FunderKeyHex != "" {
		return cfg, errors.New("use only one of --funder-key-file or --funder-key-hex")
	}
	if deployerKeyFile != "" {
		key, err := readKeyFile(deployerKeyFile)
		if err != nil {
			return cfg, fmt.Errorf("read deployer key file: %w", err)
		}
		cfg.DeployerKeyHex = key
	}
	if funderKeyFile != "" {
		key, err := readKeyFile(funderKeyFile)
		if err != nil {
			return cfg, fmt.Errorf("read funder key file: %w", err)
		}
		cfg.FunderKeyHex = key
	}
	if cfg.DeployerKeyHex != "" && cfg.FunderKeyHex != "" {
		return cfg, errors.New("use either direct deployer mode or funder+ephemeral mode, not both")
	}
	if cfg.DeployerKeyHex == "" && cfg.FunderKeyHex == "" {
		return cfg, errors.New("a deployer or funder key is required")
	}
	if cfg.FunderKeyHex != "" {
		cfg.UseEphemeralDeployer = true
		if strings.TrimSpace(ephemeralFundingAmountWei) == "" {
			return cfg, errors.New("--ephemeral-funding-amount-wei is required with funder mode")
		}
		value, ok := new(big.Int).SetString(strings.TrimSpace(ephemeralFundingAmountWei), 10)
		if !ok || value.Sign() <= 0 {
			return cfg, errors.New("--ephemeral-funding-amount-wei must be a positive integer")
		}
		cfg.EphemeralFundingAmountWei = value
	}
	if cfg.DeployerKeyHex != "" && strings.TrimSpace(ephemeralFundingAmountWei) != "" {
		return cfg, errors.New("--ephemeral-funding-amount-wei requires funder mode")
	}

	var err error
	if cfg.VerifierAddress, err = parseRequiredAddress("--verifier-address", verifierAddressHex); err != nil {
		return cfg, err
	}
	if cfg.GovernanceSafe, err = parseRequiredAddress("--governance-safe", governanceSafeHex); err != nil {
		return cfg, err
	}
	if cfg.PauseGuardian, err = parseRequiredAddress("--pause-guardian", pauseGuardianHex); err != nil {
		return cfg, err
	}
	if cfg.MinDepositAdmin, err = parseRequiredAddress("--min-deposit-admin-address", minDepositAdminHex); err != nil {
		return cfg, err
	}
	if cfg.DepositImageID, err = parseRequiredHash("--deposit-image-id", depositImageIDHex); err != nil {
		return cfg, err
	}
	if cfg.WithdrawImageID, err = parseRequiredHash("--withdraw-image-id", withdrawImageIDHex); err != nil {
		return cfg, err
	}

	cfg.OperatorAddresses = make([]common.Address, 0, len(operatorAddressFlags))
	seen := make(map[common.Address]struct{}, len(operatorAddressFlags))
	for _, raw := range operatorAddressFlags {
		op, err := parseRequiredAddress("--operator-address", raw)
		if err != nil {
			return cfg, err
		}
		if _, exists := seen[op]; exists {
			return cfg, fmt.Errorf("duplicate --operator-address: %s", op.Hex())
		}
		seen[op] = struct{}{}
		cfg.OperatorAddresses = append(cfg.OperatorAddresses, op)
	}
	if len(cfg.OperatorAddresses) < cfg.Threshold {
		return cfg, fmt.Errorf("need at least %d operator addresses, got %d", cfg.Threshold, len(cfg.OperatorAddresses))
	}
	if len(operatorFeeRecipientFlags) != 0 && len(operatorFeeRecipientFlags) != len(cfg.OperatorAddresses) {
		return cfg, fmt.Errorf(
			"need either 0 or %d --operator-fee-recipient flags, got %d",
			len(cfg.OperatorAddresses),
			len(operatorFeeRecipientFlags),
		)
	}
	cfg.OperatorFeeRecipients = make([]common.Address, 0, len(cfg.OperatorAddresses))
	if len(operatorFeeRecipientFlags) == 0 {
		cfg.OperatorFeeRecipients = append(cfg.OperatorFeeRecipients, cfg.OperatorAddresses...)
	} else {
		for _, raw := range operatorFeeRecipientFlags {
			recipient, err := parseRequiredAddress("--operator-fee-recipient", raw)
			if err != nil {
				return cfg, err
			}
			cfg.OperatorFeeRecipients = append(cfg.OperatorFeeRecipients, recipient)
		}
	}

	if sweepRecipientHex != "" {
		if cfg.SweepRecipient, err = parseRequiredAddress("--sweep-recipient", sweepRecipientHex); err != nil {
			return cfg, err
		}
		cfg.SweepRecipientSet = true
	}
	if cfg.SweepRecipientSet && !cfg.UseEphemeralDeployer {
		return cfg, errors.New("--sweep-recipient requires funder mode")
	}

	_, minDepositNet, err := withdraw.ComputeFeeAndNet(cfg.BridgeMinDepositAmount, uint32(cfg.BridgeFeeBps))
	if err != nil {
		return cfg, fmt.Errorf("validate bridge deposit minimum: %w", err)
	}
	if minDepositNet < cfg.BridgeMinWithdrawAmount {
		return cfg, fmt.Errorf("--min-deposit-amount net=%d must cover --min-withdraw-amount=%d", minDepositNet, cfg.BridgeMinWithdrawAmount)
	}

	return cfg, nil
}

func deploy(ctx context.Context, client *ethclient.Client, cfg config) (*report, error) {
	rep := &report{
		GeneratedAtUTC:        time.Now().UTC().Format(time.RFC3339),
		RPCURL:                cfg.RPCURL,
		ChainID:               cfg.ChainID,
		Operators:             make([]string, 0, len(cfg.OperatorAddresses)),
		OperatorFeeRecipients: make([]string, 0, len(cfg.OperatorFeeRecipients)),
		Threshold:             cfg.Threshold,
	}
	rep.Contracts.Verifier = cfg.VerifierAddress.Hex()
	rep.Governance.GovernanceSafe = cfg.GovernanceSafe.Hex()
	rep.Governance.PauseGuardian = cfg.PauseGuardian.Hex()
	rep.Governance.MinDepositAdmin = cfg.MinDepositAdmin.Hex()
	rep.Governance.MinDelaySeconds = cfg.TimelockMinDelaySeconds
	rep.Governance.Proposers = []string{cfg.GovernanceSafe.Hex()}
	rep.Governance.Cancellers = []string{cfg.GovernanceSafe.Hex()}
	rep.Governance.Executors = []string{cfg.GovernanceSafe.Hex()}
	rep.Governance.BridgeUpdateSteps = []string{
		"deploy protocol contracts",
		"configure operator registry and bridge pointers",
		"set dedicated minDepositAdmin and pauseGuardian",
		"bootstrap timelock ownership acceptance at zero delay",
		"raise timelock delay to final production delay",
		"revoke bootstrap deployer timelock roles",
	}
	rep.BridgeParams.FeeBps = cfg.BridgeFeeBps
	rep.BridgeParams.RelayerTipBps = cfg.BridgeRelayerTipBps
	rep.BridgeParams.WithdrawalExpiryWindowSeconds = cfg.BridgeWithdrawalExpiryWindowSeconds
	rep.BridgeParams.MaxExpiryExtensionSeconds = cfg.BridgeMaxExpiryExtensionSeconds
	rep.BridgeParams.MinDepositAmount = cfg.BridgeMinDepositAmount
	rep.BridgeParams.MinWithdrawAmount = cfg.BridgeMinWithdrawAmount
	for i, op := range cfg.OperatorAddresses {
		rep.Operators = append(rep.Operators, op.Hex())
		rep.OperatorFeeRecipients = append(rep.OperatorFeeRecipients, cfg.OperatorFeeRecipients[i].Hex())
	}

	chainID := new(big.Int).SetUint64(cfg.ChainID)

	var (
		deployerKey  *ecdsa.PrivateKey
		deployerAuth *bind.TransactOpts
		deployerAddr common.Address
		funderKey    *ecdsa.PrivateKey
	)

	if cfg.UseEphemeralDeployer {
		var err error
		funderKey, err = parsePrivateKeyHex(cfg.FunderKeyHex)
		if err != nil {
			return nil, fmt.Errorf("parse funder key: %w", err)
		}
		funderAddr := crypto.PubkeyToAddress(funderKey.PublicKey)
		rep.Actors.FunderAddress = funderAddr.Hex()
		deployerKey, err = ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral deployer: %w", err)
		}
		deployerAddr = crypto.PubkeyToAddress(deployerKey.PublicKey)
		rep.Actors.EphemeralDeployerAddress = deployerAddr.Hex()
		if cfg.SweepRecipientSet {
			rep.Actors.SweepRecipient = cfg.SweepRecipient.Hex()
		} else {
			cfg.SweepRecipient = funderAddr
			rep.Actors.SweepRecipient = funderAddr.Hex()
		}
		fundTx, fundedAmount, err := fundEphemeralDeployer(ctx, client, funderKey, chainID, deployerAddr, cfg.EphemeralFundingAmountWei)
		if err != nil {
			return nil, fmt.Errorf("fund ephemeral deployer: %w", err)
		}
		if fundedAmount.Cmp(cfg.EphemeralFundingAmountWei) < 0 {
			fmt.Fprintf(os.Stderr, "bridge-deploy: lowering ephemeral funding from %s to %s to fit funder balance\n", cfg.EphemeralFundingAmountWei.String(), fundedAmount.String())
		}
		rep.Transactions.FundEphemeral = fundTx.Hex()
		if _, err := waitBigIntAtLeastAttempts(ctx, "ephemeral deployer balance", fundedAmount, ephemeralFundingReadRetries, ephemeralFundingReadBackoff, func() (*big.Int, error) {
			return client.BalanceAt(ctx, deployerAddr, nil)
		}); err != nil {
			return nil, fmt.Errorf("wait for ephemeral deployer funding: %w", err)
		}
	} else {
		var err error
		deployerKey, err = parsePrivateKeyHex(cfg.DeployerKeyHex)
		if err != nil {
			return nil, fmt.Errorf("parse deployer key: %w", err)
		}
		deployerAddr = crypto.PubkeyToAddress(deployerKey.PublicKey)
		rep.Actors.DirectDeployerAddress = deployerAddr.Hex()
	}

	var err error
	deployerAuth, err = bind.NewKeyedTransactorWithChainID(deployerKey, chainID)
	if err != nil {
		return nil, fmt.Errorf("create deployer auth: %w", err)
	}
	deployerAuth.Context = ctx
	if err := refreshAuthNonce(ctx, client, deployerAuth); err != nil {
		return nil, fmt.Errorf("refresh deployer nonce: %w", err)
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
	timelockABI, timelockBin, err := loadFoundryArtifact(filepath.Join(cfg.ContractsOut, "ProtocolTimelock.sol", "ProtocolTimelock.json"))
	if err != nil {
		return nil, err
	}

	wjunoAddr, deployWJunoTx, err := deployContract(ctx, client, deployerAuth, wjunoABI, wjunoBin, deployerAddr)
	if err != nil {
		return nil, fmt.Errorf("deploy wjuno: %w", err)
	}
	rep.Contracts.WJuno = wjunoAddr.Hex()
	rep.Transactions.DeployWJuno = deployWJunoTx.Hex()

	regAddr, deployRegistryTx, err := deployContract(ctx, client, deployerAuth, regABI, regBin, deployerAddr)
	if err != nil {
		return nil, fmt.Errorf("deploy operator registry: %w", err)
	}
	rep.Contracts.OperatorRegistry = regAddr.Hex()
	rep.Transactions.DeployOperatorRegistry = deployRegistryTx.Hex()

	fdAddr, deployFeeDistributorTx, err := deployContract(ctx, client, deployerAuth, fdABI, fdBin, deployerAddr, wjunoAddr, regAddr)
	if err != nil {
		return nil, fmt.Errorf("deploy fee distributor: %w", err)
	}
	rep.Contracts.FeeDistributor = fdAddr.Hex()
	rep.Transactions.DeployFeeDistributor = deployFeeDistributorTx.Hex()

	bridgeAddr, deployBridgeTx, err := deployContract(
		ctx,
		client,
		deployerAuth,
		bridgeABI,
		bridgeBin,
		deployerAddr,
		wjunoAddr,
		fdAddr,
		regAddr,
		cfg.VerifierAddress,
		cfg.DepositImageID,
		cfg.WithdrawImageID,
		new(big.Int).SetUint64(cfg.BridgeFeeBps),
		new(big.Int).SetUint64(cfg.BridgeRelayerTipBps),
		cfg.BridgeWithdrawalExpiryWindowSeconds,
		cfg.BridgeMaxExpiryExtensionSeconds,
		new(big.Int).SetUint64(cfg.BridgeMinDepositAmount),
		new(big.Int).SetUint64(cfg.BridgeMinWithdrawAmount),
	)
	if err != nil {
		return nil, fmt.Errorf("deploy bridge: %w", err)
	}
	rep.Contracts.Bridge = bridgeAddr.Hex()
	rep.Transactions.DeployBridge = deployBridgeTx.Hex()

	reg := bind.NewBoundContract(regAddr, regABI, client, client, client)
	fd := bind.NewBoundContract(fdAddr, fdABI, client, client, client)
	wjuno := bind.NewBoundContract(wjunoAddr, wjunoABI, client, client, client)
	bridge := bind.NewBoundContract(bridgeAddr, bridgeABI, client, client, client)

	setFeeDistributorTx, err := transactAndWait(ctx, client, deployerAuth, reg, "setFeeDistributor", fdAddr)
	if err != nil {
		return nil, fmt.Errorf("setFeeDistributor: %w", err)
	}
	rep.Transactions.SetFeeDistributor = setFeeDistributorTx.Hex()

	for _, binding := range sortedOperatorBindings(cfg.OperatorAddresses, cfg.OperatorFeeRecipients) {
		if _, err := transactAndWait(ctx, client, deployerAuth, reg, "setOperator", binding.Operator, binding.FeeRecipient, big.NewInt(1), true); err != nil {
			return nil, fmt.Errorf("setOperator(%s): %w", binding.Operator.Hex(), err)
		}
	}

	setThresholdTx, err := transactAndWait(ctx, client, deployerAuth, reg, "setThreshold", big.NewInt(int64(cfg.Threshold)))
	if err != nil {
		return nil, fmt.Errorf("setThreshold: %w", err)
	}
	rep.Transactions.SetThreshold = setThresholdTx.Hex()

	setBridgeWJunoTx, err := transactAndWait(ctx, client, deployerAuth, wjuno, "setBridge", bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("wjuno.setBridge: %w", err)
	}
	rep.Transactions.SetBridgeWJuno = setBridgeWJunoTx.Hex()

	setBridgeFeesTx, err := transactAndWait(ctx, client, deployerAuth, fd, "setBridge", bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("feeDistributor.setBridge: %w", err)
	}
	rep.Transactions.SetBridgeFees = setBridgeFeesTx.Hex()

	setMinDepositAdminTx, err := transactAndWait(ctx, client, deployerAuth, bridge, "setMinDepositAdmin", cfg.MinDepositAdmin)
	if err != nil {
		return nil, fmt.Errorf("bridge.setMinDepositAdmin: %w", err)
	}
	rep.Transactions.SetMinDepositAdmin = setMinDepositAdminTx.Hex()

	setPauseGuardianTx, err := transactAndWait(ctx, client, deployerAuth, bridge, "setPauseGuardian", cfg.PauseGuardian)
	if err != nil {
		return nil, fmt.Errorf("bridge.setPauseGuardian: %w", err)
	}
	rep.Transactions.SetPauseGuardian = setPauseGuardianTx.Hex()

	bootstrapRoles := []common.Address{cfg.GovernanceSafe, deployerAddr}
	timelockAddr, deployTimelockTx, err := deployContract(
		ctx,
		client,
		deployerAuth,
		timelockABI,
		timelockBin,
		new(big.Int).SetUint64(defaultBootstrapTimelockDelaySeconds),
		bootstrapRoles,
		bootstrapRoles,
		deployerAddr,
	)
	if err != nil {
		return nil, fmt.Errorf("deploy timelock: %w", err)
	}
	rep.Contracts.Timelock = timelockAddr.Hex()
	rep.Transactions.DeployTimelock = deployTimelockTx.Hex()
	rep.Governance.BootstrapProposer = deployerAddr.Hex()
	timelock := bind.NewBoundContract(timelockAddr, timelockABI, client, client, client)

	if tx, err := transactAndWait(ctx, client, deployerAuth, wjuno, "transferOwnership", timelockAddr); err != nil {
		return nil, fmt.Errorf("wjuno.transferOwnership: %w", err)
	} else {
		rep.Transactions.TransferOwnerships.WJuno = tx.Hex()
	}
	if tx, err := transactAndWait(ctx, client, deployerAuth, fd, "transferOwnership", timelockAddr); err != nil {
		return nil, fmt.Errorf("feeDistributor.transferOwnership: %w", err)
	} else {
		rep.Transactions.TransferOwnerships.FeeDistributor = tx.Hex()
	}
	if tx, err := transactAndWait(ctx, client, deployerAuth, reg, "transferOwnership", timelockAddr); err != nil {
		return nil, fmt.Errorf("operatorRegistry.transferOwnership: %w", err)
	} else {
		rep.Transactions.TransferOwnerships.OperatorRegistry = tx.Hex()
	}
	if tx, err := transactAndWait(ctx, client, deployerAuth, bridge, "transferOwnership", timelockAddr); err != nil {
		return nil, fmt.Errorf("bridge.transferOwnership: %w", err)
	} else {
		rep.Transactions.TransferOwnerships.Bridge = tx.Hex()
	}

	acceptors := []struct {
		name   string
		target common.Address
		abi    abi.ABI
		dst    *string
	}{
		{name: "wjuno", target: wjunoAddr, abi: wjunoABI, dst: &rep.Transactions.AcceptOwnerships.WJuno},
		{name: "fee-distributor", target: fdAddr, abi: fdABI, dst: &rep.Transactions.AcceptOwnerships.FeeDistributor},
		{name: "operator-registry", target: regAddr, abi: regABI, dst: &rep.Transactions.AcceptOwnerships.OperatorRegistry},
		{name: "bridge", target: bridgeAddr, abi: bridgeABI, dst: &rep.Transactions.AcceptOwnerships.Bridge},
	}
	for _, acceptor := range acceptors {
		callData, err := acceptor.abi.Pack("acceptOwnership")
		if err != nil {
			return nil, fmt.Errorf("pack %s.acceptOwnership: %w", acceptor.name, err)
		}
		_, execTx, err := timelockScheduleAndExecute(ctx, client, deployerAuth, timelock, acceptor.target, callData, acceptor.name+"-accept-ownership")
		if err != nil {
			return nil, fmt.Errorf("%s acceptOwnership via timelock: %w", acceptor.name, err)
		}
		*acceptor.dst = execTx.Hex()
	}

	updateDelayData, err := timelockABI.Pack("updateDelay", new(big.Int).SetUint64(cfg.TimelockMinDelaySeconds))
	if err != nil {
		return nil, fmt.Errorf("pack timelock.updateDelay: %w", err)
	}
	_, updateDelayExecTx, err := timelockScheduleAndExecute(ctx, client, deployerAuth, timelock, timelockAddr, updateDelayData, "timelock-update-delay")
	if err != nil {
		return nil, fmt.Errorf("timelock.updateDelay: %w", err)
	}
	rep.Transactions.UpdateTimelockDelay = updateDelayExecTx.Hex()

	if tx, err := revokeTimelockRole(ctx, client, deployerAuth, timelock, timelockProposerRole(), deployerAddr); err != nil {
		return nil, fmt.Errorf("revoke proposer role: %w", err)
	} else {
		rep.Transactions.RevokeBootstrapRoles.Proposer = tx.Hex()
	}
	if tx, err := revokeTimelockRole(ctx, client, deployerAuth, timelock, timelockCancellerRole(), deployerAddr); err != nil {
		return nil, fmt.Errorf("revoke canceller role: %w", err)
	} else {
		rep.Transactions.RevokeBootstrapRoles.Canceller = tx.Hex()
	}
	if tx, err := revokeTimelockRole(ctx, client, deployerAuth, timelock, timelockExecutorRole(), deployerAddr); err != nil {
		return nil, fmt.Errorf("revoke executor role: %w", err)
	} else {
		rep.Transactions.RevokeBootstrapRoles.Executor = tx.Hex()
	}
	adminRenounceTx, err := transactAndWait(ctx, client, deployerAuth, timelock, "renounceRole", timelockAdminRole(), deployerAddr)
	if err != nil {
		return nil, fmt.Errorf("renounce timelock admin role: %w", err)
	}
	rep.Transactions.RevokeBootstrapRoles.Admin = adminRenounceTx.Hex()

	if err := verifyDeployment(ctx, rep, bridge, wjuno, fd, reg, timelock, timelockAddr, cfg, deployerAddr); err != nil {
		return nil, err
	}

	if cfg.UseEphemeralDeployer {
		sweepTx, swept, err := sweepEphemeralDeployer(ctx, client, deployerKey, chainID, cfg.SweepRecipient)
		if err != nil {
			return nil, fmt.Errorf("sweep ephemeral deployer: %w", err)
		}
		if swept {
			rep.Transactions.SweepEphemeral = sweepTx.Hex()
		}
	}

	return rep, nil
}

func verifyDeployment(
	ctx context.Context,
	rep *report,
	bridge *bind.BoundContract,
	wjuno *bind.BoundContract,
	fd *bind.BoundContract,
	reg *bind.BoundContract,
	timelock *bind.BoundContract,
	timelockAddr common.Address,
	cfg config,
	deployerAddr common.Address,
) error {
	const (
		readRetries  = 8
		readBackoff  = 500 * time.Millisecond
		roleReadName = "timelock role"
	)

	ownerChecks := []struct {
		label string
		c     *bind.BoundContract
	}{
		{label: "wjuno owner", c: wjuno},
		{label: "feeDistributor owner", c: fd},
		{label: "operatorRegistry owner", c: reg},
		{label: "bridge owner", c: bridge},
	}
	for _, check := range ownerChecks {
		if _, err := waitAddressEqualAttempts(ctx, check.label, timelockAddr, readRetries, readBackoff, func() (common.Address, error) {
			return callAddress(ctx, check.c, "owner")
		}); err != nil {
			return err
		}
	}

	operatorCount, err := waitUint64AtLeastAttempts(ctx, "operatorCount", uint64(len(cfg.OperatorAddresses)), readRetries, readBackoff, func() (uint64, error) {
		return callUint64(ctx, reg, "operatorCount")
	})
	if err != nil {
		return err
	}
	if operatorCount != uint64(len(cfg.OperatorAddresses)) {
		return fmt.Errorf("operatorCount mismatch: got=%d want=%d", operatorCount, len(cfg.OperatorAddresses))
	}
	for _, binding := range sortedOperatorBindings(cfg.OperatorAddresses, cfg.OperatorFeeRecipients) {
		feeRecipient, err := callOperatorFeeRecipient(ctx, reg, binding.Operator)
		if err != nil {
			return fmt.Errorf("operatorRegistry.getOperator(%s): %w", binding.Operator.Hex(), err)
		}
		if feeRecipient != binding.FeeRecipient {
			return fmt.Errorf(
				"operator feeRecipient mismatch for %s: got=%s want=%s",
				binding.Operator.Hex(),
				feeRecipient.Hex(),
				binding.FeeRecipient.Hex(),
			)
		}
	}
	threshold, err := waitUint64AtLeastAttempts(ctx, "threshold", uint64(cfg.Threshold), readRetries, readBackoff, func() (uint64, error) {
		return callUint64(ctx, reg, "threshold")
	})
	if err != nil {
		return err
	}
	if threshold != uint64(cfg.Threshold) {
		return fmt.Errorf("threshold mismatch: got=%d want=%d", threshold, cfg.Threshold)
	}

	minDepositAdmin, err := callAddress(ctx, bridge, "minDepositAdmin")
	if err != nil {
		return fmt.Errorf("bridge.minDepositAdmin: %w", err)
	}
	if minDepositAdmin != cfg.MinDepositAdmin {
		return fmt.Errorf("bridge minDepositAdmin mismatch: got=%s want=%s", minDepositAdmin.Hex(), cfg.MinDepositAdmin.Hex())
	}
	pauseGuardian, err := callAddress(ctx, bridge, "pauseGuardian")
	if err != nil {
		return fmt.Errorf("bridge.pauseGuardian: %w", err)
	}
	if pauseGuardian != cfg.PauseGuardian {
		return fmt.Errorf("bridge pauseGuardian mismatch: got=%s want=%s", pauseGuardian.Hex(), cfg.PauseGuardian.Hex())
	}

	minDelay, err := callUint64(ctx, timelock, "getMinDelay")
	if err != nil {
		return fmt.Errorf("timelock.getMinDelay: %w", err)
	}
	if minDelay != cfg.TimelockMinDelaySeconds {
		return fmt.Errorf("timelock minDelay mismatch: got=%d want=%d", minDelay, cfg.TimelockMinDelaySeconds)
	}

	roleChecks := []struct {
		role  common.Hash
		addr  common.Address
		want  bool
		label string
	}{
		{role: timelockProposerRole(), addr: cfg.GovernanceSafe, want: true, label: roleReadName + " proposer safe"},
		{role: timelockCancellerRole(), addr: cfg.GovernanceSafe, want: true, label: roleReadName + " canceller safe"},
		{role: timelockExecutorRole(), addr: cfg.GovernanceSafe, want: true, label: roleReadName + " executor safe"},
		{role: timelockProposerRole(), addr: deployerAddr, want: false, label: roleReadName + " proposer deployer"},
		{role: timelockCancellerRole(), addr: deployerAddr, want: false, label: roleReadName + " canceller deployer"},
		{role: timelockExecutorRole(), addr: deployerAddr, want: false, label: roleReadName + " executor deployer"},
		{role: timelockAdminRole(), addr: deployerAddr, want: false, label: roleReadName + " admin deployer"},
	}
	for _, check := range roleChecks {
		got, err := callBool(ctx, timelock, "hasRole", check.role, check.addr)
		if err != nil {
			return fmt.Errorf("%s: %w", check.label, err)
		}
		if got != check.want {
			return fmt.Errorf("%s mismatch: got=%v want=%v", check.label, got, check.want)
		}
	}

	return nil
}

func writeReport(path string, rep *report, stdout io.Writer) error {
	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if path == "-" {
		_, err = stdout.Write(append(out, '\n'))
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir report dir: %w", err)
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func readKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func parseRequiredAddress(flagName, raw string) (common.Address, error) {
	if !common.IsHexAddress(raw) {
		return common.Address{}, fmt.Errorf("%s must be a valid hex address", flagName)
	}
	addr := common.HexToAddress(raw)
	if addr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("%s must not be zero", flagName)
	}
	return addr, nil
}

func parseRequiredHash(flagName, raw string) (common.Hash, error) {
	if !common.IsHexAddress("0x"+strings.TrimPrefix(strings.TrimSpace(raw), "0x")) && len(strings.TrimPrefix(strings.TrimSpace(raw), "0x")) != 64 {
		// continue to hex decode for accurate error below
	}
	b, err := hexutil.Decode(raw)
	if err != nil {
		return common.Hash{}, fmt.Errorf("%s: %w", flagName, err)
	}
	if len(b) != common.HashLength {
		return common.Hash{}, fmt.Errorf("%s must be 32 bytes", flagName)
	}
	return common.BytesToHash(b), nil
}

func parsePrivateKeyHex(raw string) (*ecdsa.PrivateKey, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "0x"))
	if trimmed == "" {
		return nil, errors.New("empty private key")
	}
	return crypto.HexToECDSA(trimmed)
}

func loadFoundryArtifact(path string) (abi.ABI, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return abi.ABI{}, nil, fmt.Errorf("read artifact %s: %w", path, err)
	}
	var artifact foundryArtifact
	if err := json.Unmarshal(b, &artifact); err != nil {
		return abi.ABI{}, nil, fmt.Errorf("unmarshal artifact %s: %w", path, err)
	}
	parsed, err := abi.JSON(bytes.NewReader(artifact.ABI))
	if err != nil {
		return abi.ABI{}, nil, fmt.Errorf("parse abi %s: %w", path, err)
	}
	code, err := hexutil.Decode(artifact.Bytecode.Object)
	if err != nil {
		return abi.ABI{}, nil, fmt.Errorf("decode bytecode %s: %w", path, err)
	}
	return parsed, code, nil
}

func deployContract(ctx context.Context, backend evmBackend, auth *bind.TransactOpts, parsedABI abi.ABI, bin []byte, args ...any) (common.Address, common.Hash, error) {
	for attempt := 1; attempt <= 4; attempt++ {
		txAuth := transactAuthWithDefaults(auth, 4_000_000)
		applyRetryGasBump(ctx, backend, txAuth, attempt)
		addr, tx, _, err := bind.DeployContract(txAuth, parsedABI, bin, backend, args...)
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
		receipt, err := waitMinedWithGrace(ctx, backend, tx)
		if err != nil {
			if ctx.Err() == nil && isRetriableWaitMinedError(err) {
				recovered, recoverErr := waitForCodeAtAddress(ctx, backend, addr, deployCodeRecoveryTimeout, deployCodeRecoveryPollInterval)
				if recoverErr == nil && recovered {
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
		if receipt.Status != 1 {
			return common.Address{}, common.Hash{}, fmt.Errorf("deployment reverted: %s", tx.Hash().Hex())
		}
		return addr, tx.Hash(), nil
	}
	return common.Address{}, common.Hash{}, errors.New("deploy contract retries exhausted")
}

func transactAndWait(ctx context.Context, backend txBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, args ...any) (common.Hash, error) {
	for attempt := 1; attempt <= 4; attempt++ {
		txAuth := transactAuthWithDefaults(auth, 1_000_000)
		applyRetryGasBump(ctx, backend, txAuth, attempt)
		tx, err := c.Transact(txAuth, method, args...)
		if err != nil {
			if attempt < 4 && isRetriableNonceError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Hash{}, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Hash{}, err
		}
		incrementAuthNonce(auth)
		receipt, err := waitMinedWithGrace(ctx, backend, tx)
		if err != nil {
			if ctx.Err() == nil && attempt < 4 && isRetriableWaitMinedError(err) {
				if nonceErr := refreshAuthNonce(ctx, backend, auth); nonceErr != nil {
					return common.Hash{}, fmt.Errorf("%w (and refresh nonce failed: %v)", err, nonceErr)
				}
				continue
			}
			return common.Hash{}, err
		}
		if receipt.Status != 1 {
			return common.Hash{}, fmt.Errorf("%s reverted: %s", method, tx.Hash().Hex())
		}
		return tx.Hash(), nil
	}
	return common.Hash{}, fmt.Errorf("%s retries exhausted", method)
}

func timelockScheduleAndExecute(
	ctx context.Context,
	backend txBackend,
	auth *bind.TransactOpts,
	timelock *bind.BoundContract,
	target common.Address,
	data []byte,
	label string,
) (common.Hash, common.Hash, error) {
	var predecessor [32]byte
	salt := crypto.Keccak256Hash([]byte(label))
	scheduleTx, err := transactAndWait(ctx, backend, auth, timelock, "schedule", target, big.NewInt(0), data, predecessor, salt, big.NewInt(0))
	if err != nil {
		return common.Hash{}, common.Hash{}, err
	}
	executeTx, err := transactAndWait(ctx, backend, auth, timelock, "execute", target, big.NewInt(0), data, predecessor, salt)
	if err != nil {
		return common.Hash{}, common.Hash{}, err
	}
	return scheduleTx, executeTx, nil
}

func revokeTimelockRole(ctx context.Context, backend txBackend, auth *bind.TransactOpts, timelock *bind.BoundContract, role common.Hash, addr common.Address) (common.Hash, error) {
	return transactAndWait(ctx, backend, auth, timelock, "revokeRole", role, addr)
}

func sendValueTx(ctx context.Context, client *ethclient.Client, key *ecdsa.PrivateKey, chainID *big.Int, to common.Address, value *big.Int) (common.Hash, error) {
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("suggest gas price: %w", err)
	}
	return sendValueTxWithGasPrice(ctx, client, key, chainID, to, value, gasPrice)
}

type fundingBalanceReader func(context.Context) (*big.Int, error)
type fundingGasPriceReader func(context.Context) (*big.Int, error)
type fundingSender func(context.Context, *big.Int, *big.Int) (common.Hash, error)

func fundEphemeralDeployer(ctx context.Context, client *ethclient.Client, key *ecdsa.PrivateKey, chainID *big.Int, to common.Address, requested *big.Int) (common.Hash, *big.Int, error) {
	from := crypto.PubkeyToAddress(key.PublicKey)
	return fundEphemeralDeployerWithRetry(
		ctx,
		requested,
		func(ctx context.Context) (*big.Int, error) {
			balance, err := client.PendingBalanceAt(ctx, from)
			if err != nil {
				return nil, fmt.Errorf("read pending funder balance: %w", err)
			}
			return balance, nil
		},
		func(ctx context.Context) (*big.Int, error) {
			gasPrice, err := client.SuggestGasPrice(ctx)
			if err != nil {
				return nil, fmt.Errorf("suggest funding gas price: %w", err)
			}
			return gasPrice, nil
		},
		func(ctx context.Context, value, gasPrice *big.Int) (common.Hash, error) {
			return sendValueTxWithGasPrice(ctx, client, key, chainID, to, value, gasPrice)
		},
	)
}

func fundingValueWei(requested, balance, fee *big.Int) (*big.Int, bool) {
	if requested == nil || requested.Sign() <= 0 || balance == nil || fee == nil {
		return big.NewInt(0), false
	}
	if balance.Cmp(fee) <= 0 {
		return big.NewInt(0), false
	}
	affordable := new(big.Int).Sub(balance, fee)
	if affordable.Cmp(requested) >= 0 {
		return new(big.Int).Set(requested), true
	}
	return affordable, true
}

type sweepBalanceReader func(context.Context) (*big.Int, error)
type sweepGasPriceReader func(context.Context) (*big.Int, error)
type sweepSender func(context.Context, *big.Int, *big.Int) (common.Hash, error)

func fundEphemeralDeployerWithRetry(ctx context.Context, requested *big.Int, readBalance fundingBalanceReader, suggestGasPrice fundingGasPriceReader, send fundingSender) (common.Hash, *big.Int, error) {
	extraReserve := big.NewInt(0)
	for attempt := 0; attempt < sweepRetryAttempts; attempt++ {
		balance, err := readBalance(ctx)
		if err != nil {
			return common.Hash{}, nil, err
		}
		gasPrice, err := suggestGasPrice(ctx)
		if err != nil {
			return common.Hash{}, nil, err
		}
		fee := new(big.Int).Add(legacyValueTransferFeeWei(gasPrice), extraReserve)
		value, ok := fundingValueWei(requested, balance, fee)
		if !ok {
			return common.Hash{}, nil, fmt.Errorf("funder balance %s does not cover transfer fee %s", balance.String(), fee.String())
		}
		txHash, err := send(ctx, value, gasPrice)
		if err == nil {
			return txHash, value, nil
		}
		if isRetriableNonceError(err) || errors.Is(err, context.DeadlineExceeded) {
			if attempt+1 >= sweepRetryAttempts {
				return common.Hash{}, nil, err
			}
			select {
			case <-ctx.Done():
				return common.Hash{}, nil, ctx.Err()
			case <-time.After(sweepRetryBackoff):
			}
			continue
		}

		shortage, ok := insufficientFundsShortageWei(err)
		if !ok {
			return common.Hash{}, nil, err
		}
		extraReserve = new(big.Int).Add(extraReserve, new(big.Int).Add(shortage, big.NewInt(sweepValueSafetyBufferWei)))
		if attempt+1 >= sweepRetryAttempts {
			return common.Hash{}, nil, err
		}
		select {
		case <-ctx.Done():
			return common.Hash{}, nil, ctx.Err()
		case <-time.After(sweepRetryBackoff):
		}
	}
	return common.Hash{}, nil, nil
}

func sweepEphemeralDeployer(ctx context.Context, client *ethclient.Client, key *ecdsa.PrivateKey, chainID *big.Int, to common.Address) (common.Hash, bool, error) {
	from := crypto.PubkeyToAddress(key.PublicKey)
	return sweepEphemeralDeployerWithRetry(
		ctx,
		func(ctx context.Context) (*big.Int, error) {
			balance, err := client.PendingBalanceAt(ctx, from)
			if err != nil {
				return nil, fmt.Errorf("read pending ephemeral deployer balance: %w", err)
			}
			return balance, nil
		},
		func(ctx context.Context) (*big.Int, error) {
			gasPrice, err := client.SuggestGasPrice(ctx)
			if err != nil {
				return nil, fmt.Errorf("suggest sweep gas price: %w", err)
			}
			return gasPrice, nil
		},
		func(ctx context.Context, value, gasPrice *big.Int) (common.Hash, error) {
			return sendValueTxWithGasPrice(ctx, client, key, chainID, to, value, gasPrice)
		},
	)
}

func sweepEphemeralDeployerWithRetry(ctx context.Context, readBalance sweepBalanceReader, suggestGasPrice sweepGasPriceReader, send sweepSender) (common.Hash, bool, error) {
	extraReserve := big.NewInt(0)
	for attempt := 0; attempt < sweepRetryAttempts; attempt++ {
		balance, err := readBalance(ctx)
		if err != nil {
			return common.Hash{}, false, err
		}
		gasPrice, err := suggestGasPrice(ctx)
		if err != nil {
			return common.Hash{}, false, err
		}
		fee := new(big.Int).Add(sweepReservedFeeWei(gasPrice), extraReserve)
		value, ok := sweepValueWei(balance, fee)
		if !ok {
			return common.Hash{}, false, nil
		}
		txHash, err := send(ctx, value, gasPrice)
		if err == nil {
			return txHash, true, nil
		}
		if isRetriableNonceError(err) || errors.Is(err, context.DeadlineExceeded) {
			if attempt+1 >= sweepRetryAttempts {
				return common.Hash{}, false, err
			}
			select {
			case <-ctx.Done():
				return common.Hash{}, false, ctx.Err()
			case <-time.After(sweepRetryBackoff):
			}
			continue
		}

		shortage, ok := insufficientFundsShortageWei(err)
		if !ok {
			return common.Hash{}, false, err
		}
		extraReserve = new(big.Int).Add(shortage, big.NewInt(sweepValueSafetyBufferWei))
		if attempt+1 >= sweepRetryAttempts {
			return common.Hash{}, false, err
		}
		select {
		case <-ctx.Done():
			return common.Hash{}, false, ctx.Err()
		case <-time.After(sweepRetryBackoff):
		}
	}
	return common.Hash{}, false, nil
}

func sendValueTxWithGasPrice(ctx context.Context, client *ethclient.Client, key *ecdsa.PrivateKey, chainID *big.Int, to common.Address, value, gasPrice *big.Int) (common.Hash, error) {
	from := crypto.PubkeyToAddress(key.PublicKey)
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return common.Hash{}, fmt.Errorf("read pending nonce: %w", err)
	}
	tx := buildLegacyValueTransferTx(nonce, to, value, gasPrice)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), key)
	if err != nil {
		return common.Hash{}, fmt.Errorf("sign tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		return common.Hash{}, fmt.Errorf("send tx: %w", err)
	}
	receipt, err := waitMinedWithGrace(ctx, client, signed)
	if err != nil {
		return common.Hash{}, err
	}
	if receipt.Status != 1 {
		return common.Hash{}, fmt.Errorf("value transfer reverted: %s", signed.Hash().Hex())
	}
	return signed.Hash(), nil
}

func buildLegacyValueTransferTx(nonce uint64, to common.Address, value, gasPrice *big.Int) *types.Transaction {
	return types.NewTransaction(nonce, to, value, legacyValueTransferGasLimit, gasPrice, nil)
}

func legacyValueTransferFeeWei(gasPrice *big.Int) *big.Int {
	if gasPrice == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Mul(new(big.Int).Set(gasPrice), new(big.Int).SetUint64(legacyValueTransferGasLimit))
}

func sweepReservedFeeWei(gasPrice *big.Int) *big.Int {
	return new(big.Int).Add(legacyValueTransferFeeWei(gasPrice), big.NewInt(sweepValueSafetyBufferWei))
}

func sweepValueWei(balance, fee *big.Int) (*big.Int, bool) {
	if balance == nil || fee == nil {
		return big.NewInt(0), false
	}
	if balance.Cmp(fee) < 0 {
		return big.NewInt(0), false
	}
	return new(big.Int).Sub(balance, fee), true
}

func insufficientFundsShortageWei(err error) (*big.Int, bool) {
	if err == nil {
		return big.NewInt(0), false
	}
	message := err.Error()
	if shortage, ok := parseInsufficientFundsHaveWant(message); ok {
		return shortage, true
	}
	if shortage, ok := parseInsufficientFundsOvershot(message); ok {
		return shortage, true
	}
	return big.NewInt(0), false
}

func parseInsufficientFundsHaveWant(message string) (*big.Int, bool) {
	const marker = "insufficient funds for gas * price + value: have "
	idx := strings.Index(message, marker)
	if idx < 0 {
		return big.NewInt(0), false
	}
	fields := strings.Fields(message[idx+len(marker):])
	if len(fields) < 3 || fields[1] != "want" {
		return big.NewInt(0), false
	}
	have, ok := new(big.Int).SetString(fields[0], 10)
	if !ok {
		return big.NewInt(0), false
	}
	want, ok := new(big.Int).SetString(fields[2], 10)
	if !ok {
		return big.NewInt(0), false
	}
	if want.Cmp(have) <= 0 {
		return big.NewInt(0), true
	}
	return new(big.Int).Sub(want, have), true
}

func parseInsufficientFundsOvershot(message string) (*big.Int, bool) {
	const marker = "insufficient funds for gas * price + value: balance "
	idx := strings.Index(message, marker)
	if idx < 0 {
		return big.NewInt(0), false
	}
	fields := strings.Fields(strings.ReplaceAll(message[idx+len(marker):], ",", ""))
	if len(fields) < 6 || fields[1] != "tx" || fields[2] != "cost" || fields[4] != "overshot" {
		return big.NewInt(0), false
	}
	shortage, ok := new(big.Int).SetString(fields[5], 10)
	if !ok {
		return big.NewInt(0), false
	}
	if shortage.Sign() < 0 {
		return big.NewInt(0), false
	}
	return shortage, true
}

func transactAuthWithDefaults(auth *bind.TransactOpts, defaultGasLimit uint64) *bind.TransactOpts {
	if auth == nil {
		return nil
	}
	cloned := *auth
	if cloned.GasLimit == 0 && defaultGasLimit > 0 {
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
	if txAuth == nil {
		return
	}
	if attempt < 1 {
		attempt = 1
	}
	multiplier := retryGasMultiplier(attempt)
	gasPriceBase := preferredGasValue(ctx, backend, txAuth.GasPrice, big.NewInt(defaultRetryGasPriceWei))
	if suggester, ok := backend.(gasTipCapSuggester); ok {
		tipBase := preferredTipCap(ctx, suggester, txAuth.GasTipCap, big.NewInt(defaultRetryGasTipCapWei))

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

func preferredGasValue(ctx context.Context, backend any, explicitValue *big.Int, fallback *big.Int) *big.Int {
	if explicitValue != nil && explicitValue.Sign() > 0 {
		return new(big.Int).Set(explicitValue)
	}
	if suggester, ok := backend.(gasPriceSuggester); ok {
		if suggested, err := suggester.SuggestGasPrice(ctx); err == nil && suggested != nil && suggested.Sign() > 0 {
			return new(big.Int).Set(suggested)
		}
	}
	return new(big.Int).Set(fallback)
}

func preferredTipCap(ctx context.Context, suggester gasTipCapSuggester, explicitValue *big.Int, fallback *big.Int) *big.Int {
	if explicitValue != nil && explicitValue.Sign() > 0 {
		return new(big.Int).Set(explicitValue)
	}
	if suggested, err := suggester.SuggestGasTipCap(ctx); err == nil && suggested != nil && suggested.Sign() > 0 {
		return new(big.Int).Set(suggested)
	}
	return new(big.Int).Set(fallback)
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

func waitMinedWithGrace(ctx context.Context, backend bind.DeployBackend, tx *types.Transaction) (*types.Receipt, error) {
	waitCtx, cancel := context.WithTimeout(ctx, txMinedWaitTimeout)
	receipt, err := bind.WaitMined(waitCtx, backend, tx)
	cancel()
	if err == nil || ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded) {
		return receipt, err
	}
	graceCtx, graceCancel := context.WithTimeout(ctx, txMinedGraceTimeout)
	defer graceCancel()
	return bind.WaitMined(graceCtx, backend, tx)
}

type codeAtBackend interface {
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

func waitForCodeAtAddress(ctx context.Context, backend codeAtBackend, addr common.Address, timeout time.Duration, pollInterval time.Duration) (bool, error) {
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

func waitUint64AtLeastAttempts(
	ctx context.Context,
	label string,
	want uint64,
	attempts int,
	interval time.Duration,
	readFn func() (uint64, error),
) (uint64, error) {
	if attempts < 1 {
		attempts = 1
	}
	var (
		lastVal uint64
		lastErr error
	)
	for i := 0; i < attempts; i++ {
		val, err := readFn()
		if err != nil {
			lastErr = err
		} else {
			lastVal = val
			lastErr = nil
			if val == want {
				return val, nil
			}
		}
		if i == attempts-1 || interval <= 0 {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastVal, ctx.Err()
		case <-timer.C:
		}
	}
	if lastErr != nil {
		return lastVal, fmt.Errorf("%s read failed after %d attempts: %w", label, attempts, lastErr)
	}
	return lastVal, nil
}

func waitAddressEqualAttempts(
	ctx context.Context,
	label string,
	want common.Address,
	attempts int,
	interval time.Duration,
	readFn func() (common.Address, error),
) (common.Address, error) {
	if attempts < 1 {
		attempts = 1
	}
	var (
		lastVal common.Address
		lastErr error
	)
	for i := 0; i < attempts; i++ {
		val, err := readFn()
		if err != nil {
			lastErr = err
		} else {
			lastVal = val
			lastErr = nil
			if val == want {
				return val, nil
			}
		}
		if i == attempts-1 || interval <= 0 {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastVal, ctx.Err()
		case <-timer.C:
		}
	}
	if lastErr != nil {
		return lastVal, fmt.Errorf("%s read failed after %d attempts: %w", label, attempts, lastErr)
	}
	return lastVal, fmt.Errorf("%s mismatch: got=%s want=%s", label, lastVal.Hex(), want.Hex())
}

func waitBigIntAtLeastAttempts(
	ctx context.Context,
	label string,
	want *big.Int,
	attempts int,
	interval time.Duration,
	readFn func() (*big.Int, error),
) (*big.Int, error) {
	if attempts < 1 {
		attempts = 1
	}
	if want == nil {
		want = big.NewInt(0)
	}
	lastVal := big.NewInt(0)
	var lastErr error
	for i := 0; i < attempts; i++ {
		val, err := readFn()
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			if val == nil {
				lastVal = big.NewInt(0)
			} else {
				lastVal = new(big.Int).Set(val)
			}
			if lastVal.Cmp(want) >= 0 {
				return lastVal, nil
			}
		}
		if i == attempts-1 || interval <= 0 {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastVal, ctx.Err()
		case <-timer.C:
		}
	}
	if lastErr != nil {
		return lastVal, fmt.Errorf("%s read failed after %d attempts: %w", label, attempts, lastErr)
	}
	return lastVal, fmt.Errorf("%s mismatch: got=%s want_at_least=%s", label, lastVal.String(), want.String())
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

func callBool(ctx context.Context, c contractCaller, method string, args ...any) (bool, error) {
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

func callOperatorFeeRecipient(ctx context.Context, c contractCaller, operator common.Address) (common.Address, error) {
	var res []any
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, "getOperator", operator); err != nil {
		return common.Address{}, err
	}
	if len(res) != 3 {
		return common.Address{}, fmt.Errorf("unexpected getOperator result count: %d", len(res))
	}
	switch v := res[0].(type) {
	case common.Address:
		return v, nil
	case [20]byte:
		return common.BytesToAddress(v[:]), nil
	default:
		return common.Address{}, fmt.Errorf("unexpected getOperator feeRecipient type: %T", res[0])
	}
}

func sortedOperatorBindings(operators, feeRecipients []common.Address) []operatorBinding {
	if len(operators) != len(feeRecipients) {
		return nil
	}
	bindings := make([]operatorBinding, len(operators))
	for i := range operators {
		bindings[i] = operatorBinding{
			Operator:     operators[i],
			FeeRecipient: feeRecipients[i],
		}
	}
	sort.Slice(bindings, func(i, j int) bool {
		return bytes.Compare(bindings[i].Operator.Bytes(), bindings[j].Operator.Bytes()) < 0
	})
	return bindings
}

func timelockAdminRole() common.Hash {
	return crypto.Keccak256Hash([]byte("TIMELOCK_ADMIN_ROLE"))
}

func timelockProposerRole() common.Hash {
	return crypto.Keccak256Hash([]byte("PROPOSER_ROLE"))
}

func timelockCancellerRole() common.Hash {
	return crypto.Keccak256Hash([]byte("CANCELLER_ROLE"))
}

func timelockExecutorRole() common.Hash {
	return crypto.Keccak256Hash([]byte("EXECUTOR_ROLE"))
}
