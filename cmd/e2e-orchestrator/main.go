package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/e2eorch"
)

func main() {
	var (
		// HTTP endpoints.
		bridgeAPIURL = flag.String("bridge-api-url", "", "bridge-api base URL (required)")
		baseRPCURL   = flag.String("base-rpc-url", "", "Base chain RPC URL (required)")
		baseChainID  = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		junoRPCURL   = flag.String("juno-rpc-url", "", "Juno RPC URL (required)")

		// Contract addresses.
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")
		wjunoAddr   = flag.String("wjuno-address", "", "wJUNO token address (required)")
		feeDistAddr = flag.String("fee-distributor-address", "", "FeeDistributor address (required)")

		// Recipient and Juno wallet.
		recipientAddr  = flag.String("recipient-address", "", "Base recipient address for deposit (required)")
		junoFunderAddr = flag.String("juno-funder-source-address", "", "Juno t-addr or UA that funds the deposit (required)")
		owalletUA      = flag.String("owallet-ua", "", "Orchard wallet UA for the bridge (required)")
		junoWalletID   = flag.String("juno-wallet-id", "", "Juno wallet name for witness extraction (required)")

		// Test amounts.
		depositAmountZat = flag.Uint64("deposit-amount-zat", 100000, "deposit amount in zatoshis")
		withdrawAmount   = flag.Uint64("withdraw-amount", 10000, "withdrawal amount")
		withdrawRecipientRawHex = flag.String("withdraw-recipient-raw-hex", "", "43-byte raw UA hex for withdrawal recipient (required)")

		// Witness extraction.
		junoScanURL    = flag.String("juno-scan-url", "", "juno-scan URL (required)")
		witnessExtractBin = flag.String("witness-extract-bin", "juno-witness-extract", "path to juno-witness-extract binary")

		// Timeouts.
		runTimeout      = flag.Duration("run-timeout", 45*time.Minute, "overall run timeout")
		depositTimeout  = flag.Duration("deposit-timeout", 20*time.Minute, "deposit flow timeout")
		withdrawTimeout = flag.Duration("withdraw-timeout", 30*time.Minute, "withdrawal flow timeout")
		pollInterval    = flag.Duration("poll-interval", 5*time.Second, "status poll interval")

		// IPFS and fee params.
		ipfsAPIURL     = flag.String("ipfs-api-url", "", "IPFS gateway URL for checkpoint verification (optional)")
		expectedFeeBps = flag.Uint64("expected-fee-bps", 50, "expected withdrawal fee in basis points")
		expectedTipBps = flag.Uint64("expected-tip-bps", 1000, "expected tip portion of fee in basis points")

		// Output.
		output = flag.String("output", "-", "output file for report (default: stdout)")
	)

	flag.Parse()

	// Read credentials from environment.
	junoRPCUser := os.Getenv("JUNO_RPC_USER")
	junoRPCPass := os.Getenv("JUNO_RPC_PASS")
	junoScanBearerToken := os.Getenv("JUNO_SCAN_BEARER_TOKEN")

	// Validate required flags.
	var missing []string
	if *bridgeAPIURL == "" {
		missing = append(missing, "--bridge-api-url")
	}
	if *baseRPCURL == "" {
		missing = append(missing, "--base-rpc-url")
	}
	if *baseChainID == 0 {
		missing = append(missing, "--base-chain-id")
	}
	if *junoRPCURL == "" {
		missing = append(missing, "--juno-rpc-url")
	}
	if *bridgeAddr == "" {
		missing = append(missing, "--bridge-address")
	}
	if *wjunoAddr == "" {
		missing = append(missing, "--wjuno-address")
	}
	if *feeDistAddr == "" {
		missing = append(missing, "--fee-distributor-address")
	}
	if *recipientAddr == "" {
		missing = append(missing, "--recipient-address")
	}
	if *junoFunderAddr == "" {
		missing = append(missing, "--juno-funder-source-address")
	}
	if *owalletUA == "" {
		missing = append(missing, "--owallet-ua")
	}
	if *junoWalletID == "" {
		missing = append(missing, "--juno-wallet-id")
	}
	if *withdrawRecipientRawHex == "" {
		missing = append(missing, "--withdraw-recipient-raw-hex")
	}
	if *junoScanURL == "" {
		missing = append(missing, "--juno-scan-url")
	}
	if junoRPCUser == "" {
		missing = append(missing, "JUNO_RPC_USER (env)")
	}
	if junoRPCPass == "" {
		missing = append(missing, "JUNO_RPC_PASS (env)")
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "error: missing required flags/env: %s\n", strings.Join(missing, ", "))
		flag.Usage()
		os.Exit(2)
	}

	// Validate addresses.
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if !common.IsHexAddress(*wjunoAddr) {
		fmt.Fprintln(os.Stderr, "error: --wjuno-address must be a valid hex address")
		os.Exit(2)
	}
	if !common.IsHexAddress(*feeDistAddr) {
		fmt.Fprintln(os.Stderr, "error: --fee-distributor-address must be a valid hex address")
		os.Exit(2)
	}
	if !common.IsHexAddress(*recipientAddr) {
		fmt.Fprintln(os.Stderr, "error: --recipient-address must be a valid hex address")
		os.Exit(2)
	}

	cfg := e2eorch.E2EConfig{
		BridgeAPIURL: *bridgeAPIURL,
		BaseRPCURL:   *baseRPCURL,
		BaseChainID:  *baseChainID,
		JunoRPCURL:   *junoRPCURL,
		JunoRPCUser:  junoRPCUser,
		JunoRPCPass:  junoRPCPass,

		BridgeAddress:         common.HexToAddress(*bridgeAddr),
		WJunoAddress:          common.HexToAddress(*wjunoAddr),
		FeeDistributorAddress: common.HexToAddress(*feeDistAddr),
		RecipientAddress:      common.HexToAddress(*recipientAddr),

		JunoFunderSourceAddress: *junoFunderAddr,
		OWalletUA:               *owalletUA,
		JunoWalletID:            *junoWalletID,

		DepositAmountZat: *depositAmountZat,
		WithdrawAmount:   *withdrawAmount,

		WithdrawRecipientRawHex: *withdrawRecipientRawHex,

		JunoScanURL:         *junoScanURL,
		JunoScanBearerToken: junoScanBearerToken,
		WitnessExtractBin:   *witnessExtractBin,

		RunTimeout:      *runTimeout,
		DepositTimeout:  *depositTimeout,
		WithdrawTimeout: *withdrawTimeout,
		PollInterval:    *pollInterval,

		IPFSAPIUrl: *ipfsAPIURL,

		ExpectedFeeBps: *expectedFeeBps,
		ExpectedTipBps: *expectedTipBps,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Apply the overall run timeout.
	ctx, cancel := context.WithTimeout(ctx, cfg.RunTimeout)
	defer cancel()

	report, err := e2eorch.Run(ctx, cfg)
	if err != nil && report == nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	// Marshal report to JSON.
	reportJSON, jsonErr := report.JSON()
	if jsonErr != nil {
		fmt.Fprintf(os.Stderr, "error: marshal report: %v\n", jsonErr)
		os.Exit(1)
	}

	// Write report.
	if *output == "-" || *output == "" {
		_, _ = os.Stdout.Write(reportJSON)
	} else {
		if writeErr := os.WriteFile(*output, reportJSON, 0644); writeErr != nil {
			fmt.Fprintf(os.Stderr, "error: write report to %s: %v\n", *output, writeErr)
			os.Exit(1)
		}
	}

	// Exit code based on success.
	if !report.Success {
		os.Exit(1)
	}
}
