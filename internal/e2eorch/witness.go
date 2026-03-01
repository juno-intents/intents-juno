package e2eorch

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// ExtractDepositWitness shells out to the juno-witness-extract binary to
// extract the deposit witness item for a given txid. Retries up to 30 times
// with a 10s delay because juno-scan may not have indexed the transaction yet.
func ExtractDepositWitness(ctx context.Context, cfg E2EConfig, txid string) ([]byte, error) {
	const maxRetries = 30
	const retryDelay = 10 * time.Second

	bin := cfg.WitnessExtractBin
	if bin == "" {
		bin = "juno-witness-extract"
	}

	args := []string{
		"deposit",
		"--juno-scan-url", cfg.JunoScanURL,
		"--juno-rpc-url", cfg.JunoRPCURL,
		"--juno-rpc-user", cfg.JunoRPCUser,
		"--juno-rpc-pass", cfg.JunoRPCPass,
		"--wallet-id", cfg.JunoWalletID,
		"--txid", txid,
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		log.Printf("[witness] extracting deposit witness attempt %d/%d txid=%s", attempt, maxRetries, txid)

		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err == nil {
			hexStr := strings.TrimSpace(stdout.String())
			if hexStr == "" {
				lastErr = fmt.Errorf("e2eorch: witness-extract returned empty output")
				log.Printf("[witness] empty output, retrying in %s", retryDelay)
				sleepCtx(ctx, retryDelay)
				continue
			}
			witnessBytes, decErr := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
			if decErr != nil {
				return nil, fmt.Errorf("e2eorch: decode witness hex: %w", decErr)
			}
			log.Printf("[witness] extracted %d bytes", len(witnessBytes))
			return witnessBytes, nil
		}

		lastErr = fmt.Errorf("e2eorch: witness-extract attempt %d: %w (stderr: %s)", attempt, err, strings.TrimSpace(stderr.String()))
		log.Printf("[witness] attempt %d failed: %v stderr=%s", attempt, err, strings.TrimSpace(stderr.String()))

		if attempt < maxRetries {
			sleepCtx(ctx, retryDelay)
		}
	}

	return nil, fmt.Errorf("e2eorch: witness extraction failed after %d attempts: %w", maxRetries, lastErr)
}

// sleepCtx sleeps for the given duration or until the context is canceled.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
