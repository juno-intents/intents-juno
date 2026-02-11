package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/juno-intents/intents-juno/internal/tss"
	"github.com/juno-intents/intents-juno/internal/tsssigner"
)

func main() {
	var (
		txsignBin          = flag.String("juno-txsign-bin", "juno-txsign", "path to juno-txsign binary")
		ufvk               = flag.String("ufvk", "", "UFVK (jview...) for ext-prepare")
		ufvkFile           = flag.String("ufvk-file", "", "path to file containing UFVK")
		spendAuthSignerBin = flag.String("spendauth-signer-bin", "", "path to spend-auth signer binary (required; invoked as `sign-spendauth --session-id <id> --requests <path> --out <path>`)")
		workDir            = flag.String("work-dir", "", "working directory for temporary files")
		maxStdinBytes      = flag.Int64("max-stdin-bytes", 4<<20, "maximum stdin request size (bytes)")
		timeout            = flag.Duration("timeout", 2*time.Minute, "overall signing timeout")
	)
	flag.Parse()

	if *maxStdinBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-stdin-bytes must be > 0")
		os.Exit(2)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --timeout must be > 0")
		os.Exit(2)
	}
	if strings.TrimSpace(*spendAuthSignerBin) == "" {
		fmt.Fprintln(os.Stderr, "error: --spendauth-signer-bin is required")
		os.Exit(2)
	}

	ufvkValue, err := resolveUFVK(*ufvk, *ufvkFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	reqBytes, err := readLimited(os.Stdin, *maxStdinBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read stdin: %v\n", err)
		os.Exit(1)
	}

	var req tss.SignRequest
	dec := json.NewDecoder(bytes.NewReader(reqBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "error: decode request: %v\n", err)
		os.Exit(1)
	}
	if req.Version != tss.SignRequestVersion {
		fmt.Fprintf(os.Stderr, "error: invalid request version %q\n", req.Version)
		os.Exit(1)
	}
	sessionID, err := tss.ParseSessionID(req.SessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid session id\n")
		os.Exit(1)
	}
	if len(req.TxPlan) == 0 {
		fmt.Fprintf(os.Stderr, "error: empty txplan\n")
		os.Exit(1)
	}

	adapter, err := tsssigner.NewAdapter(tsssigner.Config{
		TxSignBin:          *txsignBin,
		UFVK:               ufvkValue,
		SpendAuthSignerBin: *spendAuthSignerBin,
		WorkDir:            *workDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: init signer: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rawTx, err := adapter.Sign(ctx, sessionID, req.TxPlan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: sign txplan: %v\n", err)
		os.Exit(1)
	}

	resp := tss.SignResponse{
		Version:   tss.SignResponseVersion,
		SessionID: tss.FormatSessionID(sessionID),
		SignedTx:  rawTx,
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: encode response: %v\n", err)
		os.Exit(1)
	}
}

func resolveUFVK(ufvk string, ufvkFile string) (string, error) {
	sources := 0
	if strings.TrimSpace(ufvk) != "" {
		sources++
	}
	if strings.TrimSpace(ufvkFile) != "" {
		sources++
	}
	if sources == 0 {
		return "", errors.New("one of --ufvk or --ufvk-file is required")
	}
	if sources > 1 {
		return "", errors.New("use only one of --ufvk or --ufvk-file")
	}
	if strings.TrimSpace(ufvk) != "" {
		return strings.TrimSpace(ufvk), nil
	}
	b, err := os.ReadFile(strings.TrimSpace(ufvkFile))
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(string(b))
	if out == "" {
		return "", errors.New("ufvk file is empty")
	}
	return out, nil
}

func readLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	lr := io.LimitReader(r, maxBytes+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("request exceeds %d bytes", maxBytes)
	}
	return b, nil
}
