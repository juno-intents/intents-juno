package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type signatureMessageV1 struct {
	Version    string                `json:"version"`
	Operator   common.Address        `json:"operator"`
	Digest     common.Hash           `json:"digest"`
	Signature  string                `json:"signature"`
	Checkpoint checkpoint.Checkpoint `json:"checkpoint"`
	SignedAt   time.Time             `json:"signedAt"`
}

type checkpointPackageV1 struct {
	Version         string                `json:"version"`
	Digest          common.Hash           `json:"digest"`
	Checkpoint      checkpoint.Checkpoint `json:"checkpoint"`
	OperatorSetHash common.Hash           `json:"operatorSetHash"`
	Signers         []common.Address      `json:"signers"`
	Signatures      []string              `json:"signatures"`
	CreatedAt       time.Time             `json:"createdAt"`
}

func main() {
	var (
		baseChainID = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")

		operatorsFlag = flag.String("operators", "", "comma-separated operator addresses (required)")
		thresholdFlag = flag.Int("threshold", 0, "signatures required (required)")

		maxLineBytes = flag.Int("max-line-bytes", 1<<20, "maximum input line size (bytes)")
		maxOpen      = flag.Int("max-open", 4, "maximum distinct checkpoint digests tracked concurrently")
		maxEmitted   = flag.Int("max-emitted", 128, "maximum emitted digests remembered for dedupe")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *baseChainID == 0 || *bridgeAddr == "" || *operatorsFlag == "" || *thresholdFlag <= 0 {
		fmt.Fprintln(os.Stderr, "error: --base-chain-id, --bridge-address, --operators, and --threshold are required")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *maxLineBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-line-bytes must be > 0")
		os.Exit(2)
	}
	if *maxOpen < 0 || *maxEmitted < 0 {
		fmt.Fprintln(os.Stderr, "error: --max-open and --max-emitted must be >= 0")
		os.Exit(2)
	}

	bridge := common.HexToAddress(*bridgeAddr)

	ops, err := parseOperatorList(*operatorsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --operators: %v\n", err)
		os.Exit(2)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    *baseChainID,
		BridgeContract: bridge,
		Operators:      ops,
		Threshold:      *thresholdFlag,
		MaxOpen:        *maxOpen,
		MaxEmitted:     *maxEmitted,
		Now:            time.Now,
	})
	if err != nil {
		log.Error("init aggregator", "err", err)
		os.Exit(2)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024), *maxLineBytes)

	log.Info("checkpoint aggregator started",
		"baseChainID", *baseChainID,
		"bridge", bridge,
		"threshold", *thresholdFlag,
		"operators", len(ops),
	)

	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}

		var in signatureMessageV1
		if err := json.Unmarshal(line, &in); err != nil {
			log.Error("parse input json", "err", err)
			continue
		}
		if in.Version != "checkpoints.signature.v1" {
			continue
		}

		sig, err := decodeHexSignature(in.Signature)
		if err != nil {
			log.Error("decode signature", "err", err)
			continue
		}

		pkg, ok, err := agg.AddSignature(checkpoint.SignatureMessageV1{
			Operator:   in.Operator,
			Digest:     in.Digest,
			Signature:  sig,
			Checkpoint: in.Checkpoint,
			SignedAt:   in.SignedAt,
		})
		if err != nil {
			log.Error("add signature", "err", err, "operator", in.Operator, "digest", in.Digest)
			continue
		}
		if !ok || pkg == nil {
			continue
		}

		out := checkpointPackageV1{
			Version:         "checkpoints.package.v1",
			Digest:          pkg.Digest,
			Checkpoint:      pkg.Checkpoint,
			OperatorSetHash: pkg.OperatorSetHash,
			Signers:         pkg.Signers,
			Signatures:      make([]string, 0, len(pkg.Signatures)),
			CreatedAt:       pkg.CreatedAt.UTC(),
		}
		for _, s := range pkg.Signatures {
			out.Signatures = append(out.Signatures, "0x"+hex.EncodeToString(s))
		}

		if err := enc.Encode(out); err != nil {
			log.Error("write output", "err", err)
			continue
		}
	}

	if err := sc.Err(); err != nil {
		log.Error("read stdin", "err", err)
		os.Exit(1)
	}
}

func parseOperatorList(s string) ([]common.Address, error) {
	parts := strings.Split(s, ",")
	out := make([]common.Address, 0, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !common.IsHexAddress(p) {
			return nil, fmt.Errorf("bad address at index %d", i)
		}
		out = append(out, common.HexToAddress(p))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty operator list")
	}
	return out, nil
}

func decodeHexSignature(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, fmt.Errorf("empty signature")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex signature")
	}
	return b, nil
}
