//go:build integration

package checkpoint_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/junorpc"
)

func TestCheckpointAggregator_Integration_RegtestJunocashd(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))

	composeDir := filepath.Join(wd, "testdata", "junocashd-regtest")
	project := fmt.Sprintf("intentsjuno_%d", time.Now().UnixNano())
	composeEnv := append(os.Environ(), "COMPOSE_PROJECT_NAME="+project)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	runCompose := func(args ...string) string {
		cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, args...)...)
		cmd.Dir = composeDir
		cmd.Env = composeEnv
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		return string(out)
	}

	runCompose("up", "-d", "--build")
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer ccancel()
		cmd := exec.CommandContext(cctx, "docker", "compose", "down", "-v", "--remove-orphans")
		cmd.Dir = composeDir
		cmd.Env = composeEnv
		_ = cmd.Run()
	})

	portOut := strings.TrimSpace(runCompose("port", "junocashd", "18232"))
	idx := strings.LastIndex(portOut, ":")
	if idx == -1 || idx == len(portOut)-1 {
		t.Fatalf("unexpected port output: %q", portOut)
	}
	hostPort, err := strconv.Atoi(portOut[idx+1:])
	if err != nil {
		t.Fatalf("parse port from %q: %v", portOut, err)
	}

	rpcURL := fmt.Sprintf("http://127.0.0.1:%d", hostPort)
	rpc, err := junorpc.New(rpcURL, "rpcuser", "rpcpass",
		junorpc.WithTimeout(3*time.Second),
		junorpc.WithMaxResponseBytes(5<<20),
	)
	if err != nil {
		t.Fatalf("junorpc.New: %v", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("junocashd RPC not ready after 60s (rpcURL=%s)", rpcURL)
		}
		_, err := rpc.GetBlockChainInfo(ctx)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	tmpDir := t.TempDir()

	signerBin := filepath.Join(tmpDir, "checkpoint-signer")
	buildSigner := exec.CommandContext(ctx, "go", "build", "-o", signerBin, "./cmd/checkpoint-signer")
	buildSigner.Dir = repoRoot
	if out, err := buildSigner.CombinedOutput(); err != nil {
		t.Fatalf("go build checkpoint-signer: %v\n%s", err, string(out))
	}

	aggBin := filepath.Join(tmpDir, "checkpoint-aggregator")
	buildAgg := exec.CommandContext(ctx, "go", "build", "-o", aggBin, "./cmd/checkpoint-aggregator")
	buildAgg.Dir = repoRoot
	if out, err := buildAgg.CombinedOutput(); err != nil {
		t.Fatalf("go build checkpoint-aggregator: %v\n%s", err, string(out))
	}

	keys := []string{
		"4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a",
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
	}

	operators := make([]common.Address, 0, len(keys))
	for _, k := range keys {
		key, err := crypto.HexToECDSA(k)
		if err != nil {
			t.Fatalf("HexToECDSA: %v", err)
		}
		operators = append(operators, crypto.PubkeyToAddress(key.PublicKey))
	}

	type sigMsg struct {
		Version    string                `json:"version"`
		Operator   common.Address        `json:"operator"`
		Digest     common.Hash           `json:"digest"`
		Signature  string                `json:"signature"`
		Checkpoint checkpoint.Checkpoint `json:"checkpoint"`
		SignedAt   time.Time             `json:"signedAt"`
	}

	var lines []string
	for _, k := range keys {
		binCtx, binCancel := context.WithTimeout(ctx, 30*time.Second)

		cmd := exec.CommandContext(binCtx, signerBin,
			"--juno-rpc-url", rpcURL,
			"--base-chain-id", "8453",
			"--bridge-address", "0x000000000000000000000000000000000000bEEF",
			"--confirmations", "0",
			"--poll-interval", "100ms",
			"--rpc-timeout", "5s",
			"--queue-driver", "stdio",
		)
		cmd.Env = append(os.Environ(),
			"JUNO_RPC_USER=rpcuser",
			"JUNO_RPC_PASS=rpcpass",
			"CHECKPOINT_SIGNER_PRIVATE_KEY="+k,
		)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			binCancel()
			t.Fatalf("StdoutPipe: %v", err)
		}
		if err := cmd.Start(); err != nil {
			binCancel()
			t.Fatalf("start checkpoint-signer: %v\n%s", err, stderr.String())
		}

		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1024), 1<<20)
		var line string
		if sc.Scan() {
			line = sc.Text()
		}
		if err := sc.Err(); err != nil {
			binCancel()
			_ = cmd.Wait()
			t.Fatalf("scan signer stdout: %v\nstderr:\n%s", err, stderr.String())
		}
		if line == "" {
			binCancel()
			_ = cmd.Wait()
			t.Fatalf("no signer output received\nstderr:\n%s", stderr.String())
		}

		var m sigMsg
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			binCancel()
			_ = cmd.Wait()
			t.Fatalf("unmarshal signer output: %v\nline=%q\nstderr:\n%s", err, line, stderr.String())
		}
		if m.Version != "checkpoints.signature.v1" {
			binCancel()
			_ = cmd.Wait()
			t.Fatalf("unexpected signer version: %q", m.Version)
		}

		binCancel()
		_ = cmd.Wait()

		lines = append(lines, line)
	}

	opsCSV := operators[0].Hex() + "," + operators[1].Hex() + "," + operators[2].Hex()

	aggCtx, aggCancel := context.WithTimeout(ctx, 30*time.Second)
	defer aggCancel()

	cmd := exec.CommandContext(aggCtx, aggBin,
		"--base-chain-id", "8453",
		"--bridge-address", "0x000000000000000000000000000000000000bEEF",
		"--operators", opsCSV,
		"--threshold", "3",
		"--max-line-bytes", "1048576",
		"--queue-driver", "stdio",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start checkpoint-aggregator: %v\n%s", err, stderr.String())
	}

	for _, line := range lines {
		if _, err := fmt.Fprintln(stdin, line); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			t.Fatalf("write to aggregator stdin: %v\nstderr:\n%s", err, stderr.String())
		}
	}
	_ = stdin.Close()

	type outPkg struct {
		Version         string                `json:"version"`
		Digest          common.Hash           `json:"digest"`
		Checkpoint      checkpoint.Checkpoint `json:"checkpoint"`
		OperatorSetHash common.Hash           `json:"operatorSetHash"`
		Signers         []common.Address      `json:"signers"`
		Signatures      []string              `json:"signatures"`
		CreatedAt       time.Time             `json:"createdAt"`
	}

	aggScan := bufio.NewScanner(stdout)
	aggScan.Buffer(make([]byte, 1024), 1<<20)
	var outLine string
	if aggScan.Scan() {
		outLine = aggScan.Text()
	}
	if err := aggScan.Err(); err != nil {
		aggCancel()
		_ = cmd.Wait()
		t.Fatalf("scan aggregator stdout: %v\nstderr:\n%s", err, stderr.String())
	}
	if outLine == "" {
		aggCancel()
		_ = cmd.Wait()
		t.Fatalf("no aggregator output received\nstderr:\n%s", stderr.String())
	}

	var pkg outPkg
	if err := json.Unmarshal([]byte(outLine), &pkg); err != nil {
		aggCancel()
		_ = cmd.Wait()
		t.Fatalf("unmarshal aggregator output: %v\nline=%q\nstderr:\n%s", err, outLine, stderr.String())
	}
	if pkg.Version != "checkpoints.package.v1" {
		t.Fatalf("version mismatch: got %q want %q", pkg.Version, "checkpoints.package.v1")
	}
	if (pkg.OperatorSetHash == common.Hash{}) {
		t.Fatalf("expected non-zero operatorSetHash")
	}
	wantDigest := checkpoint.Digest(pkg.Checkpoint)
	if pkg.Digest != wantDigest {
		t.Fatalf("digest mismatch: got %s want %s", pkg.Digest, wantDigest)
	}
	if len(pkg.Signers) != 3 || len(pkg.Signatures) != 3 {
		t.Fatalf("unexpected package size: signers=%d signatures=%d", len(pkg.Signers), len(pkg.Signatures))
	}

	// Ensure signer order is strictly ascending and matches recovered signatures.
	for i := 0; i < len(pkg.Signers); i++ {
		if i > 0 && bytes.Compare(pkg.Signers[i-1].Bytes(), pkg.Signers[i].Bytes()) >= 0 {
			t.Fatalf("signers not sorted/unique: %s then %s", pkg.Signers[i-1], pkg.Signers[i])
		}
		sigHex := strings.TrimPrefix(pkg.Signatures[i], "0x")
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			t.Fatalf("decode signature[%d]: %v", i, err)
		}
		gotSigner, err := checkpoint.RecoverSigner(pkg.Digest, sig)
		if err != nil {
			t.Fatalf("RecoverSigner[%d]: %v", i, err)
		}
		if gotSigner != pkg.Signers[i] {
			t.Fatalf("signature[%d] recovers to %s want %s", i, gotSigner, pkg.Signers[i])
		}
	}

	aggCancel()
	_ = cmd.Wait()
}
