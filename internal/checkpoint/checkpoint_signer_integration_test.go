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
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/junorpc"
)

func TestCheckpointSigner_Integration_RegtestJunocashd(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))

	composeDir := filepath.Join(wd, "testdata", "junocashd-regtest")
	project := fmt.Sprintf("intentsjuno_%d", time.Now().UnixNano())
	composeEnv := append(os.Environ(), "COMPOSE_PROJECT_NAME="+project)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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
	// Example: "0.0.0.0:49153" or "[::]:49153"
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

	// Wait for junocashd RPC to become ready.
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

	// Build checkpoint-signer binary.
	binPath := filepath.Join(t.TempDir(), "checkpoint-signer")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/checkpoint-signer")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}

	// Run it against regtest RPC and assert it emits a valid signed checkpoint.
	binCtx, binCancel := context.WithTimeout(ctx, 30*time.Second)
	defer binCancel()

	cmd := exec.CommandContext(binCtx, binPath,
		"--juno-rpc-url", rpcURL,
		"--base-chain-id", "8453",
		"--bridge-address", "0x000000000000000000000000000000000000bEEF",
		"--confirmations", "0",
		"--poll-interval", "200ms",
		"--rpc-timeout", "5s",
	)
	cmd.Env = append(os.Environ(),
		"JUNO_RPC_USER=rpcuser",
		"JUNO_RPC_PASS=rpcpass",
		"CHECKPOINT_SIGNER_PRIVATE_KEY=4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start checkpoint-signer: %v\n%s", err, stderr.String())
	}

	type outMsg struct {
		Version    string                `json:"version"`
		Operator   common.Address        `json:"operator"`
		Digest     common.Hash           `json:"digest"`
		Signature  string                `json:"signature"`
		Checkpoint checkpoint.Checkpoint `json:"checkpoint"`
		SignedAt   time.Time             `json:"signedAt"`
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024), 1<<20)

	var line string
	if sc.Scan() {
		line = sc.Text()
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan stdout: %v\nstderr:\n%s", err, stderr.String())
	}
	if line == "" {
		t.Fatalf("no output received\nstderr:\n%s", stderr.String())
	}

	var m outMsg
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("unmarshal output: %v\nline=%q\nstderr:\n%s", err, line, stderr.String())
	}
	if m.Version != "checkpoints.signature.v1" {
		t.Fatalf("version mismatch: got %q want %q", m.Version, "checkpoints.signature.v1")
	}
	if m.Checkpoint.BaseChainID != 8453 {
		t.Fatalf("baseChainId mismatch: got %d want %d", m.Checkpoint.BaseChainID, 8453)
	}
	if m.Checkpoint.BridgeContract != common.HexToAddress("0x000000000000000000000000000000000000bEEF") {
		t.Fatalf("bridgeContract mismatch: got %s", m.Checkpoint.BridgeContract)
	}

	wantDigest := checkpoint.Digest(m.Checkpoint)
	if m.Digest != wantDigest {
		t.Fatalf("digest mismatch: got %s want %s", m.Digest, wantDigest)
	}

	sigHex := strings.TrimPrefix(m.Signature, "0x")
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length: got %d want 65", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("signature v: got %d want 27/28", sig[64])
	}

	gotOperator, err := checkpoint.RecoverSigner(m.Digest, sig)
	if err != nil {
		t.Fatalf("RecoverSigner: %v", err)
	}
	if gotOperator != m.Operator {
		t.Fatalf("operator mismatch: got %s want %s", gotOperator, m.Operator)
	}

	// Shut down process (CommandContext will SIGKILL on cancel).
	binCancel()
	_ = cmd.Wait()
}
