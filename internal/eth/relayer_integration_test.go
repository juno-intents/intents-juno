//go:build integration

package eth

import (
	"context"
	"math/big"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TestRelayer_AnvilSendAndWaitMined(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Pin the image for deterministic integration tests.
	const anvilImage = "ghcr.io/foundry-rs/foundry@sha256:043752653d5be351c71709091b3db97c4421c907eb40ea294195e7f532aadf46"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	containerID := dockerRunAnvil(t, ctx, anvilImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	rpcURL := "http://127.0.0.1:" + port
	client := dialRPC(t, ctx, rpcURL)
	defer client.Close()

	// Anvil default funded dev key.
	key, err := crypto.HexToECDSA(strings.TrimPrefix("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "0x"))
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}

	relayer, err := NewRelayer(client, []Signer{NewLocalSigner(key)}, RelayerConfig{
		ChainID:             big.NewInt(31337),
		GasLimitMultiplier:  1.2,
		MinTipCap:           big.NewInt(1),
		ReceiptPollInterval: 200 * time.Millisecond,
		MaxReplacements:     0,
	})
	if err != nil {
		t.Fatalf("NewRelayer: %v", err)
	}

	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	res, err := relayer.SendAndWaitMined(ctx, TxRequest{
		To:    to,
		Value: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("SendAndWaitMined: %v", err)
	}
	if res.Receipt == nil || res.Receipt.Status != 1 {
		t.Fatalf("receipt: %+v", res.Receipt)
	}
	if (res.TxHash == common.Hash{}) {
		t.Fatalf("expected non-zero tx hash")
	}
}

func mustFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
}

func dockerRunAnvil(t *testing.T, ctx context.Context, image string, hostPort string) string {
	t.Helper()

	cmd := exec.CommandContext(ctx, "docker",
		"run",
		"--rm",
		"-d",
		"-e", "ANVIL_IP_ADDR=0.0.0.0",
		"-p", "127.0.0.1:"+hostPort+":8545",
		image,
		"anvil",
		"--port", "8545",
		"--chain-id", "31337",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run anvil: %v: %s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func dialRPC(t *testing.T, ctx context.Context, url string) *ethclient.Client {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		c, err := ethclient.DialContext(cctx, url)
		if err == nil {
			// DialContext does not guarantee the RPC is responsive; perform a real call.
			_, err = c.ChainID(cctx)
			if err == nil {
				cancel()
				return c
			}
			c.Close()
		}
		cancel()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("rpc not ready: %s", url)
	return nil
}
