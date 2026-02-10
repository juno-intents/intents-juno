//go:build integration

package depositrelayer

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
)

type recordingSender struct {
	inner      *httpapi.Client
	lastReq    httpapi.SendRequest
	lastTxHash string
}

func (s *recordingSender) Send(ctx context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error) {
	s.lastReq = req
	res, err := s.inner.Send(ctx, req)
	if err == nil {
		s.lastTxHash = res.TxHash
	}
	return res, err
}

type staticSealProver struct {
	seal []byte
}

func (p *staticSealProver) Prove(_ context.Context, _ common.Hash, _ []byte) ([]byte, error) {
	return p.seal, nil
}

func TestRelayer_Integration_SubmitsMintBatchTx(t *testing.T) {
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
	evm := dialRPC(t, ctx, rpcURL)
	t.Cleanup(func() { evm.Close() })

	key, err := crypto.HexToECDSA(strings.TrimPrefix("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "0x"))
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}

	relayer, err := eth.NewRelayer(evm, []eth.Signer{eth.NewLocalSigner(key)}, eth.RelayerConfig{
		ChainID:             big.NewInt(31337),
		GasLimitMultiplier:  1.2,
		MinTipCap:           big.NewInt(1),
		ReceiptPollInterval: 200 * time.Millisecond,
		MaxReplacements:     0,
	})
	if err != nil {
		t.Fatalf("eth.NewRelayer: %v", err)
	}

	handler := httpapi.NewHandler(relayer, httpapi.Config{
		AuthToken:      "secret",
		MaxBodyBytes:   1 << 20,
		MaxWaitSeconds: 60,
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := httpapi.NewClient(srv.URL, "secret", httpapi.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("httpapi.NewClient: %v", err)
	}

	sender := &recordingSender{inner: client}

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])

	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa

	r, err := New(Config{
		BaseChainID:    baseChainID,
		BridgeAddress:  bridge,
		DepositImageID: common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		MaxItems:       1,
		MaxAge:         10 * time.Minute,
		DedupeMax:      1000,
		GasLimit:       200_000, // skip estimation for deterministic tests
		Now:            time.Now,
	}, sender, &staticSealProver{seal: []byte{0x99}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: [][]byte{[]byte{0x01}}}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment: cm,
		LeafIndex:  7,
		Amount:     1000,
		Memo:       memoBytes[:],
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	if sender.lastTxHash == "" {
		t.Fatalf("expected tx hash")
	}

	txHash := common.HexToHash(sender.lastTxHash)
	tx, pending, err := evm.TransactionByHash(ctx, txHash)
	if err != nil {
		t.Fatalf("TransactionByHash: %v", err)
	}
	if pending {
		t.Fatalf("tx is still pending")
	}
	if tx.To() == nil || *tx.To() != bridge {
		t.Fatalf("tx to mismatch: got %v want %s", tx.To(), bridge.Hex())
	}

	depositIDBytes := idempotency.DepositIDV1([32]byte(cm), 7)
	journal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []bridgeabi.MintItem{
			{
				DepositId: common.Hash(depositIDBytes),
				Recipient: recipient,
				Amount:    new(big.Int).SetUint64(1000),
			},
		},
	})
	if err != nil {
		t.Fatalf("EncodeDepositJournal: %v", err)
	}
	want, err := bridgeabi.PackMintBatchCalldata(cp, [][]byte{[]byte{0x01}}, []byte{0x99}, journal)
	if err != nil {
		t.Fatalf("PackMintBatchCalldata: %v", err)
	}
	if !bytes.Equal(tx.Data(), want) {
		t.Fatalf("calldata mismatch")
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
