//go:build integration

package withdrawfinalizer

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/withdraw"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
)

func TestFinalizer_Integration_PostgresAndAnvil(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Pin images for deterministic integration tests.
	const (
		foundryImage = "ghcr.io/foundry-rs/foundry@sha256:043752653d5be351c71709091b3db97c4421c907eb40ea294195e7f532aadf46"
		pgImage      = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"
	)

	evmPort := mustFreePort(t)
	pgPort := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)

	// Start Postgres.
	pgContainerID := dockerRunPostgres(t, ctx, pgImage, pgPort)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", pgContainerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + pgPort + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	store, err := withdrawpg.New(pool)
	if err != nil {
		t.Fatalf("withdrawpg.New: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	leaseStore, err := leasespg.New(pool)
	if err != nil {
		t.Fatalf("leasespg.New: %v", err)
	}
	if err := leaseStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema leases: %v", err)
	}

	// Start Anvil.
	evmContainerID := dockerRunAnvil(t, ctx, foundryImage, evmPort)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", evmContainerID).Run() })

	rpcURL := "http://127.0.0.1:" + evmPort
	evm := dialRPC(t, ctx, rpcURL)
	t.Cleanup(func() { evm.Close() })

	chainID := big.NewInt(31337)

	// Anvil default funded dev key.
	key, err := crypto.HexToECDSA(strings.TrimPrefix("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "0x"))
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	signerAddr := crypto.PubkeyToAddress(key.PublicKey)

	// base-relayer HTTP server (in-process).
	relayer, err := eth.NewRelayer(evm, []eth.Signer{eth.NewLocalSigner(key)}, eth.RelayerConfig{
		ChainID:             chainID,
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

	// Deploy contracts (reuse helpers from bridge_withdraw_integration_test.go).
	repoRoot := mustRepoRoot(t)
	contractsDir := repoRoot + "/contracts"
	outDir := t.TempDir()
	cacheDir := t.TempDir()
	forgeBuild(t, ctx, foundryImage, contractsDir, outDir, cacheDir)

	wjunoABI, wjunoBin := loadFoundryArtifact(t, outDir+"/WJuno.sol/WJuno.json")
	regABI, regBin := loadFoundryArtifact(t, outDir+"/OperatorRegistry.sol/OperatorRegistry.json")
	fdABI, fdBin := loadFoundryArtifact(t, outDir+"/FeeDistributor.sol/FeeDistributor.json")
	bridgeABI, bridgeBin := loadFoundryArtifact(t, outDir+"/Bridge.sol/Bridge.json")

	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		t.Fatalf("NewKeyedTransactorWithChainID: %v", err)
	}
	auth.Context = ctx

	owner := auth.From

	verifierAddr := deployNoopVerifier(t, ctx, evm, auth)
	wjunoAddr := deployContract(t, ctx, evm, auth, wjunoABI, wjunoBin, owner)
	regAddr := deployContract(t, ctx, evm, auth, regABI, regBin, owner)
	fdAddr := deployContract(t, ctx, evm, auth, fdABI, fdBin, owner, wjunoAddr, regAddr)

	reg := bind.NewBoundContract(regAddr, regABI, evm, evm, evm)
	fd := bind.NewBoundContract(fdAddr, fdABI, evm, evm, evm)
	wjuno := bind.NewBoundContract(wjunoAddr, wjunoABI, evm, evm, evm)

	mustTransact(t, ctx, evm, auth, reg, "setFeeDistributor", fdAddr)

	opKeys := []*ecdsa.PrivateKey{
		mustKeyFromUint256(t, 0xC0),
		mustKeyFromUint256(t, 0xC1),
		mustKeyFromUint256(t, 0xC2),
		mustKeyFromUint256(t, 0xC3),
		mustKeyFromUint256(t, 0xC4),
	}
	for _, k := range opKeys {
		op := crypto.PubkeyToAddress(k.PublicKey)
		mustTransact(t, ctx, evm, auth, reg, "setOperator", op, op, big.NewInt(1), true)
	}
	mustTransact(t, ctx, evm, auth, reg, "setThreshold", big.NewInt(3))

	depositImageID := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01")
	withdrawImageID := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02")
	const feeBps = uint64(50)
	const tipBps = uint64(1000)
	const refundWindowSeconds = uint64(60)
	const maxExtendSeconds = uint64(12 * 60 * 60)

	bridgeAddr := deployContract(
		t, ctx, evm, auth, bridgeABI, bridgeBin,
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

	bridge := bind.NewBoundContract(bridgeAddr, bridgeABI, evm, evm, evm)
	mustTransact(t, ctx, evm, auth, wjuno, "setBridge", bridgeAddr)
	mustTransact(t, ctx, evm, auth, fd, "setBridge", bridgeAddr)

	// Mint wJUNO to requester via mintBatch (no-op verifier so seal is ignored).
	cp := checkpoint.Checkpoint{
		Height:           1,
		BlockHash:        common.Hash{},
		FinalOrchardRoot: common.Hash{},
		BaseChainID:      uint64(chainID.Uint64()),
		BridgeContract:   bridgeAddr,
	}
	cpDigest := checkpoint.Digest(cp)
	cpSigs := signDigestSorted(t, cpDigest, opKeys[:3])

	var depositID common.Hash
	depositID[0] = 0x01
	mintAmount := new(big.Int).SetUint64(100_000)
	journal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []bridgeabi.MintItem{
			{DepositId: depositID, Recipient: signerAddr, Amount: mintAmount},
		},
	})
	if err != nil {
		t.Fatalf("EncodeDepositJournal: %v", err)
	}
	cpABI := checkpointABIFrom(cp)
	mustTransact(t, ctx, evm, auth, bridge, "mintBatch", cpABI, cpSigs, []byte{0x99}, journal)

	// requestWithdraw on-chain
	withdrawAmount := new(big.Int).SetUint64(10_000)
	recipientUA := []byte{0x01, 0x02, 0x03}
	mustTransact(t, ctx, evm, auth, wjuno, "approve", bridgeAddr, withdrawAmount)
	tx, err := bridge.Transact(auth, "requestWithdraw", withdrawAmount, recipientUA)
	if err != nil {
		t.Fatalf("requestWithdraw tx: %v", err)
	}
	rcpt := mustWaitMined(t, ctx, evm, tx)
	if rcpt.Status != 1 {
		t.Fatalf("requestWithdraw reverted")
	}
	withdrawalID, expiry, feeBpsAtReq := mustParseWithdrawRequested(t, bridgeABI, rcpt)

	// Persist withdrawal into Postgres store.
	var req20 [20]byte
	copy(req20[:], signerAddr[:])

	w := withdraw.Withdrawal{
		ID:          ([32]byte)(withdrawalID),
		Requester:   req20,
		Amount:      withdrawAmount.Uint64(),
		FeeBps:      uint32(feeBpsAtReq),
		RecipientUA: append([]byte(nil), recipientUA...),
		Expiry:      time.Unix(int64(expiry), 0).UTC(),
	}
	if _, _, err := store.UpsertRequested(ctx, w); err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	}

	// Create a confirmed batch in DB.
	claimed, err := store.ClaimUnbatched(ctx, "coord", 10*time.Second, 1)
	if err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("expected 1 claimed withdrawal, got %d", len(claimed))
	}

	batchID := seq32(0x42)
	if err := store.CreatePlannedBatch(ctx, "coord", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	if err := store.MarkBatchSigning(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchSigning: %v", err)
	}
	if err := store.SetBatchSigned(ctx, batchID, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned: %v", err)
	}
	if err := store.SetBatchBroadcasted(ctx, batchID, "juno-txid"); err != nil {
		t.Fatalf("SetBatchBroadcasted: %v", err)
	}
	if err := store.SetBatchConfirmed(ctx, batchID); err != nil {
		t.Fatalf("SetBatchConfirmed: %v", err)
	}

	// Run the finalizer.
	operatorAddrs := make([]common.Address, 0, len(opKeys))
	for _, k := range opKeys {
		operatorAddrs = append(operatorAddrs, crypto.PubkeyToAddress(k.PublicKey))
	}
	f, err := New(Config{
		Owner:             "finalizer1",
		LeaseTTL:          10 * time.Second,
		MaxBatches:        10,
		BaseChainID:       uint64(chainID.Uint64()),
		BridgeAddress:     bridgeAddr,
		WithdrawImageID:   withdrawImageID,
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 3,
		GasLimit:          500_000,
	}, store, leaseStore, client, &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}, nil)
	if err != nil {
		t.Fatalf("New finalizer: %v", err)
	}
	if err := f.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: cpSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}
	if err := f.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// Batch should be finalized in DB.
	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateFinalized {
		t.Fatalf("expected finalized, got %s", b.State)
	}
	if b.BaseTxHash == "" {
		t.Fatalf("expected base tx hash to be set")
	}

	// On-chain withdrawal should be finalized and escrow cleared.
	var res []interface{}
	if err := bridge.Call(&bind.CallOpts{Context: ctx}, &res, "getWithdrawal", withdrawalID); err != nil {
		t.Fatalf("getWithdrawal call: %v", err)
	}
	if len(res) != 7 {
		t.Fatalf("getWithdrawal result count: got %d want 7", len(res))
	}
	finalized, ok := res[4].(bool)
	if !ok {
		t.Fatalf("getWithdrawal finalized type: got %T want bool", res[4])
	}
	if !finalized {
		t.Fatalf("expected withdrawal to be finalized on-chain")
	}

	if bal := callBalanceOf(t, ctx, wjuno, bridgeAddr); bal.Sign() != 0 {
		t.Fatalf("bridge escrow balance: got %s want 0", bal.String())
	}
}

func dockerRunPostgres(t *testing.T, ctx context.Context, image string, hostPort string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker",
		"run",
		"--rm",
		"-d",
		"-e", "POSTGRES_USER=postgres",
		"-e", "POSTGRES_PASSWORD=postgres",
		"-e", "POSTGRES_DB=postgres",
		"-p", "127.0.0.1:"+hostPort+":5432",
		image,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run postgres: %v: %s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func dialPostgres(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		pool, err := pgxpool.New(cctx, dsn)
		if err == nil {
			if err := pool.Ping(cctx); err == nil {
				cancel()
				return pool
			}
			pool.Close()
		}
		cancel()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("postgres not ready: %s", dsn)
	return nil
}
