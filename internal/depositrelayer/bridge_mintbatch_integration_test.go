//go:build integration

package depositrelayer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
)

func TestBridgeMintBatchHarness_MintsNetAndFees(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Pinned, deterministic image used for both anvil and forge builds.
	const foundryImage = "ghcr.io/foundry-rs/foundry@sha256:043752653d5be351c71709091b3db97c4421c907eb40ea294195e7f532aadf46"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunAnvil(t, ctx, foundryImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	rpcURL := "http://127.0.0.1:" + port
	evm := dialRPC(t, ctx, rpcURL)
	t.Cleanup(func() { evm.Close() })

	chainID := big.NewInt(31337)

	// Anvil default funded dev key.
	key, err := crypto.HexToECDSA(strings.TrimPrefix("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "0x"))
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	baseSenderAddr := crypto.PubkeyToAddress(key.PublicKey)

	// Base-relayer HTTP server (in-process).
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

	sender := &recordingSender{inner: client}

	// Build contract artifacts via dockerized forge.
	repoRoot := mustRepoRoot(t)
	contractsDir := filepath.Join(repoRoot, "contracts")
	outDir := t.TempDir()
	cacheDir := t.TempDir()
	forgeBuild(t, ctx, foundryImage, contractsDir, outDir, cacheDir)

	wjunoABI, wjunoBin := loadFoundryArtifact(t, filepath.Join(outDir, "WJuno.sol", "WJuno.json"))
	regABI, regBin := loadFoundryArtifact(t, filepath.Join(outDir, "OperatorRegistry.sol", "OperatorRegistry.json"))
	fdABI, fdBin := loadFoundryArtifact(t, filepath.Join(outDir, "FeeDistributor.sol", "FeeDistributor.json"))
	bridgeABI, bridgeBin := loadFoundryArtifact(t, filepath.Join(outDir, "Bridge.sol", "Bridge.json"))

	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		t.Fatalf("NewKeyedTransactorWithChainID: %v", err)
	}
	auth.Context = ctx

	owner := auth.From

	// Deploy verifier: 1-byte STOP runtime code => calls succeed and do nothing.
	verifierAddr := deployNoopVerifier(t, ctx, evm, auth)

	// Deploy WJuno, OperatorRegistry, FeeDistributor, Bridge.
	wjunoAddr := deployContract(t, ctx, evm, auth, wjunoABI, wjunoBin, owner)
	regAddr := deployContract(t, ctx, evm, auth, regABI, regBin, owner)
	fdAddr := deployContract(t, ctx, evm, auth, fdABI, fdBin, owner, wjunoAddr, regAddr)

	reg := bind.NewBoundContract(regAddr, regABI, evm, evm, evm)
	fd := bind.NewBoundContract(fdAddr, fdABI, evm, evm, evm)

	mustTransact(t, ctx, evm, auth, reg, "setFeeDistributor", fdAddr)

	// Operator set + threshold (must be set before minting so FeeDistributor has non-zero weight).
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
	const refundWindowSeconds = uint64(24 * 60 * 60)
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
	wjuno := bind.NewBoundContract(wjunoAddr, wjunoABI, evm, evm, evm)

	// Sanity-check deployed wiring.
	if got := callAddress0(t, ctx, bridge, "wjuno"); got != wjunoAddr {
		t.Fatalf("bridge.wjuno: got %s want %s", got.Hex(), wjunoAddr.Hex())
	}
	if got := callAddress0(t, ctx, bridge, "feeDistributor"); got != fdAddr {
		t.Fatalf("bridge.feeDistributor: got %s want %s", got.Hex(), fdAddr.Hex())
	}
	if got := callAddress0(t, ctx, bridge, "operatorRegistry"); got != regAddr {
		t.Fatalf("bridge.operatorRegistry: got %s want %s", got.Hex(), regAddr.Hex())
	}
	if got := callAddress0(t, ctx, bridge, "verifier"); got != verifierAddr {
		t.Fatalf("bridge.verifier: got %s want %s", got.Hex(), verifierAddr.Hex())
	}

	mustTransact(t, ctx, evm, auth, wjuno, "setBridge", bridgeAddr)
	mustTransact(t, ctx, evm, auth, fd, "setBridge", bridgeAddr)

	// Build checkpoint + signatures (sorted ascending by signer address).
	cp := checkpoint.Checkpoint{
		Height:           1,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(chainID.Uint64()),
		BridgeContract:   bridgeAddr,
	}
	digest := checkpoint.Digest(cp)
	sigs := signDigestSorted(t, digest, opKeys[:3])

	onchainDigest := callCheckpointDigest(t, ctx, bridge, cp)
	if onchainDigest != digest {
		t.Fatalf("checkpoint digest mismatch: chain=%s offchain=%s", onchainDigest.Hex(), digest.Hex())
	}

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var bridge20 [20]byte
	copy(bridge20[:], bridgeAddr[:])
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   uint32(chainID.Uint64()),
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	// Run relayer to submit mintBatch via base-relayer.
	operatorAddrs := make([]common.Address, 0, len(opKeys))
	for _, k := range opKeys {
		operatorAddrs = append(operatorAddrs, crypto.PubkeyToAddress(k.PublicKey))
	}

	r, err := New(Config{
		BaseChainID:       uint32(chainID.Uint64()),
		BridgeAddress:     bridgeAddr,
		DepositImageID:    depositImageID,
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 3,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		GasLimit:          500_000,
		Now:               time.Now,
	}, sender, &staticSealProofRequester{seal: []byte{0x99}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: sigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	var cm common.Hash
	cm[0] = 0xaa
	const amount = uint64(100_000)

	depositIDBytes := idempotency.DepositIDV1([32]byte(cm), 7)
	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment: cm,
		LeafIndex:  7,
		Amount:     amount,
		Memo:       memoBytes[:],
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	// Verify on-chain results.
	fee := (amount * feeBps) / 10_000
	tip := (fee * tipBps) / 10_000
	feeToDist := fee - tip
	net := amount - fee

	balRecipient := callBalanceOf(t, ctx, wjuno, recipient)
	if balRecipient.Cmp(new(big.Int).SetUint64(net)) != 0 {
		t.Fatalf("recipient balance: got %s want %d", balRecipient.String(), net)
	}

	balFD := callBalanceOf(t, ctx, wjuno, fdAddr)
	if balFD.Cmp(new(big.Int).SetUint64(feeToDist)) != 0 {
		t.Fatalf("fee distributor balance: got %s want %d", balFD.String(), feeToDist)
	}

	balTip := callBalanceOf(t, ctx, wjuno, baseSenderAddr)
	if balTip.Cmp(new(big.Int).SetUint64(tip)) != 0 {
		t.Fatalf("relayer tip balance: got %s want %d", balTip.String(), tip)
	}

	depositID := common.Hash(depositIDBytes)
	used := callDepositUsed(t, ctx, bridge, depositID)
	if !used {
		t.Fatalf("expected depositUsed=true")
	}

	if sender.lastTxHash == "" {
		t.Fatalf("expected tx hash recorded")
	}
}

func callCheckpointDigest(t *testing.T, ctx context.Context, bridge *bind.BoundContract, cp checkpoint.Checkpoint) common.Hash {
	t.Helper()

	// Match Bridge.Checkpoint tuple ABI.
	type checkpointABI struct {
		Height           uint64
		BlockHash        common.Hash
		FinalOrchardRoot common.Hash
		BaseChainId      *big.Int
		BridgeContract   common.Address
	}
	cpABI := checkpointABI{
		Height:           cp.Height,
		BlockHash:        cp.BlockHash,
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
	}

	var res []interface{}
	if err := bridge.Call(&bind.CallOpts{Context: ctx}, &res, "checkpointDigest", cpABI); err != nil {
		t.Fatalf("checkpointDigest call: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("checkpointDigest result count: got %d want 1", len(res))
	}
	d, ok := res[0].([32]byte)
	if !ok {
		t.Fatalf("checkpointDigest result type: got %T want [32]byte", res[0])
	}
	return common.Hash(d)
}

func callDepositUsed(t *testing.T, ctx context.Context, bridge *bind.BoundContract, depositID common.Hash) bool {
	t.Helper()

	var res []interface{}
	if err := bridge.Call(&bind.CallOpts{Context: ctx}, &res, "depositUsed", depositID); err != nil {
		t.Fatalf("depositUsed call: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("depositUsed result count: got %d want 1", len(res))
	}
	used, ok := res[0].(bool)
	if !ok {
		t.Fatalf("depositUsed result type: got %T want bool", res[0])
	}
	return used
}

type foundryArtifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

func loadFoundryArtifact(t *testing.T, path string) (abi.ABI, []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var a foundryArtifact
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	parsed, err := abi.JSON(bytes.NewReader(a.ABI))
	if err != nil {
		t.Fatalf("parse abi: %v", err)
	}
	code, err := hexutil.Decode(a.Bytecode.Object)
	if err != nil {
		t.Fatalf("decode bytecode: %v", err)
	}
	return parsed, code
}

func forgeBuild(t *testing.T, ctx context.Context, image string, contractsDir string, outDir string, cacheDir string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker",
		"run",
		"--rm",
		"--platform", "linux/amd64",
		"-v", contractsDir+":/work",
		"-v", outDir+":/out",
		"-v", cacheDir+":/cache",
		"-w", "/work",
		"--entrypoint", "forge",
		image,
		"build",
		"--out", "/out",
		"--cache-path", "/cache",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("forge build: %v: %s", err, string(out))
	}
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	// Package dir: <repo>/internal/depositrelayer.
	root := filepath.Clean(filepath.Join(wd, "../.."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected repo root with go.mod at %s", root)
	}
	return root
}

type evmBackend interface {
	bind.ContractBackend
	bind.DeployBackend
}

func deployContract(t *testing.T, ctx context.Context, backend evmBackend, auth *bind.TransactOpts, a abi.ABI, bin []byte, args ...any) common.Address {
	t.Helper()
	addr, tx, _, err := bind.DeployContract(auth, a, bin, backend, args...)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	receipt := mustWaitMined(t, ctx, backend, tx)
	if receipt.Status != 1 {
		t.Fatalf("deploy reverted: %s", tx.Hash())
	}
	return addr
}

func deployNoopVerifier(t *testing.T, ctx context.Context, backend evmBackend, auth *bind.TransactOpts) common.Address {
	t.Helper()

	emptyABI, err := abi.JSON(strings.NewReader("[]"))
	if err != nil {
		t.Fatalf("parse empty abi: %v", err)
	}
	// Runtime: STOP (0x00). Code size must be non-zero so it is a real contract call target.
	// Init: return the 1-byte runtime from the end of this init code.
	initCode, err := hexutil.Decode("0x6001600c60003960016000f300")
	if err != nil {
		t.Fatalf("decode init code: %v", err)
	}

	addr, tx, _, err := bind.DeployContract(auth, emptyABI, initCode, backend)
	if err != nil {
		t.Fatalf("deploy empty contract: %v", err)
	}
	receipt := mustWaitMined(t, ctx, backend, tx)
	if receipt.Status != 1 {
		t.Fatalf("verifier deploy reverted: %s", tx.Hash())
	}
	return addr
}

func mustWaitMined(t *testing.T, ctx context.Context, backend bind.DeployBackend, tx *types.Transaction) *types.Receipt {
	t.Helper()
	r, err := bind.WaitMined(ctx, backend, tx)
	if err != nil {
		t.Fatalf("WaitMined: %v", err)
	}
	return r
}

func mustTransact(t *testing.T, ctx context.Context, backend bind.DeployBackend, auth *bind.TransactOpts, c *bind.BoundContract, method string, args ...any) {
	t.Helper()
	tx, err := c.Transact(auth, method, args...)
	if err != nil {
		t.Fatalf("%s tx: %v", method, err)
	}
	receipt := mustWaitMined(t, ctx, backend, tx)
	if receipt.Status != 1 {
		t.Fatalf("%s reverted", method)
	}
}

func mustKeyFromUint256(t *testing.T, v uint64) *ecdsa.PrivateKey {
	t.Helper()
	var b [32]byte
	b[31] = byte(v)
	k, err := crypto.ToECDSA(b[:])
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	return k
}

func signDigestSorted(t *testing.T, digest common.Hash, keys []*ecdsa.PrivateKey) [][]byte {
	t.Helper()
	type pair struct {
		addr common.Address
		sig  []byte
	}
	pairs := make([]pair, 0, len(keys))
	for _, k := range keys {
		sig, err := checkpoint.SignDigest(k, digest)
		if err != nil {
			t.Fatalf("SignDigest: %v", err)
		}
		pairs = append(pairs, pair{addr: crypto.PubkeyToAddress(k.PublicKey), sig: sig})
	}
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].addr.Bytes(), pairs[j].addr.Bytes()) < 0 })
	out := make([][]byte, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.sig)
	}
	return out
}

func callBalanceOf(t *testing.T, ctx context.Context, token *bind.BoundContract, who common.Address) *big.Int {
	t.Helper()
	var res []interface{}
	if err := token.Call(&bind.CallOpts{Context: ctx}, &res, "balanceOf", who); err != nil {
		t.Fatalf("balanceOf call: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("balanceOf result count: got %d want 1", len(res))
	}
	out, ok := res[0].(*big.Int)
	if !ok {
		t.Fatalf("balanceOf result type: got %T want *big.Int", res[0])
	}
	if out == nil {
		return big.NewInt(0)
	}
	return out
}

func callAddress0(t *testing.T, ctx context.Context, c *bind.BoundContract, method string, args ...any) common.Address {
	t.Helper()

	var res []interface{}
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, method, args...); err != nil {
		t.Fatalf("%s call: %v", method, err)
	}
	if len(res) != 1 {
		t.Fatalf("%s result count: got %d want 1", method, len(res))
	}
	out, ok := res[0].(common.Address)
	if !ok {
		t.Fatalf("%s result type: got %T want common.Address", method, res[0])
	}
	return out
}
