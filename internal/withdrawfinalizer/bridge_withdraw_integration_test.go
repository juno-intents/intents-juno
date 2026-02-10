//go:build integration

package withdrawfinalizer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"net"
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
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

func TestBridgeWithdrawHarness_RequestExtendFinalizeAndRefund(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Pinned, deterministic image used for both anvil and forge builds.
	const foundryImage = "ghcr.io/foundry-rs/foundry@sha256:043752653d5be351c71709091b3db97c4421c907eb40ea294195e7f532aadf46"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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

	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		t.Fatalf("NewKeyedTransactorWithChainID: %v", err)
	}
	auth.Context = ctx
	owner := auth.From

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

	// Deploy verifier: 1-byte STOP runtime code => calls succeed and do nothing.
	verifierAddr := deployNoopVerifier(t, ctx, evm, auth)

	// Deploy WJuno, OperatorRegistry, FeeDistributor, Bridge.
	wjunoAddr := deployContract(t, ctx, evm, auth, wjunoABI, wjunoBin, owner)
	regAddr := deployContract(t, ctx, evm, auth, regABI, regBin, owner)
	fdAddr := deployContract(t, ctx, evm, auth, fdABI, fdBin, owner, wjunoAddr, regAddr)

	reg := bind.NewBoundContract(regAddr, regABI, evm, evm, evm)
	fd := bind.NewBoundContract(fdAddr, fdABI, evm, evm, evm)

	mustTransact(t, ctx, evm, auth, reg, "setFeeDistributor", fdAddr)

	// Operator set + threshold (must be set before bridging so FeeDistributor has non-zero weight).
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
	wjuno := bind.NewBoundContract(wjunoAddr, wjunoABI, evm, evm, evm)

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
	cpDigest := checkpoint.Digest(cp)
	cpSigs := signDigestSorted(t, cpDigest, opKeys[:3])

	// Mint wJUNO to the user (auth.From) so we can request a withdraw.
	var depositID common.Hash
	depositID[0] = 0x99
	mintAmount := new(big.Int).SetUint64(100_000)

	journal, err := bridgeabi.EncodeDepositJournal(bridgeabi.DepositJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []bridgeabi.MintItem{
			{DepositId: depositID, Recipient: owner, Amount: mintAmount},
		},
	})
	if err != nil {
		t.Fatalf("EncodeDepositJournal: %v", err)
	}

	cpABI := checkpointABIFrom(cp)
	mustTransact(t, ctx, evm, auth, bridge, "mintBatch", cpABI, cpSigs, []byte{0x99}, journal)

	// requestWithdraw
	withdrawAmount := new(big.Int).SetUint64(10_000)
	recipientUA := []byte{0x01, 0x02, 0x03}
	mustTransact(t, ctx, evm, auth, wjuno, "approve", bridgeAddr, withdrawAmount)

	tx, err := bridge.Transact(auth, "requestWithdraw", withdrawAmount, recipientUA)
	if err != nil {
		t.Fatalf("requestWithdraw tx: %v", err)
	}
	reqRcpt := mustWaitMined(t, ctx, evm, tx)
	if reqRcpt.Status != 1 {
		t.Fatalf("requestWithdraw reverted")
	}

	withdrawalID, expiry, feeBpsAtReq := mustParseWithdrawRequested(t, bridgeABI, reqRcpt)
	if feeBpsAtReq != feeBps {
		t.Fatalf("feeBpsAtReq: got %d want %d", feeBpsAtReq, feeBps)
	}

	// extendWithdrawExpiryBatch
	newExpiry := expiry + 3600
	idsHash := crypto.Keccak256Hash(withdrawalID.Bytes())
	extendDigest := callBytes32(t, ctx, bridge, "extendWithdrawDigest", idsHash, uint64(newExpiry))
	extendSigs := signDigestSorted(t, extendDigest, opKeys[:3])

	mustTransact(t, ctx, evm, auth, bridge, "extendWithdrawExpiryBatch", []common.Hash{withdrawalID}, uint64(newExpiry), extendSigs)

	gotExpiry := callWithdrawalExpiry(t, ctx, bridge, withdrawalID)
	if gotExpiry != uint64(newExpiry) {
		t.Fatalf("expiry: got %d want %d", gotExpiry, newExpiry)
	}

	// finalizeWithdrawBatch
	fee := new(big.Int).Mul(withdrawAmount, new(big.Int).SetUint64(feeBpsAtReq))
	fee.Div(fee, big.NewInt(10_000))
	net := new(big.Int).Sub(withdrawAmount, fee)

	balBridgeBefore := callBalanceOf(t, ctx, wjuno, bridgeAddr)
	balFDBefore := callBalanceOf(t, ctx, wjuno, fdAddr)
	balSenderBefore := callBalanceOf(t, ctx, wjuno, owner)

	withdrawJournal, err := bridgeabi.EncodeWithdrawJournal(bridgeabi.WithdrawJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []bridgeabi.FinalizeItem{
			{
				WithdrawalId:    withdrawalID,
				RecipientUAHash: crypto.Keccak256Hash(recipientUA),
				NetAmount:       net,
			},
		},
	})
	if err != nil {
		t.Fatalf("EncodeWithdrawJournal: %v", err)
	}

	mustTransact(t, ctx, evm, auth, bridge, "finalizeWithdrawBatch", cpABI, cpSigs, []byte{0x99}, withdrawJournal)

	balBridgeAfter := callBalanceOf(t, ctx, wjuno, bridgeAddr)
	if balBridgeAfter.Sign() != 0 {
		t.Fatalf("bridge balance after finalize: got %s want 0", balBridgeAfter.String())
	}

	feeTip := new(big.Int).Mul(fee, new(big.Int).SetUint64(tipBps))
	feeTip.Div(feeTip, big.NewInt(10_000))
	feeToDist := new(big.Int).Sub(fee, feeTip)

	balFDAfter := callBalanceOf(t, ctx, wjuno, fdAddr)
	if gotDelta := new(big.Int).Sub(balFDAfter, balFDBefore); gotDelta.Cmp(feeToDist) != 0 {
		t.Fatalf("fee distributor delta: got %s want %s", gotDelta.String(), feeToDist.String())
	}

	balSenderAfter := callBalanceOf(t, ctx, wjuno, owner)
	if gotDelta := new(big.Int).Sub(balSenderAfter, balSenderBefore); gotDelta.Cmp(feeTip) != 0 {
		t.Fatalf("sender tip delta: got %s want %s", gotDelta.String(), feeTip.String())
	}

	// Sanity: escrow had the amount pre-finalize.
	if balBridgeBefore.Cmp(withdrawAmount) != 0 {
		t.Fatalf("bridge balance before finalize: got %s want %s", balBridgeBefore.String(), withdrawAmount.String())
	}

	// refund
	withdrawAmount2 := new(big.Int).SetUint64(1_000)
	recipientUA2 := []byte{0xaa}
	mustTransact(t, ctx, evm, auth, wjuno, "approve", bridgeAddr, withdrawAmount2)

	tx2, err := bridge.Transact(auth, "requestWithdraw", withdrawAmount2, recipientUA2)
	if err != nil {
		t.Fatalf("requestWithdraw #2: %v", err)
	}
	rcpt2 := mustWaitMined(t, ctx, evm, tx2)
	if rcpt2.Status != 1 {
		t.Fatalf("requestWithdraw #2 reverted")
	}
	withdrawalID2, _, _ := mustParseWithdrawRequested(t, bridgeABI, rcpt2)

	// Warp past expiry2 and mine a block.
	anvilIncreaseTimeAndMine(t, ctx, evm, int64(refundWindowSeconds)+2)

	balBeforeRefund := callBalanceOf(t, ctx, wjuno, owner)
	mustTransact(t, ctx, evm, auth, bridge, "refund", withdrawalID2)
	balAfterRefund := callBalanceOf(t, ctx, wjuno, owner)

	if gotDelta := new(big.Int).Sub(balAfterRefund, balBeforeRefund); gotDelta.Cmp(withdrawAmount2) != 0 {
		t.Fatalf("refund delta: got %s want %s", gotDelta.String(), withdrawAmount2.String())
	}
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
	// Package dir: <repo>/internal/withdrawfinalizer.
	root := filepath.Clean(filepath.Join(wd, "../.."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected repo root with go.mod at %s", root)
	}
	return root
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

type evmBackend interface {
	bind.ContractBackend
	bind.DeployBackend
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

func callBytes32(t *testing.T, ctx context.Context, c *bind.BoundContract, method string, args ...any) common.Hash {
	t.Helper()

	var res []interface{}
	if err := c.Call(&bind.CallOpts{Context: ctx}, &res, method, args...); err != nil {
		t.Fatalf("%s call: %v", method, err)
	}
	if len(res) != 1 {
		t.Fatalf("%s result count: got %d want 1", method, len(res))
	}
	out, ok := res[0].([32]byte)
	if !ok {
		t.Fatalf("%s result type: got %T want [32]byte", method, res[0])
	}
	return common.Hash(out)
}

func callWithdrawalExpiry(t *testing.T, ctx context.Context, bridge *bind.BoundContract, withdrawalID common.Hash) uint64 {
	t.Helper()

	// getWithdrawal returns: requester,address; amount,uint256; expiry,uint64; feeBps,uint96; finalized,bool; refunded,bool; recipientUA,bytes.
	var res []interface{}
	if err := bridge.Call(&bind.CallOpts{Context: ctx}, &res, "getWithdrawal", withdrawalID); err != nil {
		t.Fatalf("getWithdrawal call: %v", err)
	}
	if len(res) != 7 {
		t.Fatalf("getWithdrawal result count: got %d want 7", len(res))
	}
	exp, ok := res[2].(uint64)
	if !ok {
		t.Fatalf("getWithdrawal expiry type: got %T want uint64", res[2])
	}
	return exp
}

type withdrawRequestedEvent struct {
	Amount       *big.Int
	RecipientUA  []byte
	Expiry       uint64
	FeeBps       *big.Int
}

func mustParseWithdrawRequested(t *testing.T, bridgeABI abi.ABI, rcpt *types.Receipt) (common.Hash, uint64, uint64) {
	t.Helper()

	ev, ok := bridgeABI.Events["WithdrawRequested"]
	if !ok {
		t.Fatalf("missing WithdrawRequested event in abi")
	}
	for _, lg := range rcpt.Logs {
		if len(lg.Topics) == 0 || lg.Topics[0] != ev.ID {
			continue
		}
		var out withdrawRequestedEvent
		if err := bridgeABI.UnpackIntoInterface(&out, "WithdrawRequested", lg.Data); err != nil {
			t.Fatalf("unpack WithdrawRequested: %v", err)
		}
		// indexed withdrawalId, requester are in topics.
		if len(lg.Topics) < 3 {
			t.Fatalf("WithdrawRequested topics len: got %d want >=3", len(lg.Topics))
		}
		withdrawalID := lg.Topics[1]
		feeBps := uint64(0)
		if out.FeeBps != nil {
			feeBps = out.FeeBps.Uint64()
		}
		return withdrawalID, out.Expiry, feeBps
	}
	t.Fatalf("WithdrawRequested event not found")
	return common.Hash{}, 0, 0
}

type checkpointABI struct {
	Height           uint64
	BlockHash        common.Hash
	FinalOrchardRoot common.Hash
	BaseChainId      *big.Int
	BridgeContract   common.Address
}

func checkpointABIFrom(cp checkpoint.Checkpoint) checkpointABI {
	return checkpointABI{
		Height:           cp.Height,
		BlockHash:        cp.BlockHash,
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
	}
}

func anvilIncreaseTimeAndMine(t *testing.T, ctx context.Context, evm *ethclient.Client, seconds int64) {
	t.Helper()
	if seconds <= 0 {
		seconds = 1
	}

	var res any
	if err := evm.Client().CallContext(ctx, &res, "evm_increaseTime", seconds); err != nil {
		t.Fatalf("evm_increaseTime: %v", err)
	}
	if err := evm.Client().CallContext(ctx, &res, "evm_mine"); err != nil {
		t.Fatalf("evm_mine: %v", err)
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
		"--entrypoint", "anvil",
		image,
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
