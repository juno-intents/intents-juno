package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/queue"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
	"github.com/juno-intents/intents-juno/internal/withdrawfinalizer"
	"github.com/juno-intents/intents-juno/internal/witnessextract"
)

type envelope struct {
	Version string `json:"version"`
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

const (
	defaultJunoScanBearerEnv = "JUNO_SCAN_BEARER_TOKEN"
	defaultJunoRPCUserEnv    = "JUNO_RPC_USER"
	defaultJunoRPCPassEnv    = "JUNO_RPC_PASS"
)

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")

		baseChainID     = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr      = flag.String("bridge-address", "", "Bridge contract address (required)")
		operators       = flag.String("operators", "", "comma-separated operator addresses for checkpoint quorum verification (required)")
		threshold       = flag.Int("operator-threshold", 0, "operator signature threshold for checkpoint quorum verification (required)")
		withdrawImageID = flag.String("withdraw-image-id", "", "withdraw zkVM image id (bytes32 hex, required)")
		owalletOVK      = flag.String("owallet-ovk", "", "optional 32-byte OWallet OVK hex for binary guest private input mode")
		witnessExtract  = flag.Bool("withdraw-witness-extractor-enabled", false, "enable withdraw witness extraction from juno batch tx via juno-scan + junocashd (auto-enabled with --owallet-ovk)")
		junoScanURL     = flag.String("juno-scan-url", "", "juno-scan base URL for witness extraction")
		junoScanWallet  = flag.String("juno-scan-wallet-id", "", "juno-scan wallet id for witness extraction")
		junoScanBearer  = flag.String("juno-scan-bearer-env", defaultJunoScanBearerEnv, "env var containing optional juno-scan bearer token for witness extraction")
		junoRPCURL      = flag.String("juno-rpc-url", "", "junocashd JSON-RPC URL for witness extraction")
		junoRPCUserEnv  = flag.String("juno-rpc-user-env", defaultJunoRPCUserEnv, "env var containing junocashd RPC username for witness extraction")
		junoRPCPassEnv  = flag.String("juno-rpc-pass-env", defaultJunoRPCPassEnv, "env var containing junocashd RPC password for witness extraction")

		baseRelayerURL     = flag.String("base-relayer-url", "", "base-relayer HTTP URL (required)")
		baseRelayerAuthEnv = flag.String("base-relayer-auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing base-relayer bearer auth token (required)")

		owner        = flag.String("owner", "", "unique finalizer owner id (required; used for DB leases)")
		leaseTTL     = flag.Duration("lease-ttl", 30*time.Second, "per-batch lease TTL")
		maxBatches   = flag.Int("max-batches", 10, "maximum batches to finalize per tick")
		tickInterval = flag.Duration("tick-interval", 1*time.Second, "finalizer tick interval")
		gasLimit     = flag.Uint64("gas-limit", 0, "optional gas limit override; 0 => estimate")

		submitTimeout = flag.Duration("submit-timeout", 5*time.Minute, "per-batch timeout (proof request + base-relayer)")

		proofDriver        = flag.String("proof-driver", "queue", "proof client driver: queue|mock")
		proofRequestTopic  = flag.String("proof-request-topic", "proof.requests.v1", "proof request topic")
		proofResultTopic   = flag.String("proof-result-topic", "proof.fulfillments.v1", "proof fulfillment topic")
		proofFailureTopic  = flag.String("proof-failure-topic", "proof.failures.v1", "proof failure topic")
		proofResponseGroup = flag.String("proof-response-group", "", "proof response consumer group (required for kafka when proof-driver=queue)")
		proofPriority      = flag.Int("proof-priority", 1, "proof request priority")
		proofMockSeal      = flag.String("proof-mock-seal", "0x99", "mock proof seal hex used when --proof-driver=mock")

		queueDriver   = flag.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
		queueBrokers  = flag.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
		queueGroup    = flag.String("queue-group", "withdraw-finalizer", "queue consumer group (required for kafka)")
		queueTopics   = flag.String("queue-topics", "checkpoints.packages.v1", "comma-separated queue topics")
		maxLineBytes  = flag.Int("max-line-bytes", 1<<20, "maximum stdin line size for stdio driver (bytes)")
		queueMaxBytes = flag.Int("queue-max-bytes", 10<<20, "maximum kafka message size for consumer reads (bytes)")
		ackTimeout    = flag.Duration("queue-ack-timeout", 5*time.Second, "timeout for queue message acknowledgements")

		blobDriver     = flag.String("blob-driver", blobstore.DriverS3, "blobstore driver: s3|memory")
		blobBucket     = flag.String("blob-bucket", "", "S3 bucket for durable withdrawal proof artifacts (required for s3)")
		blobPrefix     = flag.String("blob-prefix", "withdraw-finalizer", "blob key prefix")
		blobMaxGetSize = flag.Int64("blob-max-get-size", 16<<20, "max blob get size in bytes")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *postgresDSN == "" || *baseChainID == 0 || *bridgeAddr == "" || *operators == "" || *threshold <= 0 || *withdrawImageID == "" || *baseRelayerURL == "" || *owner == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn, --base-chain-id, --bridge-address, --operators, --operator-threshold, --withdraw-image-id, --base-relayer-url, and --owner are required")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *leaseTTL <= 0 || *maxBatches <= 0 || *tickInterval <= 0 || *submitTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: durations and --max-batches must be > 0")
		os.Exit(2)
	}
	if *maxLineBytes <= 0 || *queueMaxBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-line-bytes and --queue-max-bytes must be > 0")
		os.Exit(2)
	}
	if *ackTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --queue-ack-timeout must be > 0")
		os.Exit(2)
	}
	if *proofPriority < 0 {
		fmt.Fprintln(os.Stderr, "error: --proof-priority must be >= 0")
		os.Exit(2)
	}
	if *blobMaxGetSize <= 0 {
		fmt.Fprintln(os.Stderr, "error: --blob-max-get-size must be > 0")
		os.Exit(2)
	}
	if normalizeBlobDriver(*blobDriver) == blobstore.DriverS3 && strings.TrimSpace(*blobBucket) == "" {
		fmt.Fprintln(os.Stderr, "error: --blob-bucket is required when --blob-driver=s3")
		os.Exit(2)
	}

	bridge := common.HexToAddress(*bridgeAddr)
	imageID, err := parseHash32Strict(*withdrawImageID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --withdraw-image-id: %v\n", err)
		os.Exit(2)
	}
	owalletOVKBytes, err := decodeHexBytesOptional(*owalletOVK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --owallet-ovk: %v\n", err)
		os.Exit(2)
	}
	if n := len(owalletOVKBytes); n != 0 && n != 32 {
		fmt.Fprintf(os.Stderr, "error: --owallet-ovk must be 32 bytes when set, got %d\n", n)
		os.Exit(2)
	}
	operatorAddrs, err := checkpoint.ParseOperatorAddressesCSV(*operators)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --operators: %v\n", err)
		os.Exit(2)
	}
	extractorCfg := withdrawWitnessExtractorConfig{
		Enabled:       *witnessExtract || len(owalletOVKBytes) == 32,
		ScanURL:       *junoScanURL,
		WalletID:      *junoScanWallet,
		ScanBearerEnv: *junoScanBearer,
		RPCURL:        *junoRPCURL,
		RPCUserEnv:    *junoRPCUserEnv,
		RPCPassEnv:    *junoRPCPassEnv,
	}
	if err := validateWithdrawWitnessExtractorConfig(extractorCfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	witnessExtractor, err := newWithdrawWitnessExtractor(extractorCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: init witness extractor: %v\n", err)
		os.Exit(2)
	}

	authToken := os.Getenv(*baseRelayerAuthEnv)
	if authToken == "" {
		fmt.Fprintf(os.Stderr, "error: missing base-relayer auth token in env %s\n", *baseRelayerAuthEnv)
		os.Exit(2)
	}

	hc := &http.Client{
		Timeout: *submitTimeout,
	}
	baseClient, err := httpapi.NewClient(*baseRelayerURL, authToken, httpapi.WithHTTPClient(hc))
	if err != nil {
		log.Error("init base-relayer client", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
		Driver:        *queueDriver,
		Brokers:       queue.SplitCommaList(*queueBrokers),
		Group:         *queueGroup,
		Topics:        queue.SplitCommaList(*queueTopics),
		KafkaMaxBytes: *queueMaxBytes,
		MaxLineBytes:  *maxLineBytes,
	})
	if err != nil {
		log.Error("init queue consumer", "err", err)
		os.Exit(2)
	}
	defer func() { _ = consumer.Close() }()

	proofRequester, proofCleanup, err := initProofClient(ctx, initProofClientConfig{
		driver:             *proofDriver,
		queueDriver:        *queueDriver,
		queueBrokers:       queue.SplitCommaList(*queueBrokers),
		proofRequestTopic:  *proofRequestTopic,
		proofResultTopic:   *proofResultTopic,
		proofFailureTopic:  *proofFailureTopic,
		proofGroup:         *proofResponseGroup,
		maxLineBytes:       *maxLineBytes,
		queueMaxBytes:      *queueMaxBytes,
		ackTimeout:         *ackTimeout,
		mockSeal:           *proofMockSeal,
		log:                log,
		defaultGroupPrefix: "withdraw-finalizer-proof-",
	})
	if err != nil {
		log.Error("init proof client", "err", err)
		os.Exit(2)
	}
	defer proofCleanup()

	pool, err := pgxpool.New(ctx, *postgresDSN)
	if err != nil {
		log.Error("init pgx pool", "err", err)
		os.Exit(2)
	}
	defer pool.Close()

	store, err := withdrawpg.New(pool)
	if err != nil {
		log.Error("init withdraw store", "err", err)
		os.Exit(2)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		log.Error("ensure withdraw schema", "err", err)
		os.Exit(2)
	}

	artifactStore, err := newBlobStore(ctx, *blobDriver, *blobBucket, *blobPrefix, *blobMaxGetSize)
	if err != nil {
		log.Error("init blob store", "err", err)
		os.Exit(2)
	}

	leaseStore, err := leasespg.New(pool)
	if err != nil {
		log.Error("init lease store", "err", err)
		os.Exit(2)
	}
	if err := leaseStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure lease schema", "err", err)
		os.Exit(2)
	}

	f, err := withdrawfinalizer.New(withdrawfinalizer.Config{
		Owner:               *owner,
		LeaseTTL:            *leaseTTL,
		MaxBatches:          *maxBatches,
		BaseChainID:         *baseChainID,
		BridgeAddress:       bridge,
		WithdrawImageID:     imageID,
		OperatorAddresses:   operatorAddrs,
		OperatorThreshold:   *threshold,
		GasLimit:            *gasLimit,
		ProofRequestTimeout: *submitTimeout,
		ProofPriority:       *proofPriority,
		OWalletOVKBytes:     owalletOVKBytes,
		WitnessExtractor:    witnessExtractor,
	}, store, leaseStore, baseClient, proofRequester, log)
	if err != nil {
		log.Error("init withdraw finalizer", "err", err)
		os.Exit(2)
	}
	f.WithBlobStore(artifactStore)

	log.Info("withdraw finalizer started",
		"owner", *owner,
		"baseChainID", *baseChainID,
		"bridge", bridge,
		"proofDriver", *proofDriver,
		"proofRequestTopic", *proofRequestTopic,
		"proofResultTopic", *proofResultTopic,
		"proofFailureTopic", *proofFailureTopic,
		"maxBatches", *maxBatches,
		"leaseTTL", leaseTTL.String(),
		"tickInterval", tickInterval.String(),
		"queueDriver", *queueDriver,
		"blobDriver", normalizeBlobDriver(*blobDriver),
		"blobBucket", strings.TrimSpace(*blobBucket),
		"blobPrefix", strings.TrimSpace(*blobPrefix),
		"witnessExtractorEnabled", extractorCfg.Enabled,
	)

	t := time.NewTicker(*tickInterval)
	defer t.Stop()
	msgCh := consumer.Messages()
	errCh := consumer.Errors()

	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown", "reason", ctx.Err())
			return
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if err != nil {
				log.Error("queue consume error", "err", err)
			}
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, *submitTimeout)
			err := f.Tick(cctx)
			cancel()
			if err != nil {
				log.Error("tick", "err", err)
			}
		case qmsg, ok := <-msgCh:
			if !ok {
				return
			}
			line := qmsg.Value
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}

			var env envelope
			if err := json.Unmarshal(line, &env); err != nil {
				log.Error("parse input json", "err", err)
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}

			switch env.Version {
			case "checkpoints.package.v1":
				var cpMsg checkpointPackageV1
				if err := json.Unmarshal(line, &cpMsg); err != nil {
					log.Error("parse checkpoint package", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				if cpMsg.Version != "checkpoints.package.v1" {
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				if want := checkpoint.Digest(cpMsg.Checkpoint); cpMsg.Digest != want {
					log.Error("checkpoint digest mismatch", "want", want, "got", cpMsg.Digest)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}

				sigs := make([][]byte, 0, len(cpMsg.Signatures))
				for i, s := range cpMsg.Signatures {
					b, err := decodeHexBytes(s)
					if err != nil {
						log.Error("decode operator signature", "err", err, "index", i)
						sigs = nil
						break
					}
					sigs = append(sigs, b)
				}
				if sigs == nil {
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}

				cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := f.IngestCheckpoint(cctx, withdrawfinalizer.CheckpointPackage{
					Checkpoint:         cpMsg.Checkpoint,
					OperatorSignatures: sigs,
				})
				cancel()
				if err != nil {
					log.Error("ingest checkpoint", "err", err)
				}
				ackMessage(qmsg, *ackTimeout, log)
			default:
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}
		}
	}
}

type withdrawWitnessExtractorConfig struct {
	Enabled       bool
	ScanURL       string
	WalletID      string
	ScanBearerEnv string
	RPCURL        string
	RPCUserEnv    string
	RPCPassEnv    string
}

func validateWithdrawWitnessExtractorConfig(cfg withdrawWitnessExtractorConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.ScanURL) == "" {
		return fmt.Errorf("--juno-scan-url is required when withdraw witness extractor is enabled")
	}
	if strings.TrimSpace(cfg.WalletID) == "" {
		return fmt.Errorf("--juno-scan-wallet-id is required when withdraw witness extractor is enabled")
	}
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return fmt.Errorf("--juno-rpc-url is required when withdraw witness extractor is enabled")
	}
	if strings.TrimSpace(cfg.RPCUserEnv) == "" {
		return fmt.Errorf("--juno-rpc-user-env is required when withdraw witness extractor is enabled")
	}
	if strings.TrimSpace(cfg.RPCPassEnv) == "" {
		return fmt.Errorf("--juno-rpc-pass-env is required when withdraw witness extractor is enabled")
	}
	return nil
}

func newWithdrawWitnessExtractor(cfg withdrawWitnessExtractorConfig) (withdrawfinalizer.WithdrawWitnessExtractor, error) {
	if err := validateWithdrawWitnessExtractorConfig(cfg); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}

	rpcUserEnv := strings.TrimSpace(cfg.RPCUserEnv)
	rpcPassEnv := strings.TrimSpace(cfg.RPCPassEnv)
	rpcUser := strings.TrimSpace(os.Getenv(rpcUserEnv))
	rpcPass := strings.TrimSpace(os.Getenv(rpcPassEnv))
	if rpcUser == "" || rpcPass == "" {
		return nil, fmt.Errorf("missing junocashd RPC credentials in env %s/%s", rpcUserEnv, rpcPassEnv)
	}

	rpcClient, err := junorpc.New(strings.TrimSpace(cfg.RPCURL), rpcUser, rpcPass)
	if err != nil {
		return nil, err
	}

	scanBearer := strings.TrimSpace(os.Getenv(strings.TrimSpace(cfg.ScanBearerEnv)))
	scanClient := &scanHTTPClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.ScanURL), "/"),
		bearer:  scanBearer,
		hc:      &http.Client{Timeout: 15 * time.Second},
	}
	return &withdrawWitnessExtractor{
		walletID: strings.TrimSpace(cfg.WalletID),
		builder:  witnessextract.New(scanClient, rpcClient),
		minAnchorHeight: func(ctx context.Context, txid string) (int64, error) {
			return txMinAnchorHeight(ctx, rpcClient, txid)
		},
	}, nil
}

type withdrawWitnessExtractor struct {
	walletID        string
	builder         *witnessextract.Builder
	minAnchorHeight func(ctx context.Context, txid string) (int64, error)
}

func txMinAnchorHeight(ctx context.Context, rpcClient *junorpc.Client, txid string) (int64, error) {
	if rpcClient == nil {
		return 0, fmt.Errorf("withdraw witness extractor: nil rpc client")
	}
	txMeta, err := rpcClient.GetRawTransaction(ctx, txid)
	if err != nil {
		return 0, fmt.Errorf("withdraw witness extractor: getrawtransaction metadata: %w", err)
	}
	if txMeta.Confirmations <= 0 {
		return 0, fmt.Errorf("withdraw witness extractor: tx not confirmed yet txid=%s confirmations=%d", txid, txMeta.Confirmations)
	}

	chainInfo, err := rpcClient.GetBlockChainInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("withdraw witness extractor: getblockchaininfo: %w", err)
	}
	confirms := uint64(txMeta.Confirmations)
	if confirms > chainInfo.Blocks+1 {
		return 0, fmt.Errorf(
			"withdraw witness extractor: inconsistent confirmations for txid=%s confirmations=%d chain_height=%d",
			txid,
			txMeta.Confirmations,
			chainInfo.Blocks,
		)
	}
	return int64(chainInfo.Blocks-confirms) + 1, nil
}

func (e *withdrawWitnessExtractor) ExtractWithdrawWitness(ctx context.Context, req withdrawfinalizer.WithdrawWitnessExtractRequest) ([]byte, error) {
	if e == nil || e.builder == nil {
		return nil, fmt.Errorf("withdraw witness extractor: nil builder")
	}
	txHash := strings.TrimSpace(req.TxHash)
	if txHash == "" {
		return nil, fmt.Errorf("withdraw witness extractor: missing tx hash")
	}
	if len(req.RecipientUA) != 43 {
		return nil, fmt.Errorf("withdraw witness extractor: recipient ua must be 43 bytes, got %d", len(req.RecipientUA))
	}

	var recipientRaw [43]byte
	copy(recipientRaw[:], req.RecipientUA)
	if req.AnchorHeight != nil && e.minAnchorHeight != nil {
		minHeight, err := e.minAnchorHeight(ctx, txHash)
		if err != nil {
			return nil, fmt.Errorf("withdraw witness extractor: derive tx minimum anchor height: %w", err)
		}
		if *req.AnchorHeight < minHeight {
			return nil, fmt.Errorf(
				"withdraw witness extractor: anchor height %d below tx minimum anchor height %d for txid=%s",
				*req.AnchorHeight,
				minHeight,
				txHash,
			)
		}
	}

	out, err := e.builder.BuildWithdraw(ctx, witnessextract.WithdrawRequest{
		WalletID:            e.walletID,
		TxID:                txHash,
		ActionIndex:         req.ActionIndex,
		ExpectedValueZat:    req.ExpectedValueZat,
		AnchorHeight:        req.AnchorHeight,
		WithdrawalID:        req.WithdrawalID,
		RecipientRawAddress: recipientRaw,
	})
	if err != nil {
		return nil, fmt.Errorf("withdraw witness extractor: build withdraw witness: %w", err)
	}
	if len(out.WitnessItem) == 0 {
		return nil, fmt.Errorf("withdraw witness extractor: empty witness item")
	}
	return append([]byte(nil), out.WitnessItem...), nil
}

type scanHTTPClient struct {
	baseURL string
	bearer  string
	hc      *http.Client
}

func (c *scanHTTPClient) ListWalletIDs(ctx context.Context) ([]string, error) {
	if c == nil || c.hc == nil {
		return nil, fmt.Errorf("scan client is nil")
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, fmt.Errorf("scan client base URL is empty")
	}

	body, status, err := c.do(ctx, http.MethodGet, c.baseURL+"/v1/wallets", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("juno-scan list wallets status=%d body=%s", status, strings.TrimSpace(string(body)))
	}

	var resp struct {
		Wallets []json.RawMessage `json:"wallets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode juno-scan list wallets: %w", err)
	}

	out := make([]string, 0, len(resp.Wallets))
	seen := make(map[string]struct{}, len(resp.Wallets))
	for _, raw := range resp.Wallets {
		id := ""
		if err := json.Unmarshal(raw, &id); err == nil {
			id = strings.TrimSpace(id)
		} else {
			var item struct {
				WalletID string `json:"wallet_id"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				continue
			}
			id = strings.TrimSpace(item.WalletID)
		}
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func (c *scanHTTPClient) ListWalletNotes(ctx context.Context, walletID string) ([]witnessextract.WalletNote, error) {
	if c == nil || c.hc == nil {
		return nil, fmt.Errorf("scan client is nil")
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, fmt.Errorf("scan client base URL is empty")
	}
	wallet := strings.TrimSpace(walletID)
	if wallet == "" {
		return nil, fmt.Errorf("wallet id is empty")
	}

	cursor := ""
	seen := map[string]struct{}{}
	out := make([]witnessextract.WalletNote, 0, 1024)
	for {
		path := c.baseURL + "/v1/wallets/" + url.PathEscape(wallet) + "/notes?limit=1000"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		body, status, err := c.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("juno-scan list notes status=%d body=%s", status, strings.TrimSpace(string(body)))
		}

		var resp struct {
			Notes []struct {
				TxID        string `json:"txid"`
				ActionIndex int32  `json:"action_index"`
				Position    *int64 `json:"position,omitempty"`
				ValueZat    uint64 `json:"value_zat,omitempty"`
			} `json:"notes"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode juno-scan list notes: %w", err)
		}
		for _, n := range resp.Notes {
			out = append(out, witnessextract.WalletNote{
				TxID:        n.TxID,
				ActionIndex: n.ActionIndex,
				Position:    n.Position,
				ValueZat:    n.ValueZat,
			})
		}

		next := strings.TrimSpace(resp.NextCursor)
		if next == "" {
			break
		}
		if _, ok := seen[next]; ok {
			return nil, fmt.Errorf("juno-scan list notes cursor did not advance")
		}
		seen[next] = struct{}{}
		cursor = next
	}
	return out, nil
}

func (c *scanHTTPClient) OrchardWitness(ctx context.Context, anchorHeight *int64, positions []uint32) (witnessextract.WitnessResponse, error) {
	if c == nil || c.hc == nil {
		return witnessextract.WitnessResponse{}, fmt.Errorf("scan client is nil")
	}

	reqBody := map[string]any{
		"positions": positions,
	}
	if anchorHeight != nil {
		reqBody["anchor_height"] = *anchorHeight
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return witnessextract.WitnessResponse{}, err
	}

	body, status, err := c.do(ctx, http.MethodPost, c.baseURL+"/v1/orchard/witness", raw)
	if err != nil {
		return witnessextract.WitnessResponse{}, err
	}
	if status != http.StatusOK {
		return witnessextract.WitnessResponse{}, fmt.Errorf("juno-scan orchard witness status=%d body=%s", status, strings.TrimSpace(string(body)))
	}

	var resp struct {
		AnchorHeight int64 `json:"anchor_height"`
		Root         string
		Paths        []struct {
			Position uint32   `json:"position"`
			AuthPath []string `json:"auth_path"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return witnessextract.WitnessResponse{}, fmt.Errorf("decode juno-scan orchard witness: %w", err)
	}

	out := witnessextract.WitnessResponse{
		AnchorHeight: resp.AnchorHeight,
		Root:         resp.Root,
		Paths:        make([]witnessextract.WitnessPath, 0, len(resp.Paths)),
	}
	for _, p := range resp.Paths {
		out.Paths = append(out.Paths, witnessextract.WitnessPath{
			Position: p.Position,
			AuthPath: append([]string(nil), p.AuthPath...),
		})
	}
	return out, nil
}

func (c *scanHTTPClient) do(ctx context.Context, method, endpoint string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, 0, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, 0, err
	}
	return respBody, resp.StatusCode, nil
}

func ackMessage(msg queue.Message, timeout time.Duration, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := msg.Ack(ctx); err != nil {
		log.Error("ack queue message", "topic", msg.Topic, "err", err)
	}
}

type initProofClientConfig struct {
	driver             string
	queueDriver        string
	queueBrokers       []string
	proofRequestTopic  string
	proofResultTopic   string
	proofFailureTopic  string
	proofGroup         string
	maxLineBytes       int
	queueMaxBytes      int
	ackTimeout         time.Duration
	mockSeal           string
	log                *slog.Logger
	defaultGroupPrefix string
}

func initProofClient(ctx context.Context, cfg initProofClientConfig) (proofclient.Client, func(), error) {
	switch strings.ToLower(strings.TrimSpace(cfg.driver)) {
	case "mock":
		seal, err := decodeHexBytes(cfg.mockSeal)
		if err != nil {
			return nil, func() {}, fmt.Errorf("decode --proof-mock-seal: %w", err)
		}
		return &proofclient.StaticClient{Result: proofclient.Result{Seal: seal}}, func() {}, nil
	case "queue":
		if strings.EqualFold(strings.TrimSpace(cfg.queueDriver), queue.DriverStdio) {
			return nil, func() {}, fmt.Errorf("proof-driver=queue is incompatible with queue-driver=stdio; use --proof-driver=mock for local stdio mode")
		}
		group := strings.TrimSpace(cfg.proofGroup)
		if group == "" {
			hostname, _ := os.Hostname()
			hostname = strings.TrimSpace(hostname)
			if hostname == "" {
				hostname = "local"
			}
			group = cfg.defaultGroupPrefix + hostname
		}

		producer, err := queue.NewProducer(queue.ProducerConfig{
			Driver:  cfg.queueDriver,
			Brokers: cfg.queueBrokers,
		})
		if err != nil {
			return nil, func() {}, err
		}
		consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
			Driver:        cfg.queueDriver,
			Brokers:       cfg.queueBrokers,
			Group:         group,
			Topics:        []string{cfg.proofResultTopic, cfg.proofFailureTopic},
			KafkaMaxBytes: cfg.queueMaxBytes,
			MaxLineBytes:  cfg.maxLineBytes,
		})
		if err != nil {
			_ = producer.Close()
			return nil, func() {}, err
		}
		client, err := proofclient.NewQueueClient(proofclient.QueueConfig{
			RequestTopic: cfg.proofRequestTopic,
			ResultTopic:  cfg.proofResultTopic,
			FailureTopic: cfg.proofFailureTopic,
			Producer:     producer,
			Consumer:     consumer,
			AckTimeout:   cfg.ackTimeout,
			Log:          cfg.log,
		})
		if err != nil {
			_ = producer.Close()
			_ = consumer.Close()
			return nil, func() {}, err
		}
		cleanup := func() {
			_ = consumer.Close()
			_ = producer.Close()
		}
		return client, cleanup, nil
	default:
		return nil, func() {}, fmt.Errorf("unsupported proof driver %q", cfg.driver)
	}
}

func decodeHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, fmt.Errorf("empty hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return b, nil
}

func decodeHexBytesOptional(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return b, nil
}

func parseHash32Strict(s string) (common.Hash, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return common.Hash{}, fmt.Errorf("expected 32-byte hex, got len %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode hex: %w", err)
	}
	return common.BytesToHash(b), nil
}

func normalizeBlobDriver(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return blobstore.DriverS3
	}
	return s
}

func newBlobStore(ctx context.Context, driver string, bucket string, prefix string, maxGetSize int64) (blobstore.Store, error) {
	cfg := blobstore.Config{
		Driver:     normalizeBlobDriver(driver),
		Bucket:     strings.TrimSpace(bucket),
		Prefix:     strings.TrimSpace(prefix),
		MaxGetSize: maxGetSize,
	}

	if cfg.Driver == blobstore.DriverS3 {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("load aws config: %w", err)
		}
		cfg.S3Client = awss3.NewFromConfig(awsCfg)
	}

	return blobstore.New(cfg)
}
