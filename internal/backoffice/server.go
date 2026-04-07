package backoffice

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/backoffice/alerts"
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/emf"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
)

// ServerConfig holds all configuration for the backoffice API server.
type ServerConfig struct {
	Pool       *pgxpool.Pool
	BaseClient *ethclient.Client
	SP1RPCURL  string // Succinct prover network gRPC URL (e.g. rpc.mainnet.succinct.xyz)

	JunoRPCURL          string
	JunoRPCURLs         []string
	JunoRPCUser         string
	JunoRPCPass         string
	JunoScanURL         string
	JunoScanWalletID    string
	JunoScanBearerToken string

	DLQStore          dlq.Store
	AlertStore        *alerts.Store
	RuntimeStore      RuntimeSettingsStore
	BridgeSettings    BridgeSettingsProvider
	SettingsAudit     *SettingsAuditStore
	MinDepositUpdater MinDepositUpdater

	BridgeAddress              common.Address
	WJunoAddress               common.Address
	OperatorRegistryAddress    common.Address
	FeeDistributorAddress      common.Address
	OWalletUA                  string
	SP1RequestorAddress        common.Address
	OperatorAddresses          []common.Address
	BaseRelayerSignerAddresses []common.Address

	ServiceEntries    []ServiceEntry
	OperatorEndpoints []OperatorEndpoint

	KafkaBrokers       []string // Kafka broker addresses for health probe
	IPFSApiURL         string   // IPFS API URL for health probe (e.g. http://host:5001)
	IPFSApiBearerToken string

	AuthSecret string

	RateLimitPerSecond float64
	RateLimitBurst     int

	OperatorGasMinWei      *big.Int
	BaseRelayerFundsMinWei *big.Int
	ProverFundsMinWei      *big.Int
	ReadinessCheck         func(context.Context) error
	MetricsEmitter         metricEmitter

	Log *slog.Logger
}

type metricEmitter interface {
	Emit(...emf.Metric) error
}

// Server is the backoffice HTTP API server.
type Server struct {
	cfg    ServerConfig
	mux    *http.ServeMux
	log    *slog.Logger
	closer []func()
}

// New creates a new backoffice server with all routes registered.
func New(cfg ServerConfig) (*Server, error) {
	if cfg.Pool == nil {
		return nil, fmt.Errorf("backoffice: nil pool")
	}
	if cfg.BaseClient == nil {
		return nil, fmt.Errorf("backoffice: nil base client")
	}
	if cfg.AuthSecret == "" {
		return nil, fmt.Errorf("backoffice: empty auth secret")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.RateLimitPerSecond <= 0 {
		cfg.RateLimitPerSecond = 15
	}
	if cfg.RateLimitBurst <= 0 {
		cfg.RateLimitBurst = 30
	}
	if cfg.OperatorGasMinWei == nil {
		cfg.OperatorGasMinWei = new(big.Int)
	}
	if cfg.BaseRelayerFundsMinWei == nil {
		cfg.BaseRelayerFundsMinWei = new(big.Int).Set(cfg.OperatorGasMinWei)
	}
	if cfg.ProverFundsMinWei == nil {
		cfg.ProverFundsMinWei = new(big.Int)
	}

	s := &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
		log: cfg.Log,
	}

	// Register routes.
	s.mux.HandleFunc("GET /livez", s.handleHealthz)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleHealthz)

	// DLQ routes
	s.mux.HandleFunc("GET /api/dlq/proofs", s.handleDLQListProofs)
	s.mux.HandleFunc("GET /api/dlq/deposits", s.handleDLQListDeposits)
	s.mux.HandleFunc("GET /api/dlq/withdrawals", s.handleDLQListWithdrawals)
	s.mux.HandleFunc("POST /api/dlq/{type}/{id}/acknowledge", s.handleDLQAcknowledge)
	s.mux.HandleFunc("GET /api/dlq/counts", s.handleDLQCounts)

	// Funds routes
	s.mux.HandleFunc("GET /api/funds", s.handleFunds)

	// Ops routes
	s.mux.HandleFunc("GET /api/ops/deposits/recent", s.handleRecentDeposits)
	s.mux.HandleFunc("GET /api/ops/withdrawals/recent", s.handleRecentWithdrawals)
	s.mux.HandleFunc("GET /api/ops/batches/stuck", s.handleStuckBatches)
	s.mux.HandleFunc("GET /api/ops/services/health", s.handleServicesHealth)
	s.mux.HandleFunc("GET /api/ops/operators/status", s.handleOperatorStatus)

	// Analytics routes
	s.mux.HandleFunc("GET /api/analytics/overview", s.handleAnalyticsOverview)
	s.mux.HandleFunc("GET /api/analytics/bridges-over-time", s.handleBridgesOverTime)
	s.mux.HandleFunc("GET /api/analytics/operator-revenue", s.handleOperatorRevenue)

	// Settings routes
	s.mux.HandleFunc("GET /api/settings/runtime", s.handleRuntimeSettings)
	s.mux.HandleFunc("PUT /api/settings/runtime", s.handleUpdateRuntimeSettings)
	s.mux.HandleFunc("GET /api/settings/audit", s.handleSettingsAudit)
	s.mux.HandleFunc("POST /api/settings/min-deposit", s.handleSetMinDeposit)

	// Alert routes
	if s.cfg.AlertStore != nil {
		alerts.RegisterRoutes(s.mux, s.cfg.AlertStore)
	}

	// UI routes (dashboard + embedded static assets)
	RegisterUIRoutes(s.mux)

	return s, nil
}

// Handler returns the http.Handler with auth and rate-limit middleware applied.
func (s *Server) Handler() http.Handler {
	// Chain: rate limit -> auth -> mux
	return s.rateLimitMiddleware(s.authMiddleware(s.mux))
}

// Close cleans up server resources.
func (s *Server) Close() {
	for _, fn := range s.closer {
		fn()
	}
}

// handleHealthz returns a simple health check response.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/readyz" && s.cfg.ReadinessCheck != nil {
		if err := s.cfg.ReadinessCheck(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": "v1",
				"status":  "not_ready",
				"time":    time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": "v1",
		"status":  "ok",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// writeJSON encodes v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{
		"version": "v1",
		"error":   msg,
	})
}

// hex32 returns the 0x-prefixed hex encoding of a [32]byte.
func hex32(b [32]byte) string {
	return "0x" + common.Bytes2Hex(b[:])
}

// ServiceEntry describes a service health endpoint with a human-readable label.
type ServiceEntry struct {
	Label string
	URL   string
}

// OperatorEndpoint describes an operator signer endpoint for health checking.
type OperatorEndpoint struct {
	Address  common.Address
	Endpoint string // host:port for HTTP /healthz probe
}

type RuntimeSettingsStore interface {
	Get(ctx context.Context) (runtimeconfig.Settings, error)
	Update(ctx context.Context, settings runtimeconfig.Settings, updatedBy string) (runtimeconfig.Settings, error)
}

type BridgeSettingsProvider interface {
	Current() (bridgeconfig.Snapshot, error)
}

func isProbePath(path string) bool {
	return path == "/healthz" || path == "/livez" || path == "/readyz"
}

func (s *Server) configuredJunoRPCURLs() []string {
	urls := make([]string, 0, len(s.cfg.JunoRPCURLs)+1)
	seen := make(map[string]struct{}, len(s.cfg.JunoRPCURLs)+1)
	appendURL := func(raw string) {
		url := strings.TrimSpace(raw)
		if url == "" {
			return
		}
		if _, ok := seen[url]; ok {
			return
		}
		seen[url] = struct{}{}
		urls = append(urls, url)
	}

	for _, url := range s.cfg.JunoRPCURLs {
		appendURL(url)
	}
	appendURL(s.cfg.JunoRPCURL)
	return urls
}
