package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/dlq"
)

// EngineConfig holds all configuration and dependencies for the alert engine.
type EngineConfig struct {
	// CheckInterval controls how often the engine runs its checks. Default 30s.
	CheckInterval time.Duration

	// Thresholds
	OperatorGasMinWei      *big.Int // minimum ETH balance per operator
	ProverFundsMinWei      *big.Int // minimum ETH balance for SP1 requestor
	StuckBatchMinutes      int      // deposit/withdrawal batch staleness threshold (default 30)
	CheckpointGapMinutes   int      // checkpoint freshness threshold (default 60)
	DLQInsertionRatePerMin int      // unused placeholder for rate-based alerting (default 5)

	// Dependencies
	Pool                *pgxpool.Pool
	EthClient           *ethclient.Client
	OperatorAddresses   []common.Address
	SP1RequestorAddress common.Address
	ServiceURLs         []string
	DLQStore            dlq.Store
}

func (c *EngineConfig) setDefaults() {
	if c.CheckInterval == 0 {
		c.CheckInterval = 30 * time.Second
	}
	if c.StuckBatchMinutes == 0 {
		c.StuckBatchMinutes = 30
	}
	if c.CheckpointGapMinutes == 0 {
		c.CheckpointGapMinutes = 60
	}
	if c.DLQInsertionRatePerMin == 0 {
		c.DLQInsertionRatePerMin = 5
	}
	if c.OperatorGasMinWei == nil {
		// Default: 0.01 ETH
		c.OperatorGasMinWei = new(big.Int).Mul(big.NewInt(1e16), big.NewInt(1))
	}
	if c.ProverFundsMinWei == nil {
		// Default: 0.05 ETH
		c.ProverFundsMinWei = new(big.Int).Mul(big.NewInt(5e16), big.NewInt(1))
	}
}

// Engine runs background alert checks on a configurable interval.
type Engine struct {
	cfg    EngineConfig
	store  *Store
	cancel context.CancelFunc
	wg     sync.WaitGroup

	httpClient *http.Client
}

// NewEngine creates a new alert engine. It returns an error if required
// dependencies are missing.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Pool == nil {
		return nil, fmt.Errorf("alerts: Pool is required")
	}
	cfg.setDefaults()

	return &Engine{
		cfg:   cfg,
		store: NewStore(cfg.Pool),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

// Store returns the underlying alert store so callers (e.g. HTTP handlers)
// can query alerts.
func (e *Engine) Store() *Store {
	return e.store
}

// Start launches the background check goroutine. It blocks until ctx is
// cancelled or Stop is called.
func (e *Engine) Start(ctx context.Context) {
	ctx, e.cancel = context.WithCancel(ctx)
	e.wg.Add(1)
	go e.loop(ctx)
}

// Stop signals the background goroutine to stop and waits for it to finish.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
}

func (e *Engine) loop(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(e.cfg.CheckInterval)
	defer ticker.Stop()

	// Run once immediately.
	e.runChecks(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runChecks(ctx)
		}
	}
}

func (e *Engine) runChecks(ctx context.Context) {
	e.checkOperatorGas(ctx)
	e.checkProverFunds(ctx)
	e.checkStuckDepositBatches(ctx)
	e.checkStuckWithdrawalBatches(ctx)
	e.checkDLQ(ctx)
	e.checkServiceHealth(ctx)
}

// checkOperatorGas checks each operator address ETH balance on Base.
func (e *Engine) checkOperatorGas(ctx context.Context) {
	if e.cfg.EthClient == nil || len(e.cfg.OperatorAddresses) == 0 {
		return
	}
	const ruleID = "operator_gas_low"
	threshold := e.cfg.OperatorGasMinWei

	lowCount := 0
	var details []string
	for _, addr := range e.cfg.OperatorAddresses {
		bal, err := e.cfg.EthClient.BalanceAt(ctx, addr, nil)
		if err != nil {
			slog.Warn("alert check: failed to get operator balance",
				"address", addr.Hex(), "error", err)
			continue
		}
		if bal.Cmp(threshold) < 0 {
			lowCount++
			details = append(details, fmt.Sprintf("%s: %s wei", addr.Hex(), bal.String()))
		}
	}

	if lowCount > 0 {
		sev := SeverityWarning
		if lowCount == len(e.cfg.OperatorAddresses) {
			sev = SeverityCritical
		}
		e.fireIfNew(ctx, ruleID, sev,
			"Operator gas balance low",
			fmt.Sprintf("%d/%d operators below threshold: %v", lowCount, len(e.cfg.OperatorAddresses), details))
	} else {
		e.autoResolve(ctx, ruleID)
	}
}

// checkProverFunds checks the SP1 requestor address balance.
func (e *Engine) checkProverFunds(ctx context.Context) {
	if e.cfg.EthClient == nil {
		return
	}
	const ruleID = "prover_funds_low"
	emptyAddr := common.Address{}
	if e.cfg.SP1RequestorAddress == emptyAddr {
		return
	}

	bal, err := e.cfg.EthClient.BalanceAt(ctx, e.cfg.SP1RequestorAddress, nil)
	if err != nil {
		slog.Warn("alert check: failed to get prover balance",
			"address", e.cfg.SP1RequestorAddress.Hex(), "error", err)
		return
	}

	if bal.Cmp(e.cfg.ProverFundsMinWei) < 0 {
		e.fireIfNew(ctx, ruleID, SeverityWarning,
			"Prover funds low",
			fmt.Sprintf("SP1 requestor %s balance: %s wei (threshold: %s)",
				e.cfg.SP1RequestorAddress.Hex(), bal.String(), e.cfg.ProverFundsMinWei.String()))
	} else {
		e.autoResolve(ctx, ruleID)
	}
}

// checkStuckDepositBatches looks for deposit jobs stuck in non-terminal states.
func (e *Engine) checkStuckDepositBatches(ctx context.Context) {
	const ruleID = "stuck_deposit_batch"
	minutes := e.cfg.StuckBatchMinutes

	// deposit_jobs: terminal state is 6 (StateFinalized). There is no explicit "failed" state.
	var count int
	err := e.cfg.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM deposit_jobs
		WHERE state < 6
		  AND updated_at < now() - make_interval(mins := $1)`,
		minutes,
	).Scan(&count)
	if err != nil {
		slog.Warn("alert check: stuck deposit query failed", "error", err)
		return
	}

	if count > 0 {
		e.fireIfNew(ctx, ruleID, SeverityWarning,
			"Stuck deposit jobs detected",
			fmt.Sprintf("%d deposit jobs not finalized and idle for >%d minutes", count, minutes))
	} else {
		e.autoResolve(ctx, ruleID)
	}
}

func withdrawalBatchStateIsStuck(state int16) bool {
	return state < 8
}

// checkStuckWithdrawalBatches looks for withdrawal batches stuck in non-terminal states.
func (e *Engine) checkStuckWithdrawalBatches(ctx context.Context) {
	const ruleID = "stuck_withdrawal_batch"
	minutes := e.cfg.StuckBatchMinutes

	// Keep this aligned with the backoffice stuck-batches view: every state
	// below finalized is considered unresolved and alertable.
	var count int
	rows, err := e.cfg.Pool.Query(ctx, `
		SELECT state
		FROM withdrawal_batches
		WHERE updated_at < now() - make_interval(mins := $1)`,
		minutes)
	if err != nil {
		slog.Warn("alert check: stuck withdrawal query failed", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var state int16
		if err := rows.Scan(&state); err != nil {
			slog.Warn("alert check: stuck withdrawal scan failed", "error", err)
			return
		}
		if withdrawalBatchStateIsStuck(state) {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("alert check: stuck withdrawal rows failed", "error", err)
		return
	}

	if count > 0 {
		e.fireIfNew(ctx, ruleID, SeverityWarning,
			"Stuck withdrawal batches detected",
			fmt.Sprintf("%d withdrawal batches not finalized and idle for >%d minutes", count, minutes))
	} else {
		e.autoResolve(ctx, ruleID)
	}
}

// checkDLQ inspects the dead-letter queue for unacknowledged entries.
func (e *Engine) checkDLQ(ctx context.Context) {
	if e.cfg.DLQStore == nil {
		return
	}
	const ruleID = "dlq_high"

	counts, err := e.cfg.DLQStore.CountUnacknowledged(ctx)
	if err != nil {
		slog.Warn("alert check: DLQ count failed", "error", err)
		return
	}
	total := counts.Proofs + counts.DepositBatches + counts.WithdrawalBatches

	if total > 0 {
		sev := SeverityWarning
		if total > 10 {
			sev = SeverityCritical
		}
		e.fireIfNew(ctx, ruleID, sev,
			"Dead-letter queue has unacknowledged items",
			fmt.Sprintf("proofs=%d deposit_batches=%d withdrawal_batches=%d total=%d",
				counts.Proofs, counts.DepositBatches, counts.WithdrawalBatches, total))
	} else {
		e.autoResolve(ctx, ruleID)
	}
}

// checkServiceHealth pings each configured service URL.
func (e *Engine) checkServiceHealth(ctx context.Context) {
	for _, url := range e.cfg.ServiceURLs {
		ruleID := "service_unhealthy:" + url
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			slog.Warn("alert check: bad service URL", "url", url, "error", err)
			continue
		}
		resp, err := e.httpClient.Do(req)
		if err != nil {
			e.fireIfNew(ctx, ruleID, SeverityWarning,
				"Service unreachable",
				fmt.Sprintf("GET %s failed: %v", url, err))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			e.fireIfNew(ctx, ruleID, SeverityWarning,
				"Service unhealthy",
				fmt.Sprintf("GET %s returned %d", url, resp.StatusCode))
		} else {
			e.autoResolve(ctx, ruleID)
		}
	}
}

// fireIfNew inserts an alert only if there is no active (unresolved) alert
// with the same ruleID, providing deduplication.
func (e *Engine) fireIfNew(ctx context.Context, ruleID string, sev Severity, title, detail string) {
	exists, err := e.store.HasActiveAlert(ctx, ruleID)
	if err != nil {
		slog.Warn("alert check: dedup lookup failed", "rule", ruleID, "error", err)
		return
	}
	if exists {
		return
	}
	a := Alert{
		RuleID:   ruleID,
		Severity: sev,
		Title:    title,
		Detail:   detail,
		FiredAt:  time.Now().UTC(),
	}
	id, err := e.store.InsertAlert(ctx, a)
	if err != nil {
		slog.Error("alert check: insert failed", "rule", ruleID, "error", err)
		return
	}
	slog.Warn("alert fired", "id", id, "rule", ruleID, "severity", sev, "title", title)
}

// autoResolve resolves all active alerts for the given ruleID.
func (e *Engine) autoResolve(ctx context.Context, ruleID string) {
	if err := e.store.ResolveAlert(ctx, ruleID); err != nil {
		slog.Warn("alert check: auto-resolve failed", "rule", ruleID, "error", err)
	}
}
