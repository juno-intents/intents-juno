package backoffice

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
)

type stubRuntimeSettingsStore struct {
	mu       sync.Mutex
	settings runtimeconfig.Settings
}

func (s *stubRuntimeSettingsStore) Get(context.Context) (runtimeconfig.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings, nil
}

func (s *stubRuntimeSettingsStore) Update(_ context.Context, settings runtimeconfig.Settings, updatedBy string) (runtimeconfig.Settings, error) {
	settings.UpdatedBy = updatedBy
	if err := settings.Validate(); err != nil {
		return runtimeconfig.Settings{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	settings.UpdatedAt = time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
	s.settings = settings
	return s.settings, nil
}

type stubBackofficeBridgeSettings struct {
	mu       sync.Mutex
	snapshot bridgeconfig.Snapshot
}

func (s *stubBackofficeBridgeSettings) Current() (bridgeconfig.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, nil
}

func (s *stubBackofficeBridgeSettings) setMinDepositAmount(amount uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.MinDepositAmount = amount
}

type stubMinDepositUpdater struct {
	txHash  common.Hash
	bridge  *stubBackofficeBridgeSettings
	lastSet uint64
}

func (s *stubMinDepositUpdater) SetMinDepositAmount(_ context.Context, amount uint64) (common.Hash, error) {
	s.lastSet = amount
	if s.bridge != nil {
		s.bridge.setMinDepositAmount(amount)
	}
	return s.txHash, nil
}

func newSettingsTestServer(runtimeStore RuntimeSettingsStore, bridgeSettings BridgeSettingsProvider, updater MinDepositUpdater) *Server {
	return &Server{
		cfg: ServerConfig{
			RuntimeStore:      runtimeStore,
			BridgeSettings:    bridgeSettings,
			MinDepositUpdater: updater,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestHandleRuntimeSettingsReturnsRuntimeAndBridgeState(t *testing.T) {
	t.Parallel()

	runtimeStore := &stubRuntimeSettingsStore{
		settings: runtimeconfig.Settings{
			DepositMinConfirmations:         2,
			WithdrawPlannerMinConfirmations: 3,
			WithdrawBatchConfirmations:      4,
			UpdatedBy:                       "seed",
			UpdatedAt:                       time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		},
	}
	bridgeSettings := &stubBackofficeBridgeSettings{
		snapshot: bridgeconfig.Snapshot{
			MinDepositAmount: 201005025,
			MinDepositAdmin:  common.HexToAddress("0x0000000000000000000000000000000000000abc"),
			LoadedAt:         time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		},
	}
	s := newSettingsTestServer(runtimeStore, bridgeSettings, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings/runtime", nil)
	s.handleRuntimeSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data struct {
			DepositMinConfirmations         int64  `json:"depositMinConfirmations"`
			WithdrawPlannerMinConfirmations int64  `json:"withdrawPlannerMinConfirmations"`
			WithdrawBatchConfirmations      int64  `json:"withdrawBatchConfirmations"`
			MinDepositAmount                string `json:"minDepositAmount"`
			MinDepositAdmin                 string `json:"minDepositAdmin"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Data.DepositMinConfirmations != 2 {
		t.Fatalf("depositMinConfirmations = %d, want 2", body.Data.DepositMinConfirmations)
	}
	if body.Data.WithdrawPlannerMinConfirmations != 3 {
		t.Fatalf("withdrawPlannerMinConfirmations = %d, want 3", body.Data.WithdrawPlannerMinConfirmations)
	}
	if body.Data.WithdrawBatchConfirmations != 4 {
		t.Fatalf("withdrawBatchConfirmations = %d, want 4", body.Data.WithdrawBatchConfirmations)
	}
	if body.Data.MinDepositAmount != "201005025" {
		t.Fatalf("minDepositAmount = %q, want 201005025", body.Data.MinDepositAmount)
	}
	if body.Data.MinDepositAdmin != "0x0000000000000000000000000000000000000aBc" && body.Data.MinDepositAdmin != "0x0000000000000000000000000000000000000abc" {
		t.Fatalf("minDepositAdmin = %q", body.Data.MinDepositAdmin)
	}
}

func TestHandleUpdateRuntimeSettingsPersistsNewValues(t *testing.T) {
	t.Parallel()

	runtimeStore := &stubRuntimeSettingsStore{
		settings: runtimeconfig.Settings{
			DepositMinConfirmations:         1,
			WithdrawPlannerMinConfirmations: 1,
			WithdrawBatchConfirmations:      1,
			UpdatedBy:                       "seed",
			UpdatedAt:                       time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		},
	}
	bridgeSettings := &stubBackofficeBridgeSettings{
		snapshot: bridgeconfig.Snapshot{
			MinDepositAmount: 201005025,
			MinDepositAdmin:  common.HexToAddress("0x0000000000000000000000000000000000000abc"),
		},
	}
	s := newSettingsTestServer(runtimeStore, bridgeSettings, nil)

	body := bytes.NewBufferString(`{"depositMinConfirmations":5,"withdrawPlannerMinConfirmations":6,"withdrawBatchConfirmations":7,"updatedBy":"ops"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings/runtime", body)
	s.handleUpdateRuntimeSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	got, err := runtimeStore.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DepositMinConfirmations != 5 || got.WithdrawPlannerMinConfirmations != 6 || got.WithdrawBatchConfirmations != 7 {
		t.Fatalf("unexpected settings: %+v", got)
	}
	if got.UpdatedBy != "ops" {
		t.Fatalf("updatedBy = %q, want ops", got.UpdatedBy)
	}
}

func TestHandleUpdateRuntimeSettingsRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	runtimeStore := &stubRuntimeSettingsStore{
		settings: runtimeconfig.Settings{
			DepositMinConfirmations:         1,
			WithdrawPlannerMinConfirmations: 1,
			WithdrawBatchConfirmations:      1,
			UpdatedBy:                       "seed",
			UpdatedAt:                       time.Now().UTC(),
		},
	}
	bridgeSettings := &stubBackofficeBridgeSettings{
		snapshot: bridgeconfig.Snapshot{
			MinDepositAmount: 201005025,
			MinDepositAdmin:  common.HexToAddress("0x0000000000000000000000000000000000000abc"),
		},
	}
	s := newSettingsTestServer(runtimeStore, bridgeSettings, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings/runtime", bytes.NewBufferString(`{"depositMinConfirmations":0,"withdrawPlannerMinConfirmations":1,"withdrawBatchConfirmations":1}`))
	s.handleUpdateRuntimeSettings(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleSetMinDepositUpdatesBridgeAndReturnsTxHash(t *testing.T) {
	t.Parallel()

	bridgeSettings := &stubBackofficeBridgeSettings{
		snapshot: bridgeconfig.Snapshot{
			MinDepositAmount: 201005025,
			MinDepositAdmin:  common.HexToAddress("0x0000000000000000000000000000000000000abc"),
		},
	}
	updater := &stubMinDepositUpdater{
		txHash: common.HexToHash("0x1234"),
		bridge: bridgeSettings,
	}
	s := newSettingsTestServer(&stubRuntimeSettingsStore{
		settings: runtimeconfig.Settings{
			DepositMinConfirmations:         1,
			WithdrawPlannerMinConfirmations: 1,
			WithdrawBatchConfirmations:      1,
			UpdatedBy:                       "seed",
			UpdatedAt:                       time.Now().UTC(),
		},
	}, bridgeSettings, updater)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/settings/min-deposit", bytes.NewBufferString(`{"minDepositAmount":"333","updatedBy":"ops"}`))
	s.handleSetMinDeposit(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if updater.lastSet != 333 {
		t.Fatalf("lastSet = %d, want 333", updater.lastSet)
	}

	var body struct {
		Data struct {
			MinDepositAmount string `json:"minDepositAmount"`
			TxHash           string `json:"txHash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Data.MinDepositAmount != "333" {
		t.Fatalf("minDepositAmount = %q, want 333", body.Data.MinDepositAmount)
	}
	if body.Data.TxHash != updater.txHash.Hex() {
		t.Fatalf("txHash = %q, want %q", body.Data.TxHash, updater.txHash.Hex())
	}
}
