package backoffice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
)

type runtimeSettingsUpdateRequest struct {
	DepositMinConfirmations         int64  `json:"depositMinConfirmations"`
	WithdrawPlannerMinConfirmations int64  `json:"withdrawPlannerMinConfirmations"`
	WithdrawBatchConfirmations      int64  `json:"withdrawBatchConfirmations"`
	UpdatedBy                       string `json:"updatedBy"`
}

type minDepositUpdateRequest struct {
	MinDepositAmount string `json:"minDepositAmount"`
	UpdatedBy        string `json:"updatedBy"`
}

func (s *Server) handleRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RuntimeStore == nil || s.cfg.BridgeSettings == nil {
		writeError(w, http.StatusNotImplemented, "settings_not_available")
		return
	}

	settings, err := s.cfg.RuntimeStore.Get(r.Context())
	if err != nil {
		s.log.Error("get runtime settings", "err", err)
		writeError(w, http.StatusServiceUnavailable, "runtime_settings_not_ready")
		return
	}
	bridgeSnapshot, err := s.cfg.BridgeSettings.Current()
	if err != nil {
		s.log.Error("get bridge settings", "err", err)
		writeError(w, http.StatusServiceUnavailable, "bridge_settings_not_ready")
		return
	}

	resp := map[string]any{
		"version": "v1",
		"data":    runtimeSettingsResponse(settings, bridgeSnapshot),
	}
	if s.cfg.SettingsAudit != nil {
		audit, err := s.cfg.SettingsAudit.List(r.Context(), 20)
		if err != nil {
			s.log.Error("list settings audit", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		resp["audit"] = settingsAuditResponse(audit)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RuntimeStore == nil {
		writeError(w, http.StatusNotImplemented, "settings_not_available")
		return
	}

	var req runtimeSettingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	current, err := s.cfg.RuntimeStore.Get(r.Context())
	if err != nil {
		s.log.Error("get runtime settings before update", "err", err)
		writeError(w, http.StatusServiceUnavailable, "runtime_settings_not_ready")
		return
	}

	updatedBy := normalizeUpdatedBy(req.UpdatedBy)
	updated, err := s.cfg.RuntimeStore.Update(r.Context(), runtimeconfig.Settings{
		DepositMinConfirmations:         req.DepositMinConfirmations,
		WithdrawPlannerMinConfirmations: req.WithdrawPlannerMinConfirmations,
		WithdrawBatchConfirmations:      req.WithdrawBatchConfirmations,
	}, updatedBy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_settings")
		return
	}

	if s.cfg.SettingsAudit != nil {
		auditCtx := r.Context()
		entries := []SettingsAuditEntry{
			{
				SettingKey: "deposit_min_confirmations",
				OldValue:   strconv.FormatInt(current.DepositMinConfirmations, 10),
				NewValue:   strconv.FormatInt(updated.DepositMinConfirmations, 10),
				UpdatedBy:  updatedBy,
			},
			{
				SettingKey: "withdraw_planner_min_confirmations",
				OldValue:   strconv.FormatInt(current.WithdrawPlannerMinConfirmations, 10),
				NewValue:   strconv.FormatInt(updated.WithdrawPlannerMinConfirmations, 10),
				UpdatedBy:  updatedBy,
			},
			{
				SettingKey: "withdraw_batch_confirmations",
				OldValue:   strconv.FormatInt(current.WithdrawBatchConfirmations, 10),
				NewValue:   strconv.FormatInt(updated.WithdrawBatchConfirmations, 10),
				UpdatedBy:  updatedBy,
			},
		}
		for _, entry := range entries {
			if entry.OldValue == entry.NewValue {
				continue
			}
			if err := s.cfg.SettingsAudit.Insert(auditCtx, entry); err != nil {
				s.log.Error("insert runtime settings audit", "err", err)
				writeError(w, http.StatusInternalServerError, "internal")
				return
			}
		}
	}

	bridgeSnapshot, err := s.currentBridgeSettings(r.Context())
	if err != nil {
		s.log.Error("get bridge settings after runtime update", "err", err)
		writeError(w, http.StatusServiceUnavailable, "bridge_settings_not_ready")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    runtimeSettingsResponse(updated, bridgeSnapshot),
	})
}

func (s *Server) handleSettingsAudit(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SettingsAudit == nil {
		writeError(w, http.StatusNotImplemented, "settings_audit_not_available")
		return
	}

	limit := parseIntParam(r, "limit", 20)
	if limit > 200 {
		limit = 200
	}
	entries, err := s.cfg.SettingsAudit.List(r.Context(), limit)
	if err != nil {
		s.log.Error("list settings audit", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data":    settingsAuditResponse(entries),
	})
}

func (s *Server) handleSetMinDeposit(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MinDepositUpdater == nil || s.cfg.BridgeSettings == nil {
		writeError(w, http.StatusNotImplemented, "min_deposit_update_not_available")
		return
	}

	var req minDepositUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.MinDepositAmount = strings.TrimSpace(req.MinDepositAmount)
	if req.MinDepositAmount == "" {
		writeError(w, http.StatusBadRequest, "missing_min_deposit_amount")
		return
	}
	amount, err := strconv.ParseUint(req.MinDepositAmount, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_min_deposit_amount")
		return
	}

	before, err := s.currentBridgeSettings(r.Context())
	if err != nil {
		s.log.Error("get bridge settings before min deposit update", "err", err)
		writeError(w, http.StatusServiceUnavailable, "bridge_settings_not_ready")
		return
	}

	txHash, err := s.cfg.MinDepositUpdater.SetMinDepositAmount(r.Context(), amount)
	if err != nil {
		s.log.Error("set min deposit amount", "err", err)
		writeError(w, http.StatusBadGateway, "min_deposit_update_failed")
		return
	}

	after, err := s.waitForMinDepositAmount(r.Context(), amount)
	if err != nil {
		s.log.Warn("bridge settings cache did not refresh to new min deposit yet", "err", err, "amount", amount)
		after = before
		after.MinDepositAmount = amount
	}

	updatedBy := normalizeUpdatedBy(req.UpdatedBy)
	if s.cfg.SettingsAudit != nil {
		if err := s.cfg.SettingsAudit.Insert(r.Context(), SettingsAuditEntry{
			SettingKey: "min_deposit_amount",
			OldValue:   strconv.FormatUint(before.MinDepositAmount, 10),
			NewValue:   strconv.FormatUint(after.MinDepositAmount, 10),
			TxHash:     txHash.Hex(),
			UpdatedBy:  updatedBy,
		}); err != nil {
			s.log.Error("insert min deposit audit", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": "v1",
		"data": map[string]any{
			"minDepositAmount": strconv.FormatUint(after.MinDepositAmount, 10),
			"minDepositAdmin":  after.MinDepositAdmin.Hex(),
			"txHash":           txHash.Hex(),
		},
	})
}

func (s *Server) currentBridgeSettings(ctx context.Context) (bridgeconfig.Snapshot, error) {
	if s.cfg.BridgeSettings == nil {
		return bridgeconfig.Snapshot{}, fmt.Errorf("%w: missing bridge settings provider", ErrInvalidSettingsConfig)
	}
	snapshot, err := s.cfg.BridgeSettings.Current()
	if err != nil {
		return bridgeconfig.Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Server) waitForMinDepositAmount(ctx context.Context, amount uint64) (bridgeconfig.Snapshot, error) {
	deadline := time.Now().Add(12 * time.Second)
	for {
		snapshot, err := s.currentBridgeSettings(ctx)
		if err == nil && snapshot.MinDepositAmount == amount {
			return snapshot, nil
		}
		if !time.Now().Before(deadline) {
			if err == nil {
				return snapshot, fmt.Errorf("min deposit cache still at %d", snapshot.MinDepositAmount)
			}
			return bridgeconfig.Snapshot{}, err
		}
		select {
		case <-ctx.Done():
			return bridgeconfig.Snapshot{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func runtimeSettingsResponse(settings runtimeconfig.Settings, bridgeSnapshot bridgeconfig.Snapshot) map[string]any {
	return map[string]any{
		"depositMinConfirmations":         settings.DepositMinConfirmations,
		"withdrawPlannerMinConfirmations": settings.WithdrawPlannerMinConfirmations,
		"withdrawBatchConfirmations":      settings.WithdrawBatchConfirmations,
		"updatedBy":                       settings.UpdatedBy,
		"updatedAt":                       settings.UpdatedAt.UTC().Format(time.RFC3339),
		"minDepositAmount":                strconv.FormatUint(bridgeSnapshot.MinDepositAmount, 10),
		"minDepositAdmin":                 bridgeSnapshot.MinDepositAdmin.Hex(),
	}
}

func settingsAuditResponse(entries []SettingsAuditEntry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, map[string]any{
			"id":         entry.ID,
			"settingKey": entry.SettingKey,
			"oldValue":   entry.OldValue,
			"newValue":   entry.NewValue,
			"txHash":     entry.TxHash,
			"updatedBy":  entry.UpdatedBy,
			"updatedAt":  entry.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func normalizeUpdatedBy(updatedBy string) string {
	updatedBy = strings.TrimSpace(updatedBy)
	if updatedBy == "" {
		return "backoffice"
	}
	return updatedBy
}
