package withdrawcoordinator

import (
	"fmt"

	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
)

type RuntimeSettingsProvider interface {
	Current() (runtimeconfig.Settings, error)
}

func currentWithdrawPlannerMinConfirmations(provider RuntimeSettingsProvider, fallback int64) (int64, error) {
	if provider == nil {
		if fallback <= 0 {
			return 0, fmt.Errorf("%w: planner min confirmations must be > 0", ErrInvalidJunoRuntimeConfig)
		}
		return fallback, nil
	}
	settings, err := provider.Current()
	if err != nil {
		return 0, err
	}
	if settings.WithdrawPlannerMinConfirmations <= 0 {
		return 0, fmt.Errorf("%w: planner min confirmations must be > 0", ErrInvalidJunoRuntimeConfig)
	}
	return settings.WithdrawPlannerMinConfirmations, nil
}

func currentWithdrawBatchConfirmations(provider RuntimeSettingsProvider, fallback int64) (int64, error) {
	if provider == nil {
		if fallback <= 0 {
			return 0, fmt.Errorf("%w: withdraw batch confirmations must be > 0", ErrInvalidJunoRuntimeConfig)
		}
		return fallback, nil
	}
	settings, err := provider.Current()
	if err != nil {
		return 0, err
	}
	if settings.WithdrawBatchConfirmations <= 0 {
		return 0, fmt.Errorf("%w: withdraw batch confirmations must be > 0", ErrInvalidJunoRuntimeConfig)
	}
	return settings.WithdrawBatchConfirmations, nil
}
