package alerts

import "time"

// Severity represents the urgency level of an alert.
type Severity string

const (
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert represents a single alert record persisted in backoffice_alerts.
type Alert struct {
	ID             int64      `json:"id"`
	RuleID         string     `json:"rule_id"`
	Severity       Severity   `json:"severity"`
	Title          string     `json:"title"`
	Detail         string     `json:"detail"`
	FiredAt        time.Time  `json:"fired_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
}
