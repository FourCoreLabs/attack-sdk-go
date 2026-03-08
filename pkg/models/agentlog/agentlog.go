package agentlog

import (
	"encoding/json"
	"time"
)

// AgentLog represents a log entry from an agent
type AgentLog struct {
	ID        string                 `json:"id" db:"id"`
	AssetID   string                 `json:"asset_id" db:"asset_id"`
	Hostname  string                 `json:"hostname" db:"hostname"`
	Action    string                 `json:"action" db:"action"`
	Message   string                 `json:"message" db:"message"`
	Data      map[string]interface{} `json:"data" db:"data"`
	OrgID     uint                   `json:"org_id" db:"org_id"`
	CreatedAt *time.Time             `json:"created_at,omitempty" db:"created_at"`
}

type AgentLogSummary struct {
	Time     string `json:"time"`
	AssetID  string `json:"asset_id"`
	Hostname string `json:"hostname"`
	Action   string `json:"action"`
	Message  string `json:"message"`
	Data     string `json:"data"`
}

type AgentLogExpanded AgentLog

func (a AgentLogExpanded) Summary() (any, error) {
	timeStr := "N/A"
	if a.CreatedAt != nil {
		timeStr = a.CreatedAt.Format(time.RFC3339)
	}

	message := a.Message
	if len(message) > 50 {
		message = message[:47] + "..."
	}

	dataStr := ""
	if a.Data != nil {
		b, err := json.Marshal(a.Data)
		if err != nil {
			return nil, err
		}
		dataStr = string(b)
	}

	return AgentLogSummary{
		Time:     timeStr,
		AssetID:  a.AssetID,
		Hostname: a.Hostname,
		Action:   a.Action,
		Message:  message,
		Data:     dataStr,
	}, nil
}
