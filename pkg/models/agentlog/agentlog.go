package agentlog

import "time"

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
