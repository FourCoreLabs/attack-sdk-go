package auditlog

import "time"

type AuditLogTarget map[string]interface{}

type AuditLog struct {
	CreatedAt *time.Time     `json:"created_at,omitempty" db:"created_at"`
	ID        string         `json:"id" db:"id"`
	OrgID     uint           `json:"org_id" db:"org_id"`
	OrgName   string         `json:"org_name" db:"org_name"`
	SourceIP  string         `json:"source_ip" db:"source_ip"`
	Endpoint  string         `json:"endpoint" db:"endpoint"`
	Action    string         `json:"action" db:"action"`
	Actor     AuditLogActor  `json:"actor" db:"actor"`
	Target    AuditLogTarget `json:"target,omitempty" db:"target"`
}

type AuditLogActor struct {
	ApiKey string `json:"api_key,omitempty" db:"api_key"`
	Email  string `json:"email,omitempty" db:"email"`
}
