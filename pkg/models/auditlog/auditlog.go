package auditlog

import (
	"fmt"
	"strconv"
	"time"
)

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

type AuditLogSummary struct {
	Time         string `json:"time"`
	SourceIP     string `json:"source_ip"`
	Actor        string `json:"actor"`
	Action       string `json:"action"`
	Endpoint     string `json:"endpoint"`
	Organization string `json:"organization"`
}

type AuditLogExpanded AuditLog

func (a AuditLogExpanded) Summary() (any, error) {
	timeStr := "N/A"
	if a.CreatedAt != nil {
		timeStr = a.CreatedAt.Format(time.RFC3339)
	}

	actor := a.Actor.Email
	if actor == "" {
		actor = maskAuditActor(a.Actor.ApiKey)
	}
	if actor == "" {
		actor = "System/Unknown"
	}

	return AuditLogSummary{
		Time:         timeStr,
		SourceIP:     a.SourceIP,
		Actor:        actor,
		Action:       a.Action,
		Endpoint:     a.Endpoint,
		Organization: a.OrgName + " (" + strconv.FormatUint(uint64(a.OrgID), 10) + ")",
	}, nil
}

func maskAuditActor(value string) string {
	if len(value) <= 6 {
		return value
	}
	return fmt.Sprintf("%s***%s", value[:3], value[len(value)-3:])
}
