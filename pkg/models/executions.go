package models

import (
	"database/sql"
	"time"
)

// SimulationReport is a combined-listing row for a simulation, playbook, exposure,
// emerging threat, MITRE or ad-hoc run. RunID identifies the appropriate report;
// it is not necessarily an individual execution ID.
type SimulationReport struct {
	GroupType          string                       `json:"group_type"`
	ExecutionType      []string                     `json:"execution_type"`
	RunID              string                       `json:"run_id"`
	Name               string                       `json:"name"`
	AssetCount         int                          `json:"asset_count"`
	ReportCategory     string                       `json:"report_category"`
	BehaviourAnalytics SimulationBehaviourAnalytics `json:"behaviour_analytics"`
	UserID             uint                         `json:"user_id"`
	Username           string                       `json:"username"`
	OrgID              uint                         `json:"org_id"`
	OrgName            string                       `json:"org_name"`
	Hostnames          []Hostname                   `json:"hostname"`
	Status             string                       `json:"status"`
	StatusState        string                       `json:"status_state"`
	TotalFinished      int                          `json:"total_finished"`
	TotalAttacks       int                          `json:"total_attacks"`
	TotalSuccess       int                          `json:"total_success"`
	TotalDetected      int                          `json:"total_detected"`
	CreatedAt          *time.Time                   `json:"created_at"`
	UpdatedAt          *time.Time                   `json:"updated_at"`
	ScheduleJobID      sql.NullString               `json:"schedule_job_id"`
	ScheduleID         sql.NullString               `json:"schedule_id"`
	Deprecated         bool                         `json:"deprecated"`
	Tags               Tag                          `json:"tags"`
}

// SimulationBehaviourAnalytics contains the run's normalized behavior outcomes.
type SimulationBehaviourAnalytics struct {
	Behaviours []SimulationBehaviour `json:"behaviours"`
}

// SimulationBehaviour describes the outcome of one executed behavior.
type SimulationBehaviour struct {
	Name          string `json:"name"`
	ID            string `json:"id"`
	Type          string `json:"type"`
	Severity      string `json:"severity"`
	Success       int    `json:"success"`
	Detected      int    `json:"detected"`
	Finished      int    `json:"finished"`
	Total         int    `json:"total"`
	UseLink       bool   `json:"use_link"`
	UseAttachment bool   `json:"use_attachment"`
	ExecutionType string `json:"execution_type"`
	PayloadType   string `json:"payload_type"`
}

// ExecutionStepSummary aggregates one report step across assets.
type ExecutionStepSummary struct {
	ExecutionID            string      `json:"execution_id"`
	ExecutionType          string      `json:"execution_type"`
	Name                   string      `json:"name"`
	Description            string      `json:"description"`
	Virtual                bool        `json:"virtual"`
	ActionID               string      `json:"action_id"`
	AttackPayloadID        string      `json:"attack_payload_id"`
	AttackPayloadNames     []string    `json:"attack_payload_names"`
	EmergingThreatAttackID string      `json:"emerging_threat_attack_id"`
	Severity               string      `json:"severity"`
	StageName              string      `json:"stage_name"`
	DetectedAssets         int         `json:"detected_assets"`
	DoneAssets             int         `json:"done_assets"`
	SuccessAssets          int         `json:"success_assets"`
	TotalAssets            int         `json:"total_assets"`
	Assets                 []StepAsset `json:"assets"`
	IsStager               bool        `json:"is_stager"`
	StagerID               *string     `json:"stager_id"`
	StagerMode             string      `json:"mode_used"`
	StagerModeDescription  string      `json:"mode_description"`
	UseAttachment          bool        `json:"use_attachment"`
	UseLink                bool        `json:"use_link"`
	CreatedAt              *time.Time  `json:"created_at"`
	UpdatedAt              *time.Time  `json:"updated_at"`
}

// StepAsset contains asset metadata and execution details for a summarized step.
type StepAsset = AssetExecutionDetails
