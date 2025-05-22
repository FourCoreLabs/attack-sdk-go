package models

import "time"

type OrderBy struct {
	Name string
	Asc  bool // default to desc (asc false)
}

type FilterBy struct {
	Name  string
	Value []string
}

type Pagination struct {
	Offset      uint64     `json:"offset" example:"1" description:"set offset"`
	Size        uint64     `json:"size"`
	OrderQuery  []OrderBy  `json:"order"`
	FilterQuery []FilterBy `json:"-"`
}

type PaginationResponse[Data any] struct {
	Pagination
	TotalRows int    `json:"total_rows" example:"50"`
	Data      []Data `json:"data"`
}

// ListWithCount represents a generic list response with count
type ListWithCount struct {
	Count int           `json:"count"`
	Data  []interface{} `json:"data"`
}

// SuccessIDResponse represents a success response with an ID
type SuccessIDResponse struct {
	Success bool        `json:"success"`
	ID      interface{} `json:"id"`
}

// PackRun represents a pack execution
type PackRun struct {
	ID          string      `json:"id"`
	PackID      string      `json:"pack_id"`
	OrgID       uint        `json:"org_id"`
	UserID      uint        `json:"user_id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Status      string      `json:"status"`
	StatusState string      `json:"status_state"`
	Total       int         `json:"total"`
	Success     int         `json:"success"`
	Detected    int         `json:"detected"`
	OrgName     string      `json:"org_name,omitempty"`
	Username    string      `json:"username,omitempty"`
	Assets      []string    `json:"assets"`
	Hostname    []HostInfo  `json:"hostname"`
	Executions  []Execution `json:"executions,omitempty"`
	CreatedAt   *string     `json:"created_at,omitempty"`
	UpdatedAt   *string     `json:"updated_at,omitempty"`
}

// HostInfo represents host information
type HostInfo struct {
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	IPAddr  string `json:"ipaddr"`
	OS      string `json:"os"`
}

// Execution represents an execution entry
type Execution struct {
	ID            string     `json:"id"`
	AttackName    string     `json:"attack_name"`
	Description   string     `json:"description"`
	Status        string     `json:"status"`
	Progress      float64    `json:"progress"`
	Detected      float64    `json:"detected"`
	AssetCount    int        `json:"asset_count"`
	StepIdx       int        `json:"step_idx"`
	OrgName       string     `json:"org_name"`
	Username      string     `json:"username"`
	Hostname      []HostInfo `json:"hostname"`
	ExecutionType string     `json:"execution_type"`
	TotalAttacks  int        `json:"total_attacks"`
	TotalFinished int        `json:"total_finished"`
	TotalSuccess  int        `json:"total_success"`
	TotalDetected int        `json:"total_detected"`
	CreatedAt     string     `json:"created_at"`
	UpdatedAt     string     `json:"updated_at"`
}

// AttackRun represents the request body for executing an attack chain.
type AttackRun struct {
	Assets         []string `json:"assets,omitempty"`
	DisableCleanup *bool    `json:"disable_cleanup,omitempty"`
	EmailAssets    []string `json:"email_assets,omitempty"`
	RunElevated    *bool    `json:"run_elevated,omitempty"`
	WafAssets      []string `json:"waf_assets,omitempty"`
}

// GetExecutionResponse represents the response body for getting an execution report.
type GetExecutionResponse struct {
	ActionIDs     []string                `json:"action_ids,omitempty"`
	AptID         string                  `json:"apt_id,omitempty"` // Assuming simple string for now based on usage
	AssetCount    int                     `json:"asset_count,omitempty"`
	AssetEDRs     []string                `json:"asset_edrs,omitempty"`
	Assets        []AssetExecutionDetails `json:"assets,omitempty"` // Need to define AssetExecutionDetails
	Attack        *Attack                 `json:"attack,omitempty"` // Need to define Attack
	AttackID      int                     `json:"attack_id,omitempty"`
	AttackName    string                  `json:"attack_name,omitempty"`
	C2Profile     string                  `json:"c2_profile,omitempty"`
	C2Type        string                  `json:"c2_type,omitempty"`
	ChainID       string                  `json:"chain_id,omitempty"`
	CreatedAt     *time.Time              `json:"created_at,omitempty"`
	DeletedAt     *time.Time              `json:"deleted_at,omitempty"`
	Detected      float64                 `json:"detected,omitempty"`
	Events        []Event                 `json:"events,omitempty"` // Need to define Event
	ExecutionType string                  `json:"execution_type,omitempty"`
	Hostname      []Hostname              `json:"hostname,omitempty"` // Need to define Hostname
	ID            string                  `json:"id,omitempty"`
	Integrations  []string                `json:"integrations,omitempty"`
	MalwareIDs    []string                `json:"malware_ids,omitempty"`
	OrgID         int                     `json:"org_id,omitempty"`
	OrgName       *string                 `json:"org_name,omitempty"`
	Progress      float64                 `json:"progress,omitempty"`
	RunElevated   bool                    `json:"run_elevated,omitempty"`
	Score         float64                 `json:"score,omitempty"`
	StagerID      *string                 `json:"stager_id,omitempty"`
	StagerMode    *string                 `json:"stager_mode,omitempty"`
	Statistics    *Statistics             `json:"statistics,omitempty"` // Need to define Statistics
	Status        string                  `json:"status,omitempty"`
	StatusState   string                  `json:"status_state,omitempty"`
	TotalAttacks  int                     `json:"total_attacks,omitempty"`
	TotalDetected int                     `json:"total_detected,omitempty"`
	TotalFinished int                     `json:"total_finished,omitempty"`
	TotalSuccess  int                     `json:"total_success,omitempty"`
	UpdatedAt     *time.Time              `json:"updated_at,omitempty"`
	UserID        int                     `json:"user_id,omitempty"`
	Username      *string                 `json:"username,omitempty"`
	Uses          string                  `json:"uses,omitempty"`
}

// AttackExecution represents the response body for executing email/waf attack chains.
type AttackExecution struct {
	ActionIDs        []string          `json:"action_ids,omitempty"`
	AptID            string            `json:"apt_id,omitempty"` // Assuming simple string for now
	AttackID         int               `json:"attack_id,omitempty"`
	AttackName       string            `json:"attack_name,omitempty"`   // Assuming simple string for now
	C2ExfilOnly      bool              `json:"c2_exfil_only,omitempty"` // Assuming simple bool for now
	C2Profile        string            `json:"c2_profile,omitempty"`    // Assuming simple string for now
	C2Type           string            `json:"c2_type,omitempty"`       // Assuming simple string for now
	ChainID          string            `json:"chain_id,omitempty"`
	CreatedAt        *time.Time        `json:"created_at,omitempty"`
	DeletedAt        *time.Time        `json:"deleted_at,omitempty"`
	DisableCleanup   bool              `json:"disable_cleanup,omitempty"` // Assuming simple bool for now
	EmailAssetIDs    []string          `json:"email_asset_ids,omitempty"`
	ExecutionType    string            `json:"execution_type,omitempty"`
	ExposureID       string            `json:"exposure_id,omitempty"`     // Assuming simple string for now
	ExposureRunID    string            `json:"exposure_run_id,omitempty"` // Assuming simple string for now
	FailError        interface{}       `json:"fail_error,omitempty"`
	ID               string            `json:"id,omitempty"`
	MalwareIDs       []string          `json:"malware_ids,omitempty"`
	OrgID            int               `json:"org_id,omitempty"`
	PackID           string            `json:"pack_id,omitempty"`     // Assuming simple string for now
	PackRunID        string            `json:"pack_run_id,omitempty"` // Assuming simple string for now
	Progress         float64           `json:"progress,omitempty"`
	RunElevated      bool              `json:"run_elevated,omitempty"`
	StagerID         string            `json:"stager_id,omitempty"`   // Assuming simple string for now
	StagerMode       string            `json:"stager_mode,omitempty"` // Assuming simple string for now
	Stagers          []StagerDetails   `json:"stagers,omitempty"`     // Need to define StagerDetails
	Status           string            `json:"status,omitempty"`
	TemporaryObjects []TemporaryObject `json:"temporary_objects,omitempty"` // Need to define TemporaryObject
	UpdatedAt        *time.Time        `json:"updated_at,omitempty"`
	UserID           int               `json:"user_id,omitempty"`
	Uses             string            `json:"uses,omitempty"`
	WafAssetIDs      []string          `json:"waf_asset_ids,omitempty"`
}

// Define nested structs as needed based on the OpenAPI spec

// AssetExecutionDetails represents details of an asset in an execution response.
type AssetExecutionDetails struct {
	Arch             string                          `json:"arch,omitempty"`
	AssetID          string                          `json:"asset_id,omitempty"`
	AssetType        string                          `json:"asset_type,omitempty"`
	Detected         float64                         `json:"detected,omitempty"`
	Edr              []EDR                           `json:"edr,omitempty"`          // Need to define EDR
	ExecuteUser      *User                           `json:"execute_user,omitempty"` // Need to define User
	FailError        interface{}                     `json:"fail_erorr,omitempty"`   // Note the typo in the spec: fail_erorr
	Hostname         string                          `json:"hostname,omitempty"`
	IPAddr           string                          `json:"ipaddr,omitempty"`
	PayloadConnected bool                            `json:"payload_connected,omitempty"`
	PcapObject       *S3Object                       `json:"pcap_object,omitempty"` // Need to define S3Object
	Platform         string                          `json:"platform,omitempty"`
	Progress         float64                         `json:"progress,omitempty"`
	RunElevated      bool                            `json:"run_elevated,omitempty"`
	Score            float64                         `json:"score,omitempty"`
	SeverityCount    map[string]int                  `json:"severity_count,omitempty"`
	Status           string                          `json:"status,omitempty"`
	Steps            []GetExecutionResponseAssetStep `json:"steps,omitempty"` // Need to define GetExecutionResponseAssetStep
	TotalAttacks     int                             `json:"total_attacks,omitempty"`
	TotalDetected    int                             `json:"total_detected,omitempty"`
	TotalFinished    int                             `json:"total_finished,omitempty"`
	TotalSuccess     int                             `json:"total_success,omitempty"`
}

// EDR represents EDR details.
type EDR struct {
	EdrType string `json:"edr_type,omitempty"`
}

// User represents user details.
type User struct {
	Groups      []string `json:"groups,omitempty"`
	HomeDir     string   `json:"home_dir,omitempty"`
	Interactive bool     `json:"interactive,omitempty"`
	Name        string   `json:"name,omitempty"`
	UID         string   `json:"uid,omitempty"`
	Username    string   `json:"username,omitempty"`
}

// S3Object represents an S3 object.
type S3Object struct {
	Bucket string `json:"bucket,omitempty"`
	Object string `json:"object,omitempty"`
	Valid  bool   `json:"valid,omitempty"`
}

// GetExecutionResponseAssetStep represents a step in an asset execution response.
type GetExecutionResponseAssetStep struct {
	RunElevated              bool                            `json:"RunElevated,omitempty"` // Note the capitalization in the spec
	ActionID                 string                          `json:"action_id,omitempty"`
	ActionSteps              []GetExecutionResponseAssetStep `json:"action_steps,omitempty"`
	Correlations             []Correlation                   `json:"correlations,omitempty"` // Need to define Correlation
	CreatedAt                *time.Time                      `json:"created_at,omitempty"`
	DeletedAt                *time.Time                      `json:"deleted_at,omitempty"`
	Description              string                          `json:"description,omitempty"`
	Detected                 *bool                           `json:"detected,omitempty"`
	Detection                string                          `json:"detection,omitempty"`
	Done                     *bool                           `json:"done,omitempty"`
	Events                   []Event                         `json:"events,omitempty"`
	ExecutionID              string                          `json:"execution_id,omitempty"`
	Files                    []S3Object                      `json:"files,omitempty"`
	ID                       int                             `json:"id,omitempty"`
	IOC                      []IOC                           `json:"ioc,omitempty"` // Need to define IOC
	IsStager                 bool                            `json:"is_stager,omitempty"`
	Logged                   *bool                           `json:"logged,omitempty"`
	Mitigation               string                          `json:"mitigation,omitempty"`
	Mitigations              []Mitigation                    `json:"mitigations,omitempty"` // Need to define Mitigation
	ModeDescription          string                          `json:"mode_description,omitempty"`
	ModeUsed                 string                          `json:"mode_used,omitempty"`
	Name                     string                          `json:"name,omitempty"`
	Output                   *Output                         `json:"output,omitempty"`         // Need to define Output
	Recommendation           []Recommendation                `json:"recommendation,omitempty"` // Need to define Recommendation
	Rules                    []Rule                          `json:"rules,omitempty"`          // Need to define Rule
	Severity                 string                          `json:"severity,omitempty"`
	StageName                string                          `json:"stage_name,omitempty"`
	StagerID                 *string                         `json:"stager_id,omitempty"`
	Success                  *bool                           `json:"success,omitempty"`
	UpdatedAt                *time.Time                      `json:"updated_at,omitempty"`
	UserModifiedDetectedDate *time.Time                      `json:"user_modified_detected_date,omitempty"`
	UserModifiedSuccessDate  *time.Time                      `json:"user_modified_success_date,omitempty"`
	Virtual                  bool                            `json:"virtual,omitempty"`
}

// Correlation represents correlation details.
type Correlation struct {
	CorrelationType          string      `json:"correlation_type,omitempty"`
	CreatedAt                *time.Time  `json:"created_at,omitempty"`
	Data                     interface{} `json:"data,omitempty"`
	DeletedAt                *time.Time  `json:"deleted_at,omitempty"`
	Description              string      `json:"description,omitempty"`
	DetectionTime            time.Time   `json:"detection_time,omitempty"`
	ID                       string      `json:"id,omitempty"`
	IntegrationEventUniqueID string      `json:"integration_event_unique_id,omitempty"`
	IntegrationID            string      `json:"integration_id,omitempty"` // Assuming simple string for now
	IntegrationType          string      `json:"integration_type,omitempty"`
	JobID                    string      `json:"job_id,omitempty"`
	Name                     string      `json:"name,omitempty"`
	Notes                    string      `json:"notes,omitempty"`
	Severity                 string      `json:"severity,omitempty"`
	Source                   string      `json:"source,omitempty"`
	StepID                   int         `json:"step_id,omitempty"`
	UpdatedAt                *time.Time  `json:"updated_at,omitempty"`
	URL                      string      `json:"url,omitempty"`
}

// Event represents an event.
type Event struct {
	AssetID         string    `json:"asset_id,omitempty"`
	Data            string    `json:"data,omitempty"`
	EventTime       time.Time `json:"event_time,omitempty"`
	ExecutionID     string    `json:"execution_id,omitempty"`
	Hostname        string    `json:"hostname,omitempty"`
	ID              int       `json:"id,omitempty"`
	JobID           string    `json:"job_id,omitempty"`
	StagerRequestID string    `json:"stager_request_id,omitempty"`
	Type            string    `json:"type,omitempty"`
}

// IOC represents Indicator of Compromise details.
type IOC struct {
	CreatedAt *time.Time  `json:"created_at,omitempty"`
	DeletedAt *time.Time  `json:"deleted_at,omitempty"`
	ID        string      `json:"id,omitempty"`
	IOC       interface{} `json:"ioc,omitempty"`
	IOCType   string      `json:"ioc_type,omitempty"`
	JobID     string      `json:"job_id,omitempty"`
	UpdatedAt *time.Time  `json:"updated_at,omitempty"`
}

// Mitigation represents mitigation details.
type Mitigation struct {
	ID          string `json:"ID,omitempty"` // Note the capitalization in the spec
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
}

// Output represents output details.
type Output struct {
	JobID  string      `json:"job_id,omitempty"`
	Output interface{} `json:"output,omitempty"`
	Time   time.Time   `json:"time,omitempty"`
}

// Recommendation represents recommendation details.
type Recommendation struct {
	Name  string `json:"name,omitempty"`
	Rules []Rule `json:"rules,omitempty"`
	Value string `json:"value,omitempty"`
}

// Rule represents rule details.
type Rule struct {
	Hash  *Hash  `json:"hash,omitempty"` // Need to define Hash
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// Hash represents hash details.
type Hash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// Attack represents attack details.
type Attack struct {
	Actions     []string               `json:"actions,omitempty"`
	CreatedAt   *time.Time             `json:"created_at,omitempty"`
	DeletedAt   *time.Time             `json:"deleted_at,omitempty"`
	Description string                 `json:"description,omitempty"`
	ID          int                    `json:"id,omitempty"`
	Malwares    []string               `json:"malwares,omitempty"`
	Name        string                 `json:"name,omitempty"`
	OrgID       int                    `json:"org_id,omitempty"`
	Platform    string                 `json:"platform,omitempty"`
	Platforms   []string               `json:"platforms,omitempty"`
	RunElevated bool                   `json:"run_elevated,omitempty"`
	StagerID    []StagerIDDetails      `json:"stager_id,omitempty"` // Need to define StagerIDDetails
	Tags        map[string]interface{} `json:"tags,omitempty"`
	Type        string                 `json:"type,omitempty"`
	UpdatedAt   *time.Time             `json:"updated_at,omitempty"`
	UserID      int                    `json:"user_id,omitempty"`
}

// StagerIDDetails represents stager ID details.
type StagerIDDetails struct {
	StagerID   string `json:"stager_id,omitempty"`
	StagerMode string `json:"stager_mode,omitempty"`
}

// Statistics represents statistics details.
type Statistics struct {
	AssetsAttacked    int64    `json:"assets_attacked,omitempty"`
	AttackSuccess     float64  `json:"attack_success,omitempty"`
	FilesExfiltrated  int64    `json:"files_exfiltrated,omitempty"`
	PlatformsAttacked []string `json:"platforms_attacked,omitempty"`
	TotalSteps        int64    `json:"total_steps,omitempty"`
}

// Hostname represents hostname details.
type Hostname struct {
	AssetID string `json:"asset_id,omitempty"`
	IPAddr  string `json:"ipaddr,omitempty"`
	Name    string `json:"name,omitempty"`
	OS      string `json:"os,omitempty"`
}

// StagerDetails represents stager details in AttackExecution.
type StagerDetails struct {
	StagerID   string `json:"stager_id,omitempty"`
	StagerMode string `json:"stager_mode,omitempty"`
}

// TemporaryObject represents a temporary object.
type TemporaryObject struct {
	Bucket string `json:"bucket,omitempty"`
	Object string `json:"object,omitempty"`
	Valid  bool   `json:"valid,omitempty"`
}
