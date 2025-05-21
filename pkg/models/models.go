package models

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
