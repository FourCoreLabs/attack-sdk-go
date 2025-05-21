package asset

import (
	"time"
)

// Asset represents an endpoint asset in the FourCore platform
type Asset struct {
	ID         string            `json:"id"`
	OrgID      *uint             `json:"org_id,omitempty"`
	OrgName    *string           `json:"org_name,omitempty"`
	Available  bool              `json:"available"`
	Connected  bool              `json:"connected"`
	Disabled   bool              `json:"disabled"`
	Elevated   bool              `json:"elevated"`
	Version    string            `json:"version"`
	ADUserID   *string           `json:"ad_user_id,omitempty"`
	APIKey     *string           `json:"apikey,omitempty"`
	CreatedAt  *time.Time        `json:"created_at,omitempty"`
	UpdatedAt  *time.Time        `json:"updated_at,omitempty"`
	DeletedAt  *time.Time        `json:"deleted_at,omitempty"`
	Tags       map[string]string `json:"tags"`
	Users      []AssetUser       `json:"users"`
	EDR        []AssetEDR        `json:"edr"`
	SystemInfo *AssetSystemInfo  `json:"systeminfo,omitempty"`
}

// AssetUser represents a user associated with an asset
type AssetUser struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// AssetEDR represents an EDR (Endpoint Detection & Response) solution on an asset
type AssetEDR struct {
	EDRType string `json:"edr_type"`
}

// AssetSystemInfo contains detailed system information of an asset
type AssetSystemInfo struct {
	Hostname       string          `json:"hostname"`
	IPAddr         string          `json:"ipaddr"`
	OS             string          `json:"os"`
	Kernel         string          `json:"kernel"`
	Arch           string          `json:"arch"`
	Version        string          `json:"version"`
	MachineType    string          `json:"machine_type"`
	Manufacturer   string          `json:"manufacturer"`
	Model          string          `json:"model"`
	ProductName    string          `json:"product_name"`
	SerialNumber   string          `json:"serial_number"`
	CPU            int             `json:"cpu"`
	CPUID          string          `json:"cpuid"`
	RunningProc    int             `json:"runningproc"`
	FreeMemory     string          `json:"freememory"`
	TotalMemory    string          `json:"totalmemory"`
	FreeDiskSpace  string          `json:"freediskspace"`
	TotalDiskSpace string          `json:"totaldiskspace"`
	BootTime       uint64          `json:"boot_time"`
	Uptime         uint64          `json:"uptime"`
	DomainInfo     *DomainInfo     `json:"domain_info,omitempty"`
	Users          []SystemUser    `json:"users"`
	Groups         []SystemGroup   `json:"groups"`
	Processes      []SystemProcess `json:"processes"`
	Errors         []string        `json:"errors"`
}

// DomainInfo contains information about the domain the asset belongs to
type DomainInfo struct {
	Joined        bool   `json:"Joined"`
	Name          string `json:"Name"`
	DnsDomainName string `json:"DnsDomainName"`
	DnsForestName string `json:"DnsForestName"`
	Guid          string `json:"Guid"`
	Sid           string `json:"Sid"`
}

// SystemUser represents a user account on the system
type SystemUser struct {
	UID         string   `json:"UID"`
	Username    string   `json:"Username"`
	Name        string   `json:"Name"`
	HomeDir     string   `json:"HomeDir"`
	Interactive bool     `json:"Interactive"`
	Groups      []string `json:"Groups"`
}

// SystemGroup represents a group on the system
type SystemGroup struct {
	GID   string   `json:"GID"`
	Name  string   `json:"Name"`
	Users []string `json:"Users"`
}

// SystemProcess represents a running process on the system
type SystemProcess struct {
	PID              int32    `json:"PID"`
	PPID             int32    `json:"PPID"`
	Name             string   `json:"Name"`
	Path             string   `json:"Path"`
	Cmdline          string   `json:"Cmdline"`
	Cwd              string   `json:"Cwd"`
	Username         string   `json:"Username"`
	Description      string   `json:"Description"`
	Version          string   `json:"Version"`
	ProductName      string   `json:"ProductName"`
	OriginalFilename string   `json:"OriginalFilename"`
	Environ          []string `json:"Environ"`
}

// AssetTags represents the tags associated with an asset
type AssetTags struct {
	Tags map[string]string `json:"tags"`
}

// AssetSetTagsResponse represents the response when setting tags
type AssetSetTagsResponse struct {
	Success bool      `json:"success"`
	Tags    AssetTags `json:"tags"`
}

// AssetAnalytics represents analytics data for an endpoint asset
type AssetAnalytics struct {
	Total           int                    `json:"total"`
	Success         int                    `json:"success"`
	Detected        int                    `json:"detected"`
	CorrelationType CorrelationTypeCount   `json:"correlation_type"`
	IntegrationType []IntegrationTypeCount `json:"integration_type"`
}

// CorrelationTypeCount represents counts of correlation types
type CorrelationTypeCount struct {
	Alerts  int `json:"alerts"`
	Queries int `json:"queries"`
}

// IntegrationTypeCount represents count by integration type
type IntegrationTypeCount struct {
	IntegrationType string `json:"integration_type"`
	Count           int    `json:"count"`
}

// EmailAsset represents an email asset in the FourCore platform
type EmailAsset struct {
	ID        string            `json:"id"`
	OrgID     uint              `json:"org_id"`
	UserID    uint              `json:"user_id"`
	Email     string            `json:"email"`
	Available bool              `json:"available"`
	Disabled  bool              `json:"disabled"`
	Verified  bool              `json:"verified"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
	DeletedAt *time.Time        `json:"deleted_at,omitempty"`
	Tags      map[string]string `json:"tags"`
}

// CreateEmailAssetRequest represents the request body for creating or updating an email asset
type CreateEmailAssetRequest struct {
	Email string            `json:"email"`
	Tags  map[string]string `json:"tags"`
}

// EmailAssetAnalytics represents analytics data for an email asset
type EmailAssetAnalytics struct {
	Total         int            `json:"total"`
	Success       int            `json:"success"`
	Detected      int            `json:"detected"`
	ActionSuccess map[string]int `json:"action_success"`
	ExtSuccess    map[string]int `json:"ext_success"`
	MimeSuccess   map[string]int `json:"mime_success"`
}

// GmailConfCode represents the Gmail confirmation code for email asset verification
type GmailConfCode struct {
	EmailAssetID string     `json:"email_asset_id"`
	Code         string     `json:"code"`
	Link         string     `json:"link"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}
