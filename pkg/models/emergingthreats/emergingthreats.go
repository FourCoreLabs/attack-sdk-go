// Package emergingthreats defines user-created emerging-threat campaign models.
package emergingthreats

import (
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// Payload types accepted when creating campaign entries.
const (
	PayloadTypeObject = "object"
	PayloadTypeHost   = "host"
)

// Payload identifies a tenant-store object URI or a host/URL indicator.
type Payload struct {
	Object         string `json:"object,omitempty"`
	Host           string `json:"host,omitempty"`
	AttachmentName string `json:"attachment_name,omitempty"`
}

// RuleHash contains optional hashes for a detection rule.
type RuleHash struct {
	SHA256 string `json:"sha256,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	MD5    string `json:"md5,omitempty"`
}

// Rule describes a detection rule attached to an entry or recommendation.
type Rule struct {
	ID    string   `json:"id"`
	Type  string   `json:"type"`
	Name  string   `json:"name"`
	Value string   `json:"value"`
	Hash  RuleHash `json:"hash,omitzero"`
}

// Recommendation describes a mitigation or detection recommendation.
type Recommendation struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	RuleType string `json:"rule_type"`
	Rules    []Rule `json:"rules,omitempty"`
}

// AttackInput is an IOC entry in a campaign create or update request.
// Set ID when retaining an existing entry during a campaign update.
type AttackInput struct {
	ID                  string           `json:"id,omitempty"`
	Name                string           `json:"name"`
	Description         string           `json:"description"`
	PayloadType         string           `json:"payload_type"`
	Payload             Payload          `json:"payload"`
	Family              string           `json:"family"`
	Category            string           `json:"category"`
	HostingOrganisation string           `json:"hosting_organisation"`
	DomainName          string           `json:"domain_name"`
	FileType            string           `json:"file_type"`
	Recommendations     []Recommendation `json:"recommendations"`
}

// CampaignCreateRequest creates a user-generated campaign with IOC entries.
type CampaignCreateRequest struct {
	Name            string        `json:"name"`
	Description     string        `json:"description"`
	ThreatActor     []string      `json:"threat_actor"`
	Industry        []string      `json:"industry"`
	Region          []string      `json:"region"`
	References      []string      `json:"references"`
	EmergingThreats []AttackInput `json:"emerging_threats"`
}

// CampaignUpdateRequest replaces a campaign and optionally removes orphaned files.
type CampaignUpdateRequest struct {
	CampaignCreateRequest
	DeleteTenantFileOnNoRelation bool `json:"delete_tenant_file_on_no_relation"`
}

// CampaignDeleteRequest controls file cleanup when deleting a campaign.
// Nil means use the server default; a pointer to false explicitly retains files.
type CampaignDeleteRequest struct {
	DeleteTenantFileOnNoRelation *bool `json:"delete_tenant_file_on_no_relation,omitempty"`
}

// AttackUpdateRequest replaces a standalone IOC entry and optionally removes an
// orphaned tenant file. The embedded fields form the replacement document.
type AttackUpdateRequest struct {
	AttackInput
	DeleteTenantFileOnNoRelation bool `json:"delete_tenant_file_on_no_relation"`
}

// AttackDeleteRequest controls file cleanup when deleting a standalone entry.
// Nil means use the server default; a pointer to false explicitly retains files.
type AttackDeleteRequest struct {
	DeleteTenantFileOnNoRelation *bool `json:"delete_tenant_file_on_no_relation,omitempty"`
}

// AttackFilters contains available values for standalone entry filter dropdowns.
// Unlike campaign filters these are plain values, not counted dropdowns.
type AttackFilters struct {
	PayloadType         []string `json:"payload_type"`
	Family              []string `json:"family"`
	Category            []string `json:"category"`
	HostingOrganisation []string `json:"hosting_organisation"`
	DomainName          []string `json:"domain_name"`
	FileType            []string `json:"file_type"`
}

// BehaviourOpts selects the delivery behaviors an execution may use. Entry type
// decides applicability: object entries use the download/attachment behaviors,
// host entries use the URL-request behaviors.
type BehaviourOpts struct {
	// Object entries.
	WebProxyMalwareDownload bool `json:"web_proxy_malware_download,omitempty"`
	MalwareDiskDownload     bool `json:"malware_disk_download,omitempty"`
	EmailLinkInBody         bool `json:"email_link_in_body,omitempty"`
	EmailAttachment         bool `json:"email_attachment,omitempty"`
	// Host entries.
	WebProxyURLRequest    bool `json:"web_proxy_url_request,omitempty"`
	EmailURLRequestInBody bool `json:"email_url_request_in_body,omitempty"`
}

// RunAttackRequest executes one or more saved entries on endpoint and email
// assets. Provide at least one endpoint asset, email asset, or both.
type RunAttackRequest struct {
	AttackPayloads []string       `json:"attack_payloads,omitempty"`
	Assets         []string       `json:"assets,omitempty"`
	EmailAssets    []string       `json:"email_assets,omitempty"`
	RunElevated    *bool          `json:"run_elevated,omitempty"`
	DisableCleanup *bool          `json:"disable_cleanup,omitempty"`
	Behaviours     *BehaviourOpts `json:"behaviours,omitempty"`
}

// RunCampaignRequest executes one or more saved campaigns on endpoint and email
// assets. Provide at least one endpoint asset, email asset, or both.
type RunCampaignRequest struct {
	Campaigns      []string       `json:"campaigns,omitempty"`
	Assets         []string       `json:"assets,omitempty"`
	EmailAssets    []string       `json:"email_assets,omitempty"`
	RunElevated    *bool          `json:"run_elevated,omitempty"`
	DisableCleanup *bool          `json:"disable_cleanup,omitempty"`
	Behaviours     *BehaviourOpts `json:"behaviours,omitempty"`
}

// AttackRun is one saved-entry execution and its current state. The server
// returns one run per executed entry, so a bulk request may yield several.
type AttackRun struct {
	ID                     string                         `json:"id"`
	AttackPayloadID        string                         `json:"attack_payload_id"`
	EmergingThreatAttackID string                         `json:"emerging_threat_attack_id"`
	Name                   string                         `json:"name"`
	Description            string                         `json:"description"`
	ExecutionType          []string                       `json:"execution_type"`
	UserID                 uint                           `json:"user_id"`
	OrgID                  uint                           `json:"org_id"`
	Username               string                         `json:"username,omitempty"`
	OrgName                string                         `json:"org_name,omitempty"`
	AssetIDs               []string                       `json:"asset_id"`
	EmailAssetIDs          []string                       `json:"email_asset_id"`
	Assets                 []models.AssetExecutionDetails `json:"assets"`
	Status                 string                         `json:"status"`
	StatusState            string                         `json:"status_state"`
	TotalFinished          int                            `json:"total_finished"`
	TotalAttacks           int                            `json:"total_attacks"`
	TotalSuccess           int                            `json:"total_success"`
	TotalDetected          int                            `json:"total_detected"`
	Hostname               []models.Hostname              `json:"hostname"`
	AssetEDRs              []string                       `json:"asset_edrs"`
	AssetIntegrations      []string                       `json:"asset_integrations"`
	Host                   string                         `json:"host"`
	IsRecurring            bool                           `json:"is_recurring"`
	Type                   string                         `json:"type"`
	Tags                   models.Tag                     `json:"tags"`
	Deprecated             bool                           `json:"deprecated"`
	CreatedAt              *time.Time                     `json:"created_at,omitempty"`
	UpdatedAt              *time.Time                     `json:"updated_at,omitempty"`
}

// RunVectorAnalytics counts an execution's per-vector behavior totals.
type RunVectorAnalytics struct {
	WebProxyMalwareDownload int `json:"web_proxy_malware_download"`
	MalwareDiskDownload     int `json:"malware_disk_download"`
	EmailLinkInBody         int `json:"email_link_in_body"`
	EmailAttachment         int `json:"email_attachment"`
	WebProxyURLRequest      int `json:"web_proxy_url_request"`
	EmailURLRequestInBody   int `json:"email_url_request_in_body"`
}

// RunOpts echoes the execution options a campaign run used.
type RunOpts struct {
	EmergingThreatCampaignOpt map[string]any `json:"emerging_threat_campaign_opt,omitempty"`
	AttackPayloadOpt          map[string]any `json:"attack_payload_opt,omitempty"`
}

// CampaignRun is one saved-campaign execution and its current state. Its
// attack_payload_executions lists the per-entry runs the campaign produced.
type CampaignRun struct {
	ID                      string                         `json:"id"`
	CampaignID              string                         `json:"campaign_id"`
	Name                    string                         `json:"name"`
	Description             string                         `json:"description"`
	Reference               []string                       `json:"reference"`
	Tags                    models.Tag                     `json:"tags"`
	UserID                  uint                           `json:"user_id"`
	OrgID                   uint                           `json:"org_id"`
	Username                string                         `json:"username,omitempty"`
	OrgName                 string                         `json:"org_name,omitempty"`
	AssetIDs                []string                       `json:"asset_id"`
	EmailAssetIDs           []string                       `json:"email_asset_id"`
	Assets                  []models.AssetExecutionDetails `json:"assets"`
	Status                  string                         `json:"status"`
	StatusState             string                         `json:"status_state"`
	TotalFinished           int                            `json:"total_finished"`
	TotalAttacks            int                            `json:"total_attacks"`
	TotalSuccess            int                            `json:"total_success"`
	TotalDetected           int                            `json:"total_detected"`
	Hostname                []models.Hostname              `json:"hostname"`
	TotalHosts              int                            `json:"total_hosts"`
	TotalMalwares           int                            `json:"total_malwares"`
	AssetEDRs               []string                       `json:"asset_edrs"`
	AssetIntegrations       []string                       `json:"asset_integrations"`
	AttackPayloadExecutions []AttackRun                    `json:"attack_payload_executions"`
	VectorAnalytics         RunVectorAnalytics             `json:"vector_analytics"`
	RunOpts                 RunOpts                        `json:"run_opts"`
	ReportCategory          string                         `json:"report_category"`
	IsRecurring             bool                           `json:"is_recurring"`
	Deprecated              bool                           `json:"deprecated"`
	CreatedAt               *time.Time                     `json:"created_at,omitempty"`
	UpdatedAt               *time.Time                     `json:"updated_at,omitempty"`
}

// CountAnalytics summarizes the latest outcome of a simulation behavior.
type CountAnalytics struct {
	Count    int `json:"count"`
	Success  int `json:"success"`
	Total    int `json:"total"`
	Detected int `json:"detected"`
}

// BehaviourAnalytics groups outcomes by simulation mechanism.
type BehaviourAnalytics struct {
	WebProxyMalwareDownload CountAnalytics `json:"web_proxy_malware_download"`
	MalwareDiskDownload     CountAnalytics `json:"malware_disk_download"`
	EmailAttachment         CountAnalytics `json:"email_attachment"`
	EmailLinkInBody         CountAnalytics `json:"email_link_in_body"`
	EmailURLRequestInBody   CountAnalytics `json:"email_url_request_in_body"`
	WebProxyURLRequest      CountAnalytics `json:"web_proxy_url_request"`
}

// VectorAnalytics summarizes outcomes for one execution vector.
type VectorAnalytics struct {
	Type     string `json:"type"`
	Success  int    `json:"success"`
	Detected int    `json:"detected"`
	Total    int    `json:"total"`
}

// CampaignMetadata is the campaign metadata embedded in API responses.
// Response references use "reference", unlike request "references".
type CampaignMetadata struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Reference   []string   `json:"reference"`
	Region      []string   `json:"region"`
	Industry    []string   `json:"industry"`
	ThreatActor []string   `json:"threat_actor"`
	ReleaseDate time.Time  `json:"release_date"`
	Tags        models.Tag `json:"tags,omitempty"`
}

// Campaign is a campaign response including its IOC entries and latest analytics.
type Campaign struct {
	CampaignMetadata
	CreatedAt                      *time.Time         `json:"created_at,omitempty"`
	UpdatedAt                      *time.Time         `json:"updated_at,omitempty"`
	DeletedAt                      *time.Time         `json:"deleted_at"`
	EmergingThreats                []*Attack          `json:"emerging_threats"`
	LastExecutedAt                 *time.Time         `json:"last_executed_at"`
	Success                        int                `json:"success"`
	Detected                       int                `json:"detected"`
	Total                          int                `json:"total"`
	VectorAnalytics                []VectorAnalytics  `json:"vector_analytics"`
	BehaviourAnalytics             BehaviourAnalytics `json:"behaviour_analytics"`
	IsRunning                      bool               `json:"is_running"`
	Type                           []string           `json:"type"`
	Family                         []string           `json:"family"`
	Category                       []string           `json:"category"`
	HostingOrganisation            []string           `json:"hosting_organisation"`
	FileType                       []string           `json:"file_type"`
	TotalHosts                     int                `json:"total_hosts"`
	TotalMalware                   int                `json:"total_malware"`
	UserID                         uint               `json:"user_id,omitempty"`
	OrgID                          uint               `json:"org_id,omitempty"`
	EmergingThreatAttackCampaignID string             `json:"emerging_threat_attack_campaign_id,omitempty"`
}

// Attack is an IOC entry returned by a campaign API. Its description uses "text".
type Attack struct {
	ID                     string                        `json:"id"`
	Key                    string                        `json:"key"`
	Name                   string                        `json:"name"`
	Description            string                        `json:"text"`
	Type                   string                        `json:"type"`
	Payload                Payload                       `json:"payload"`
	CreatedAt              *time.Time                    `json:"created_at,omitempty"`
	UpdatedAt              *time.Time                    `json:"updated_at,omitempty"`
	DeletedAt              *time.Time                    `json:"deleted_at"`
	ReleaseDate            time.Time                     `json:"release_date"`
	MimeType               string                        `json:"mimetype,omitempty"`
	AttachmentName         string                        `json:"attachment_name,omitempty"`
	MitreTactics           []models.MitreTacticTechnique `json:"mitre"`
	Tags                   models.Tag                    `json:"tags,omitempty"`
	Host                   string                        `json:"host,omitempty"`
	Rules                  []Rule                        `json:"rules"`
	Family                 string                        `json:"family"`
	Category               string                        `json:"category"`
	HostingOrganisation    string                        `json:"hosting_organisation"`
	DomainName             string                        `json:"domain_name"`
	FileType               string                        `json:"file_type"`
	CampaignID             string                        `json:"campaign_id"`
	Recommendations        []Recommendation              `json:"recommendations"`
	UserID                 uint                          `json:"user_id,omitempty"`
	OrgID                  uint                          `json:"org_id,omitempty"`
	EmergingThreatAttackID string                        `json:"emerging_threat_attack_id,omitempty"`
	Campaign               CampaignMetadata              `json:"campaign"`
	LastExecutedAt         *time.Time                    `json:"last_executed_at"`
	Success                int                           `json:"success"`
	Detected               int                           `json:"detected"`
	Total                  int                           `json:"total"`
	VectorAnalytics        []VectorAnalytics             `json:"vector_analytics"`
	BehaviourAnalytics     BehaviourAnalytics            `json:"behaviour_analytics"`
	IsRunning              bool                          `json:"is_running"`
	TotalHosts             int                           `json:"total_host"`
	TotalMalware           int                           `json:"total_malware"`
	Severity               models.Severity               `json:"severity,omitempty"`
}

// CountData is a filter dropdown value and its matching item count.
type CountData struct {
	Count int    `json:"count"`
	Data  string `json:"data"`
}

// CampaignFilters contains available values for campaign filter dropdowns.
type CampaignFilters struct {
	Industry            []CountData `json:"industry"`
	Region              []CountData `json:"region"`
	ThreatActor         []CountData `json:"threat_actor"`
	Family              []CountData `json:"family"`
	Category            []CountData `json:"category"`
	HostingOrganisation []CountData `json:"hosting_organisation"`
	DomainName          []CountData `json:"domain_name"`
	FileType            []CountData `json:"file_type"`
}
