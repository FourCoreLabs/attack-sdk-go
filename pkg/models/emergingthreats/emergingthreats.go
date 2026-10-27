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
