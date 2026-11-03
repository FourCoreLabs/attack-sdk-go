package emergingthreats

import "time"

// CatalogFilters contains counted filter values for subscribed catalog threats.
type CatalogFilters struct {
	Type                    []string    `json:"type"`
	Family                  []CountData `json:"family"`
	Category                []CountData `json:"category"`
	Hosting                 []CountData `json:"hosting"`
	Domain                  []CountData `json:"domain"`
	FileType                []CountData `json:"file_type"`
	Campaign                []CountData `json:"campaign"`
	EmailAttachmentCategory []CountData `json:"email_attachment_category"`
	EndpointSigCategory     []CountData `json:"endpoint_sig_category"`
}

// CatalogCampaignFilters differs from the authored-campaign dropdown response.
type CatalogCampaignFilters struct {
	ThreatActor    []CountData `json:"threat_actor"`
	Region         []CountData `json:"region"`
	RegionCountry  []CountData `json:"region_country"`
	RegionAlliance []CountData `json:"region_alliance"`
	Industry       []CountData `json:"industry"`
	FileType       []CountData `json:"file_type"`
	Family         []CountData `json:"family"`
	Category       []CountData `json:"category"`
	HostingOrg     []CountData `json:"hosting_org"`
	Type           []CountData `json:"type"`
}

// Group summarizes catalog threats grouped by a content attribute.
type Group struct {
	GroupType         string     `json:"group_type"`
	MitreCount        int        `json:"mitre_count"`
	PayloadCount      int        `json:"payload_count"`
	LastExecution     *time.Time `json:"last_execution"`
	LatestReleaseDate *time.Time `json:"latest_release_date"`
	Success           int        `json:"success"`
	Detected          int        `json:"detected"`
	Total             int        `json:"total"`
}

// MalwareCategory summarizes file-delivery threats in one malware category.
type MalwareCategory struct {
	Category          string     `json:"category"`
	MitreCount        int        `json:"mitre_count"`
	PayloadCount      int        `json:"payload_count"`
	LastExecution     *time.Time `json:"last_execution"`
	LatestReleaseDate *time.Time `json:"latest_release_date"`
	Success           int        `json:"success"`
	Detected          int        `json:"detected"`
	Total             int        `json:"total"`
}

// OverviewAnalytics counts tested and available assets and threat outcomes.
type OverviewAnalytics struct {
	AssetCount       int `json:"asset_count"`
	EmailAssetCount  int `json:"email_asset_count"`
	WafAssetCount    int `json:"waf_asset_count"`
	TotalAssets      int `json:"total_assets"`
	TotalEmailAssets int `json:"total_email_assets"`
	TotalWafAssets   int `json:"total_waf_assets"`
	Success          int `json:"success"`
	Total            int `json:"total"`
	Detected         int `json:"detected"`
}

// PayloadAnalytics groups successful catalog payload outcomes by file type.
type PayloadAnalytics struct {
	Analytics         []FileTypeAnalytics `json:"analytics"`
	TotalSuccessCount int                 `json:"total_success_count"`
}

// FileTypeAnalytics counts successful outcomes for one file type.
type FileTypeAnalytics struct {
	FileType     string `json:"file_type"`
	SuccessCount int    `json:"success_count"`
}

// CampaignIndicators lists indicators derived from a catalog campaign. NotChecked
// counts payloads for which the server could not derive a supported indicator.
type CampaignIndicators struct {
	CampaignID string      `json:"campaign_id"`
	Indicators []Indicator `json:"indicators"`
	NotChecked int         `json:"not_checked"`
}

// Indicator is a hash, domain, URL, IP or other campaign observable.
type Indicator struct {
	Type        string               `json:"type"`
	Value       string               `json:"value"`
	Source      string               `json:"source,omitempty"`
	Confidence  string               `json:"confidence,omitempty"`
	FirstSeen   string               `json:"first_seen,omitempty"`
	ReviewAfter string               `json:"review_after,omitempty"`
	Provenance  *IndicatorProvenance `json:"provenance,omitempty"`
}

// IndicatorProvenance identifies evidence supporting an indicator.
type IndicatorProvenance struct {
	InvestigationID string   `json:"investigation_id,omitempty"`
	EvidenceIDs     []string `json:"evidence_ids,omitempty"`
	SourceURL       string   `json:"source_url,omitempty"`
}
