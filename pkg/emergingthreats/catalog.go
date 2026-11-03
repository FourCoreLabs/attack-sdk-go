package emergingthreats

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/internal/query"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats"
)

// CatalogV2URI is the subscribed threat catalog, not user-authored IOC entries.
const CatalogV2URI = "/api/v2/content/emerging_threat"

// CatalogCampaignsV2URI is the subscribed campaign catalog.
const CatalogCampaignsV2URI = "/api/v2/content/emerging_threat_campaigns"

// GroupBy selects an attribute for ListCatalogGroups.
type GroupBy string

const (
	GroupByCategory                GroupBy = "category"
	GroupByFamily                  GroupBy = "family"
	GroupByFileType                GroupBy = "file_type"
	GroupByHosting                 GroupBy = "hosting"
	GroupByDomain                  GroupBy = "domain"
	GroupByCampaign                GroupBy = "campaign"
	GroupByType                    GroupBy = "type"
	GroupByEndpointSignature       GroupBy = "endpoint_sig_category"
	GroupByEmailAttachmentCategory GroupBy = "email_attachment_category"
)

// CatalogFilter selects catalog threats. These filter names differ from authored
// AttackFilter: Hosting and Domain encode filter[hosting] and filter[domain].
// The server uses object/host as payload types, despite older schemas advertising
// malware/url. Nil ShowDeprecated retains the default of hiding deprecated items.
type CatalogFilter struct {
	IDs                     []string
	Names                   []string
	Types                   []string
	Family                  []string
	Category                []string
	Hosting                 []string
	Domain                  []string
	FileType                []string
	Campaign                []string
	EndpointSigCategory     []string
	EmailAttachmentCategory []string
	StartReleaseDate        time.Time
	EndReleaseDate          time.Time
	ShowDeprecated          *bool
}

// CatalogCampaignFilter adds campaign-specific filters to catalog content filters.
// Nil HideEmpty retains the server default of hiding campaigns without threats.
type CatalogCampaignFilter struct {
	CatalogFilter
	Industry    []string
	Region      []string
	ThreatActor []string
	HideEmpty   *bool
}

// ListCatalogThreatsOpts selects a catalog page and its latest outcome analytics.
type ListCatalogThreatsOpts struct {
	models.PaginationOpts
	models.OutcomeFilter
	CatalogFilter
	AnalyticsOpts
}

// ListCatalogCampaignsOpts selects catalog campaigns and their latest analytics.
type ListCatalogCampaignsOpts struct {
	models.PaginationOpts
	models.OutcomeFilter
	CatalogCampaignFilter
	AnalyticsOpts
}

// ListMalwareCategoriesOpts selects malware category summary rows.
type ListMalwareCategoriesOpts struct {
	models.PaginationOpts
	models.OutcomeFilter
	AnalyticsOpts
	Category               []string
	StartLatestReleaseDate time.Time
	EndLatestReleaseDate   time.Time
	StartLastExecution     time.Time
	EndLastExecution       time.Time
}

// OverviewOpts selects analytics dates. StartTimestamp/EndTimestamp override the
// normal AnalyticsOpts date range when StartTimestamp is supplied.
type OverviewOpts struct {
	AnalyticsOpts
	StartTimestamp time.Time
	EndTimestamp   time.Time
}

// ListCatalogThreats lists subscribed threats, not user-created entries.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func ListCatalogThreats(ctx context.Context, h *api.HTTPAPI, opts ListCatalogThreatsOpts) (models.PaginationResponse[model.Attack], error) {
	var result models.PaginationResponse[model.Attack]
	params, err := catalogListParams(opts)
	if err != nil {
		return result, err
	}
	_, err = h.GetJSON(ctx, CatalogV2URI, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list catalog threats: %w", err)
	}
	return result, nil
}

// GetCatalogThreat retrieves a subscribed threat and its behavior analytics.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetCatalogThreat(ctx context.Context, h *api.HTTPAPI, id string, opts AnalyticsOpts) (model.Attack, error) {
	var result model.Attack
	if err := validatePathSegment(id, "catalog threat ID"); err != nil {
		return result, err
	}
	params := make(url.Values)
	if err := addAnalyticsParams(params, opts); err != nil {
		return result, err
	}
	_, err := h.GetJSON(ctx, CatalogV2URI+"/"+id, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("get catalog threat: %w", err)
	}
	return result, nil
}

// GetCatalogFilters retrieves counted threat filter values.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetCatalogFilters(ctx context.Context, h *api.HTTPAPI, filter CatalogFilter) (model.CatalogFilters, error) {
	var result model.CatalogFilters
	_, err := h.GetJSON(ctx, CatalogV2URI+"/filters", &result, api.ReqOptions{Params: catalogFilterParams(filter)})
	if err != nil {
		return result, fmt.Errorf("get catalog threat filters: %w", err)
	}
	return result, nil
}

// ListCatalogGroups groups subscribed threats by the selected content attribute.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func ListCatalogGroups(ctx context.Context, h *api.HTTPAPI, group GroupBy, opts ListCatalogThreatsOpts) (models.PaginationResponse[model.Group], error) {
	var result models.PaginationResponse[model.Group]
	switch group {
	case GroupByCategory, GroupByFamily, GroupByFileType, GroupByHosting, GroupByDomain, GroupByCampaign, GroupByType, GroupByEndpointSignature, GroupByEmailAttachmentCategory:
	default:
		return result, fmt.Errorf("unsupported catalog grouping %q", group)
	}
	params, err := catalogListParams(opts)
	if err != nil {
		return result, err
	}
	_, err = h.GetJSON(ctx, CatalogV2URI+"/group/"+string(group), &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list catalog threat groups: %w", err)
	}
	return result, nil
}

// ListMalwareCategories lists file-delivery threat categories with outcome totals.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func ListMalwareCategories(ctx context.Context, h *api.HTTPAPI, opts ListMalwareCategoriesOpts) (models.PaginationResponse[model.MalwareCategory], error) {
	var result models.PaginationResponse[model.MalwareCategory]
	params := make(url.Values)
	if err := query.Pagination(params, opts.PaginationOpts); err != nil {
		return result, err
	}
	if err := query.Outcomes(params, opts.OutcomeFilter); err != nil {
		return result, err
	}
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return result, err
	}
	query.Strings(params, "category", opts.Category)
	query.Time(params, "start_latest_release_date", opts.StartLatestReleaseDate)
	query.Time(params, "end_latest_release_date", opts.EndLatestReleaseDate)
	query.Time(params, "start_last_execution", opts.StartLastExecution)
	query.Time(params, "end_last_execution", opts.EndLastExecution)
	_, err := h.GetJSON(ctx, CatalogV2URI+"/malware_category", &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list malware categories: %w", err)
	}
	return result, nil
}

// GetOverviewAnalytics retrieves catalog coverage and outcome counts.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetOverviewAnalytics(ctx context.Context, h *api.HTTPAPI, opts OverviewOpts) (model.OverviewAnalytics, error) {
	var result model.OverviewAnalytics
	params, err := overviewParams(opts)
	if err != nil {
		return result, err
	}
	_, err = h.GetJSON(ctx, CatalogV2URI+"/overview/analytics", &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("get threat overview analytics: %w", err)
	}
	return result, nil
}

// GetOverviewPayloadAnalytics retrieves successful payload outcomes by file type.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetOverviewPayloadAnalytics(ctx context.Context, h *api.HTTPAPI, opts OverviewOpts) (model.PayloadAnalytics, error) {
	var result model.PayloadAnalytics
	params, err := overviewParams(opts)
	if err != nil {
		return result, err
	}
	_, err = h.GetJSON(ctx, CatalogV2URI+"/overview/payload_analytics", &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("get threat payload analytics: %w", err)
	}
	return result, nil
}

// GetOverviewVectorAnalytics retrieves successful outcomes by delivery vector.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetOverviewVectorAnalytics(ctx context.Context, h *api.HTTPAPI, opts OverviewOpts) (model.RunVectorAnalytics, error) {
	var result model.RunVectorAnalytics
	params, err := overviewParams(opts)
	if err != nil {
		return result, err
	}
	_, err = h.GetJSON(ctx, CatalogV2URI+"/overview/vector_analytics", &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("get threat vector analytics: %w", err)
	}
	return result, nil
}

// ListCatalogCampaigns lists subscribed campaigns, not user-authored campaigns.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func ListCatalogCampaigns(ctx context.Context, h *api.HTTPAPI, opts ListCatalogCampaignsOpts) (models.PaginationResponse[model.Campaign], error) {
	var result models.PaginationResponse[model.Campaign]
	params := catalogCampaignFilterParams(opts.CatalogCampaignFilter)
	if err := query.Pagination(params, opts.PaginationOpts); err != nil {
		return result, err
	}
	if err := query.Outcomes(params, opts.OutcomeFilter); err != nil {
		return result, err
	}
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return result, err
	}
	_, err := h.GetJSON(ctx, CatalogCampaignsV2URI, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list catalog campaigns: %w", err)
	}
	return result, nil
}

// GetCatalogCampaign retrieves a subscribed campaign with per-threat analytics.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetCatalogCampaign(ctx context.Context, h *api.HTTPAPI, id string, opts AnalyticsOpts) (model.Campaign, error) {
	var result model.Campaign
	if err := validatePathSegment(id, "catalog campaign ID"); err != nil {
		return result, err
	}
	params := make(url.Values)
	if err := addAnalyticsParams(params, opts); err != nil {
		return result, err
	}
	_, err := h.GetJSON(ctx, CatalogCampaignsV2URI+"/"+id, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("get catalog campaign: %w", err)
	}
	return result, nil
}

// GetCatalogCampaignFilters retrieves counted catalog campaign filter values.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetCatalogCampaignFilters(ctx context.Context, h *api.HTTPAPI, filter CatalogCampaignFilter) (model.CatalogCampaignFilters, error) {
	var result model.CatalogCampaignFilters
	_, err := h.GetJSON(ctx, CatalogCampaignsV2URI+"/filters", &result, api.ReqOptions{Params: catalogCampaignFilterParams(filter)})
	if err != nil {
		return result, fmt.Errorf("get catalog campaign filters: %w", err)
	}
	return result, nil
}

// GetCatalogCampaignIndicators retrieves the campaign's supported observables.
// This is a content API, not a threat-hunting automation API.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats.
func GetCatalogCampaignIndicators(ctx context.Context, h *api.HTTPAPI, id string) (model.CampaignIndicators, error) {
	var result model.CampaignIndicators
	if err := validatePathSegment(id, "catalog campaign ID"); err != nil {
		return result, err
	}
	_, err := h.GetJSON(ctx, CatalogCampaignsV2URI+"/"+id+"/indicators", &result)
	if err != nil {
		return result, fmt.Errorf("get catalog campaign indicators: %w", err)
	}
	return result, nil
}

func catalogFilterParams(filter CatalogFilter) url.Values {
	params := make(url.Values)
	for key, values := range map[string][]string{
		"id": filter.IDs, "name": filter.Names, "type": filter.Types,
		"family": filter.Family, "category": filter.Category, "hosting": filter.Hosting,
		"domain": filter.Domain, "file_type": filter.FileType, "campaign": filter.Campaign,
		"endpoint_sig_category": filter.EndpointSigCategory, "email_attachment_category": filter.EmailAttachmentCategory,
	} {
		query.Strings(params, key, values)
	}
	query.Time(params, "start_release_date", filter.StartReleaseDate)
	query.Time(params, "end_release_date", filter.EndReleaseDate)
	query.Bool(params, "show_deprecated", filter.ShowDeprecated)
	return params
}

func catalogCampaignFilterParams(filter CatalogCampaignFilter) url.Values {
	params := catalogFilterParams(filter.CatalogFilter)
	query.Strings(params, "industry", filter.Industry)
	query.Strings(params, "region", filter.Region)
	query.Strings(params, "threat_actor", filter.ThreatActor)
	query.Bool(params, "hide_empty", filter.HideEmpty)
	return params
}

func catalogListParams(opts ListCatalogThreatsOpts) (url.Values, error) {
	params := catalogFilterParams(opts.CatalogFilter)
	if err := query.Pagination(params, opts.PaginationOpts); err != nil {
		return nil, err
	}
	if err := query.Outcomes(params, opts.OutcomeFilter); err != nil {
		return nil, err
	}
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return nil, err
	}
	return params, nil
}

func overviewParams(opts OverviewOpts) (url.Values, error) {
	params := make(url.Values)
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return nil, err
	}
	query.Time(params, "start_timestamp", opts.StartTimestamp)
	query.Time(params, "end_timestamp", opts.EndTimestamp)
	return params, nil
}
