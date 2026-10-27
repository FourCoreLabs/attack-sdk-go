// Package emergingthreats manages user-created campaigns through the v2 API.
package emergingthreats

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats"
)

// CampaignsV2URI is the base endpoint for user-created emerging-threat campaigns.
const CampaignsV2URI = "/api/v2/content/emerging_threat_attacks/campaigns"

// CampaignFilter selects campaigns and available filter values.
type CampaignFilter struct {
	StartReleaseDate    time.Time
	EndReleaseDate      time.Time
	Industry            []string
	ThreatActor         []string
	Region              []string
	Family              []string
	Category            []string
	HostingOrganisation []string
	DomainName          []string
	FileType            []string
	PayloadType         []string
}

// AnalyticsOpts selects the date range and behaviors used for campaign analytics.
// Nil boolean pointers omit a filter; pointers to false explicitly filter false.
// Set both StartDayRange and EndDayRange, or neither. Dates take precedence over Days.
type AnalyticsOpts struct {
	Days          *uint
	StartDayRange time.Time
	EndDayRange   time.Time
	ExecutionType []string
	UseLink       *bool
	UseAttachment *bool
}

// ListCampaignsOpts controls campaign pagination, content filters, and analytics.
// Size zero omits the parameter, using the server default. Order is a comma-separated
// list of sort fields with optional +/- prefixes, for example "-updated_at,name".
type ListCampaignsOpts struct {
	CampaignFilter
	AnalyticsOpts
	Size   int
	Offset int
	Order  string
}

// GetCampaignOpts controls the analytics included in a campaign detail response.
type GetCampaignOpts struct {
	AnalyticsOpts
}

// CreateCampaign creates a campaign. Object entries reference a tenant:// URI
// returned by tenantstore.UploadFile, not raw bytes or a bare tenant file ID.
func CreateCampaign(ctx context.Context, h *api.HTTPAPI, request model.CampaignCreateRequest) (model.Campaign, error) {
	var result model.Campaign
	_, err := h.PostJSON(ctx, CampaignsV2URI, request, &result)
	if err != nil {
		return model.Campaign{}, fmt.Errorf("create emerging-threat campaign: %w", err)
	}
	return result, nil
}

// UpdateCampaign replaces a campaign using the supplied document and cleanup policy.
func UpdateCampaign(ctx context.Context, h *api.HTTPAPI, id string, request model.CampaignUpdateRequest) (model.Campaign, error) {
	endpoint, err := campaignEndpoint(id)
	if err != nil {
		return model.Campaign{}, err
	}
	var result model.Campaign
	_, err = h.PutJSON(ctx, endpoint, request, &result)
	if err != nil {
		return model.Campaign{}, fmt.Errorf("update emerging-threat campaign: %w", err)
	}
	return result, nil
}

// DeleteCampaign deletes a campaign. A nil request uses the server's cleanup default.
func DeleteCampaign(ctx context.Context, h *api.HTTPAPI, id string, request *model.CampaignDeleteRequest) (models.SuccessIDResponse, error) {
	endpoint, err := campaignEndpoint(id)
	if err != nil {
		return models.SuccessIDResponse{}, err
	}
	var result models.SuccessIDResponse
	// Avoid encoding a typed nil pointer as a JSON null body.
	var body any
	if request != nil {
		body = request
	}
	_, err = h.DeleteJSON(ctx, endpoint, body, &result)
	if err != nil {
		return models.SuccessIDResponse{}, fmt.Errorf("delete emerging-threat campaign: %w", err)
	}
	return result, nil
}

// ListCampaigns lists campaigns with matching content and latest behavior analytics.
func ListCampaigns(ctx context.Context, h *api.HTTPAPI, opts ListCampaignsOpts) (models.PaginationResponse[model.Campaign], error) {
	var result models.PaginationResponse[model.Campaign]
	if opts.Size < 0 || opts.Offset < 0 {
		return result, errors.New("campaign size and offset must not be negative")
	}
	params := campaignFilterParams(opts.CampaignFilter)
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return result, err
	}
	if opts.Size > 0 {
		params.Set("size", strconv.Itoa(opts.Size))
	}
	if opts.Offset > 0 {
		params.Set("offset", strconv.Itoa(opts.Offset))
	}
	if opts.Order != "" {
		params.Set("order", opts.Order)
	}
	_, err := h.GetJSON(ctx, CampaignsV2URI, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list emerging-threat campaigns: %w", err)
	}
	return result, nil
}

// GetCampaign retrieves one campaign and its latest analytics.
func GetCampaign(ctx context.Context, h *api.HTTPAPI, id string, opts GetCampaignOpts) (model.Campaign, error) {
	endpoint, err := campaignEndpoint(id)
	if err != nil {
		return model.Campaign{}, err
	}
	params := make(url.Values)
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return model.Campaign{}, err
	}
	var result model.Campaign
	_, err = h.GetJSON(ctx, endpoint, &result, api.ReqOptions{Params: params})
	if err != nil {
		return model.Campaign{}, fmt.Errorf("get emerging-threat campaign: %w", err)
	}
	return result, nil
}

// GetCampaignFilters retrieves filter dropdown values constrained by content filters.
func GetCampaignFilters(ctx context.Context, h *api.HTTPAPI, filter CampaignFilter) (model.CampaignFilters, error) {
	var result model.CampaignFilters
	_, err := h.GetJSON(ctx, CampaignsV2URI+"/filters", &result, api.ReqOptions{Params: campaignFilterParams(filter)})
	if err != nil {
		return result, fmt.Errorf("get emerging-threat campaign filters: %w", err)
	}
	return result, nil
}

func campaignEndpoint(id string) (string, error) {
	if strings.TrimSpace(id) == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\?#\x00") {
		return "", errors.New("campaign ID must be a nonempty path segment")
	}
	return CampaignsV2URI + "/" + id, nil
}

func campaignFilterParams(filter CampaignFilter) url.Values {
	params := make(url.Values)
	if !filter.StartReleaseDate.IsZero() {
		params.Set("filter[start_release_date]", filter.StartReleaseDate.Format(time.RFC3339))
	}
	if !filter.EndReleaseDate.IsZero() {
		params.Set("filter[end_release_date]", filter.EndReleaseDate.Format(time.RFC3339))
	}
	for key, values := range map[string][]string{
		"industry": filter.Industry, "threat_actor": filter.ThreatActor,
		"region": filter.Region, "family": filter.Family, "category": filter.Category,
		"hosting_organisation": filter.HostingOrganisation, "domain_name": filter.DomainName,
		"file_type": filter.FileType, "payload_type": filter.PayloadType,
	} {
		if len(values) > 0 {
			// The API reads one value per filter and splits it on commas.
			params.Set("filter["+key+"]", strings.Join(values, ","))
		}
	}
	return params
}

func addAnalyticsParams(params url.Values, opts AnalyticsOpts) error {
	if opts.StartDayRange.IsZero() != opts.EndDayRange.IsZero() {
		return errors.New("both analytics start and end dates are required")
	}
	if !opts.StartDayRange.IsZero() {
		if opts.EndDayRange.Before(opts.StartDayRange) {
			return errors.New("analytics end date must not precede start date")
		}
		params.Set("start_drange", opts.StartDayRange.Format(time.RFC3339))
		params.Set("end_drange", opts.EndDayRange.Format(time.RFC3339))
	} else if opts.Days != nil {
		params.Set("d", strconv.FormatUint(uint64(*opts.Days), 10))
	}
	if len(opts.ExecutionType) > 0 {
		params.Set("filter[execution_type]", strings.Join(opts.ExecutionType, ","))
	}
	if opts.UseLink != nil {
		params.Set("filter[use_link]", strconv.FormatBool(*opts.UseLink))
	}
	if opts.UseAttachment != nil {
		params.Set("filter[use_attachment]", strconv.FormatBool(*opts.UseAttachment))
	}
	return nil
}
