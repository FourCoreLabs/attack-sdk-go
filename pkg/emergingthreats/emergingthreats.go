// Package emergingthreats browses the threat catalog, manages user-created IOC
// entries and campaigns, and executes and reports on threats through the v2 API.
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

// AttacksV2URI is the base endpoint for standalone user-created entries.
const AttacksV2URI = "/api/v2/emerging_threat/attack"

// CampaignsV2URI is the base endpoint for user-created emerging-threat campaigns.
const CampaignsV2URI = AttacksV2URI + "/campaigns"

// ExecuteAttacksV2URI is the base endpoint for executing saved entries.
const ExecuteAttacksV2URI = "/api/v2/emerging_threat/user"

// ExecuteCampaignsV2URI is the endpoint for executing saved campaigns.
const ExecuteCampaignsV2URI = "/api/v2/emerging_threat/campaign/user"

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

// AttackFilter selects standalone entries and their available filter values.
type AttackFilter struct {
	Family              []string
	Category            []string
	HostingOrganisation []string
	DomainName          []string
	FileType            []string
	PayloadType         []string
}

// AnalyticsOpts selects the date range and behaviors used for analytics.
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

// ListAttacksOpts controls standalone entry pagination, content filters, and analytics.
// Size zero omits the parameter, using the server default. Order is a comma-separated
// list of sort fields with optional +/- prefixes, for example "-updated_at,name".
type ListAttacksOpts struct {
	AttackFilter
	AnalyticsOpts
	Size   int
	Offset int
	Order  string
}

// GetAttackOpts controls the analytics included in a standalone entry response.
type GetAttackOpts struct {
	AnalyticsOpts
}

// CreateAttack creates a standalone entry. Object entries reference a tenant:// URI
// returned by tenantstore.UploadFile, not raw bytes or a bare tenant file ID.
func CreateAttack(ctx context.Context, h *api.HTTPAPI, request model.AttackInput) (model.Attack, error) {
	var result model.Attack
	_, err := h.PostJSON(ctx, AttacksV2URI, request, &result)
	if err != nil {
		return model.Attack{}, fmt.Errorf("create emerging-threat attack: %w", err)
	}
	return result, nil
}

// UpdateAttack replaces a standalone entry using the supplied document and cleanup policy.
func UpdateAttack(ctx context.Context, h *api.HTTPAPI, id string, request model.AttackUpdateRequest) (model.Attack, error) {
	endpoint, err := attackEndpoint(id)
	if err != nil {
		return model.Attack{}, err
	}
	var result model.Attack
	_, err = h.PutJSON(ctx, endpoint, request, &result)
	if err != nil {
		return model.Attack{}, fmt.Errorf("update emerging-threat attack: %w", err)
	}
	return result, nil
}

// DeleteAttack deletes a standalone entry. A nil request uses the server's cleanup default.
func DeleteAttack(ctx context.Context, h *api.HTTPAPI, id string, request *model.AttackDeleteRequest) (models.SuccessIDResponse, error) {
	endpoint, err := attackEndpoint(id)
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
		return models.SuccessIDResponse{}, fmt.Errorf("delete emerging-threat attack: %w", err)
	}
	return result, nil
}

// ListAttacks lists standalone entries with matching content and latest behavior analytics.
func ListAttacks(ctx context.Context, h *api.HTTPAPI, opts ListAttacksOpts) (models.PaginationResponse[model.Attack], error) {
	var result models.PaginationResponse[model.Attack]
	if opts.Size < 0 || opts.Offset < 0 {
		return result, errors.New("attack size and offset must not be negative")
	}
	params := attackFilterParams(opts.AttackFilter)
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
	_, err := h.GetJSON(ctx, AttacksV2URI, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list emerging-threat attacks: %w", err)
	}
	return result, nil
}

// GetAttack retrieves one standalone entry and its latest analytics.
func GetAttack(ctx context.Context, h *api.HTTPAPI, id string, opts GetAttackOpts) (model.Attack, error) {
	endpoint, err := attackEndpoint(id)
	if err != nil {
		return model.Attack{}, err
	}
	params := make(url.Values)
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return model.Attack{}, err
	}
	var result model.Attack
	_, err = h.GetJSON(ctx, endpoint, &result, api.ReqOptions{Params: params})
	if err != nil {
		return model.Attack{}, fmt.Errorf("get emerging-threat attack: %w", err)
	}
	return result, nil
}

// GetAttackFilters retrieves standalone entry filter dropdown values.
func GetAttackFilters(ctx context.Context, h *api.HTTPAPI, filter AttackFilter) (model.AttackFilters, error) {
	var result model.AttackFilters
	_, err := h.GetJSON(ctx, AttacksV2URI+"/filters", &result, api.ReqOptions{Params: attackFilterParams(filter)})
	if err != nil {
		return result, fmt.Errorf("get emerging-threat attack filters: %w", err)
	}
	return result, nil
}

// RunAttacks executes saved entries on endpoint and email assets. It returns one
// run per executed entry.
func RunAttacks(ctx context.Context, h *api.HTTPAPI, request model.RunAttackRequest) ([]model.AttackRun, error) {
	if err := validateIDs(request.AttackPayloads, "attack payload ID"); err != nil {
		return nil, err
	}
	if err := validateRunAssets(request.Assets, request.EmailAssets); err != nil {
		return nil, err
	}
	var result []model.AttackRun
	_, err := h.PostJSON(ctx, ExecuteAttacksV2URI+"/run", request, &result)
	if err != nil {
		return nil, fmt.Errorf("run emerging-threat attacks: %w", err)
	}
	return result, nil
}

// RunAttack executes only the entry named by id. Any AttackPayloads set on the
// request are ignored: the path identity decides what runs.
func RunAttack(ctx context.Context, h *api.HTTPAPI, id string, request model.RunAttackRequest) ([]model.AttackRun, error) {
	endpoint, err := executeAttackEndpoint(id)
	if err != nil {
		return nil, err
	}
	if err := validateRunAssets(request.Assets, request.EmailAssets); err != nil {
		return nil, err
	}
	request.AttackPayloads = nil
	var result []model.AttackRun
	_, err = h.PostJSON(ctx, endpoint+"/run", request, &result)
	if err != nil {
		return nil, fmt.Errorf("run emerging-threat attack: %w", err)
	}
	return result, nil
}

// RunCampaigns executes saved campaigns on endpoint and email assets. It returns
// one run per executed campaign. An empty result means every campaign had no
// entries to run.
func RunCampaigns(ctx context.Context, h *api.HTTPAPI, request model.RunCampaignRequest) ([]model.CampaignRun, error) {
	if err := validateIDs(request.Campaigns, "campaign ID"); err != nil {
		return nil, err
	}
	if err := validateRunAssets(request.Assets, request.EmailAssets); err != nil {
		return nil, err
	}
	var result []model.CampaignRun
	_, err := h.PostJSON(ctx, ExecuteCampaignsV2URI+"/run", request, &result)
	if err != nil {
		return nil, fmt.Errorf("run emerging-threat campaigns: %w", err)
	}
	return result, nil
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

func attackEndpoint(id string) (string, error) {
	if err := validatePathSegment(id, "attack ID"); err != nil {
		return "", err
	}
	return AttacksV2URI + "/" + id, nil
}

func executeAttackEndpoint(id string) (string, error) {
	if err := validatePathSegment(id, "attack ID"); err != nil {
		return "", err
	}
	return ExecuteAttacksV2URI + "/" + id, nil
}

func campaignEndpoint(id string) (string, error) {
	if err := validatePathSegment(id, "campaign ID"); err != nil {
		return "", err
	}
	return CampaignsV2URI + "/" + id, nil
}

// validatePathSegment rejects identities that would change the request path.
func validatePathSegment(id, label string) error {
	if strings.TrimSpace(id) == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\?#\x00") {
		return fmt.Errorf("%s must be a nonempty path segment", label)
	}
	return nil
}

// validateIDs refuses an empty selection and empty selections within it.
func validateIDs(ids []string, label string) error {
	if len(ids) == 0 {
		return fmt.Errorf("at least one %s is required", label)
	}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%s must not be empty", label)
		}
	}
	return nil
}

// validateRunAssets refuses an execution without a target and empty target IDs.
func validateRunAssets(assets, emailAssets []string) error {
	if len(assets) == 0 && len(emailAssets) == 0 {
		return errors.New("at least one endpoint or email asset is required")
	}
	for _, asset := range append(assets, emailAssets...) {
		if strings.TrimSpace(asset) == "" {
			return errors.New("asset IDs must not be empty")
		}
	}
	return nil
}

func attackFilterParams(filter AttackFilter) url.Values {
	params := make(url.Values)
	for key, values := range map[string][]string{
		"family": filter.Family, "category": filter.Category,
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
