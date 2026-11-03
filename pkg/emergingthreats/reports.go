package emergingthreats

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/internal/query"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats"
)

// ReportsV2URI is the per-threat execution report collection.
const ReportsV2URI = "/api/v2/emerging_threat/reports"

// CampaignReportsV2URI is the campaign execution report collection.
const CampaignReportsV2URI = "/api/v2/emerging_threat/campaign/reports"

// ListReportsOpts selects per-threat runs, including catalog and authored threats.
// DateAfter and DateBefore are the canonical start_updated_at/end_updated_at aliases.
type ListReportsOpts struct {
	models.PaginationOpts
	Name                    string
	DateAfter               time.Time
	DateBefore              time.Time
	UserIDs                 []uint
	AttackPayloadIDs        []string
	EmergingThreatAttackIDs []string
}

// ListCampaignReportsOpts selects catalog or authored campaign runs. Explicit
// date bounds override AnalyticsOpts dates. Behaviours accepts values such as
// malware_transfer_over_network, malicious_url_request, malware_written_to_disk,
// malware_download_link_in_email, spearphishing_link_in_email and
// malicious_email_attachment.
type ListCampaignReportsOpts struct {
	models.PaginationOpts
	AnalyticsOpts
	Name                string
	DateAfter           time.Time
	DateBefore          time.Time
	UserIDs             []uint
	CampaignIDs         []string
	AttackCampaignIDs   []string
	ScheduleIDs         []string
	GroupCampaignRunIDs []string
	AssetIDs            []string
	Behaviours          []string
}

// ListReports lists per-threat execution summaries. Requires emergingthreat.read.
func ListReports(ctx context.Context, h *api.HTTPAPI, opts ListReportsOpts) (models.PaginationResponse[model.AttackRun], error) {
	var result models.PaginationResponse[model.AttackRun]
	params := make(url.Values)
	if err := query.Pagination(params, opts.PaginationOpts); err != nil {
		return result, err
	}
	addReportFilters(params, opts.Name, opts.DateAfter, opts.DateBefore, opts.UserIDs)
	query.Strings(params, "attack_payload_id", opts.AttackPayloadIDs)
	query.Strings(params, "emerging_threat_attack_id", opts.EmergingThreatAttackIDs)
	_, err := h.GetJSON(ctx, ReportsV2URI, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list emerging-threat reports: %w", err)
	}
	return result, nil
}

// GetReport retrieves a run by run ID, not threat ID, including asset/step details.
// Deleted reports return a structured API error with status 410.
func GetReport(ctx context.Context, h *api.HTTPAPI, runID string) (model.AttackRun, error) {
	var result model.AttackRun
	if err := validatePathSegment(runID, "run ID"); err != nil {
		return result, err
	}
	_, err := h.GetJSON(ctx, ReportsV2URI+"/"+runID, &result)
	if err != nil {
		return result, fmt.Errorf("get emerging-threat report: %w", err)
	}
	return result, nil
}

// DeleteReport deletes a per-threat run report. Requires emergingthreat.delete.
func DeleteReport(ctx context.Context, h *api.HTTPAPI, runID string) (models.SuccessIDResponse, error) {
	var result models.SuccessIDResponse
	if err := validatePathSegment(runID, "run ID"); err != nil {
		return result, err
	}
	_, err := h.DeleteJSON(ctx, ReportsV2URI+"/"+runID, nil, &result)
	if err != nil {
		return result, fmt.Errorf("delete emerging-threat report: %w", err)
	}
	return result, nil
}

// ListCampaignReports lists campaign run summaries. Requires emergingthreat.read.
func ListCampaignReports(ctx context.Context, h *api.HTTPAPI, opts ListCampaignReportsOpts) (models.PaginationResponse[model.CampaignRun], error) {
	var result models.PaginationResponse[model.CampaignRun]
	params := make(url.Values)
	if err := query.Pagination(params, opts.PaginationOpts); err != nil {
		return result, err
	}
	if err := addAnalyticsParams(params, opts.AnalyticsOpts); err != nil {
		return result, err
	}
	addReportFilters(params, opts.Name, opts.DateAfter, opts.DateBefore, opts.UserIDs)
	for key, values := range map[string][]string{
		"campaign_id": opts.CampaignIDs, "attack_campaign_id": opts.AttackCampaignIDs,
		"schedule_id": opts.ScheduleIDs, "group_campaign_run_id": opts.GroupCampaignRunIDs,
		"asset_id": opts.AssetIDs, "behaviours": opts.Behaviours,
	} {
		query.Strings(params, key, values)
	}
	_, err := h.GetJSON(ctx, CampaignReportsV2URI, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list emerging-threat campaign reports: %w", err)
	}
	return result, nil
}

// GetCampaignReport retrieves a campaign run by run ID, not catalog/campaign ID.
func GetCampaignReport(ctx context.Context, h *api.HTTPAPI, runID string) (model.CampaignRun, error) {
	var result model.CampaignRun
	if err := validatePathSegment(runID, "campaign run ID"); err != nil {
		return result, err
	}
	_, err := h.GetJSON(ctx, CampaignReportsV2URI+"/"+runID, &result)
	if err != nil {
		return result, fmt.Errorf("get emerging-threat campaign report: %w", err)
	}
	return result, nil
}

// DeleteCampaignReport deletes a campaign report. Requires emergingthreat.delete.
func DeleteCampaignReport(ctx context.Context, h *api.HTTPAPI, runID string) (models.SuccessIDResponse, error) {
	var result models.SuccessIDResponse
	if err := validatePathSegment(runID, "campaign run ID"); err != nil {
		return result, err
	}
	_, err := h.DeleteJSON(ctx, CampaignReportsV2URI+"/"+runID, nil, &result)
	if err != nil {
		return result, fmt.Errorf("delete emerging-threat campaign report: %w", err)
	}
	return result, nil
}

func addReportFilters(params url.Values, name string, after, before time.Time, userIDs []uint) {
	if name != "" {
		params.Set("filter[name]", name)
	}
	query.Time(params, "date_after", after)
	query.Time(params, "date_before", before)
	if len(userIDs) > 0 {
		values := make([]string, len(userIDs))
		for i, id := range userIDs {
			values[i] = strconv.FormatUint(uint64(id), 10)
		}
		params.Set("filter[user_id]", strings.Join(values, ","))
	}
}
