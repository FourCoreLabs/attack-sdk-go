package emergingthreats

import (
	"context"
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats"
)

// ExecutionsV2URI is the base endpoint for catalog execution and run control.
const ExecutionsV2URI = "/api/v2/emerging_threat"

// RunCatalogThreats executes selected subscribed catalog threat IDs. For authored
// IOC IDs use RunAttacks instead.
//
// Required permission: emergingthreat.execute.
// Required feature: emerging_threats. Requires execution_enabled=true.
func RunCatalogThreats(ctx context.Context, h *api.HTTPAPI, request model.RunAttackRequest) ([]model.AttackRun, error) {
	if err := validateIDs(request.AttackPayloads, "catalog threat ID"); err != nil {
		return nil, err
	}
	if err := validateRunAssets(request.Assets, request.EmailAssets); err != nil {
		return nil, err
	}
	var result []model.AttackRun
	_, err := h.PostJSON(ctx, ExecutionsV2URI+"/run", request, &result)
	if err != nil {
		return nil, fmt.Errorf("run catalog threats: %w", err)
	}
	return result, nil
}

// RunConditionalCatalogThreats executes catalog threats selected by conditions.
// An empty ID list applies conditions across all subscribed threats; the server
// enforces its payload execution limit. Returns one campaign-shaped grouped run.
//
// Required permission: emergingthreat.execute.
// Required feature: emerging_threats. Requires execution_enabled=true.
func RunConditionalCatalogThreats(ctx context.Context, h *api.HTTPAPI, request model.RunConditionalRequest) (model.CampaignRun, error) {
	var result model.CampaignRun
	if err := validateRunAssets(request.Assets, request.EmailAssets); err != nil {
		return result, err
	}
	if len(request.AttackPayloads) > 0 {
		if err := validateIDs(request.AttackPayloads, "catalog threat ID"); err != nil {
			return result, err
		}
	}
	_, err := h.PostJSON(ctx, ExecutionsV2URI+"/run/condition", request, &result)
	if err != nil {
		return result, fmt.Errorf("run conditional catalog threats: %w", err)
	}
	return result, nil
}

// RunCatalogCampaign executes the subscribed campaign identified by id. Any
// Campaigns in request are ignored; the path selects the campaign.
//
// Required permission: emergingthreat.execute.
// Required feature: emerging_threats. Requires execution_enabled=true.
func RunCatalogCampaign(ctx context.Context, h *api.HTTPAPI, id string, request model.RunCampaignRequest) (model.CampaignRun, error) {
	var result model.CampaignRun
	if err := validatePathSegment(id, "catalog campaign ID"); err != nil {
		return result, err
	}
	if err := validateRunAssets(request.Assets, request.EmailAssets); err != nil {
		return result, err
	}
	request.Campaigns = nil
	_, err := h.PostJSON(ctx, ExecutionsV2URI+"/campaign/"+id+"/run", request, &result)
	if err != nil {
		return result, fmt.Errorf("run catalog campaign: %w", err)
	}
	return result, nil
}

// RunCatalogCampaigns executes subscribed catalog campaigns. For user-authored
// campaigns use RunCampaigns instead. Returns one run summary per campaign.
//
// Required permission: emergingthreat.execute.
// Required feature: emerging_threats. Requires execution_enabled=true.
func RunCatalogCampaigns(ctx context.Context, h *api.HTTPAPI, request model.RunCampaignRequest) ([]model.CampaignRun, error) {
	if err := validateIDs(request.Campaigns, "catalog campaign ID"); err != nil {
		return nil, err
	}
	if err := validateRunAssets(request.Assets, request.EmailAssets); err != nil {
		return nil, err
	}
	var result []model.CampaignRun
	_, err := h.PostJSON(ctx, ExecutionsV2URI+"/campaign/run", request, &result)
	if err != nil {
		return nil, fmt.Errorf("run catalog campaigns: %w", err)
	}
	return result, nil
}

// AbortRun stops a per-threat run by run ID.
//
// Required permission: emergingthreat.execute.
// Required feature: emerging_threats. Does not require execution_enabled=true.
func AbortRun(ctx context.Context, h *api.HTTPAPI, runID string) (models.SuccessIDResponse, error) {
	var result models.SuccessIDResponse
	if err := validatePathSegment(runID, "run ID"); err != nil {
		return result, err
	}
	_, err := h.PostJSON(ctx, ExecutionsV2URI+"/runs/"+runID+"/abort", nil, &result)
	if err != nil {
		return result, fmt.Errorf("abort emerging-threat run: %w", err)
	}
	return result, nil
}

// AbortCampaignRun stops a campaign run by run ID.
//
// Required permission: emergingthreat.execute.
// Required feature: emerging_threats. Does not require execution_enabled=true.
func AbortCampaignRun(ctx context.Context, h *api.HTTPAPI, runID string) (models.SuccessIDResponse, error) {
	var result models.SuccessIDResponse
	if err := validatePathSegment(runID, "campaign run ID"); err != nil {
		return result, err
	}
	_, err := h.PostJSON(ctx, CampaignReportsV2URI+"/"+runID+"/abort", nil, &result)
	if err != nil {
		return result, fmt.Errorf("abort emerging-threat campaign run: %w", err)
	}
	return result, nil
}
