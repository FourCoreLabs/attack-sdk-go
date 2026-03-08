package actions

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	modelActions "github.com/fourcorelabs/attack-sdk-go/pkg/models/actions"
)

// EndpointChainsV2URI is the base endpoint for the endpoint chains API
const EndpointActionsV2URI = "/api/v2/actions"

// ListEndpointActionsV2URI is the base endpoint for listing endpoint actions
const ListEndpointActionsV2URI = "/api/v2/content/actions"

// ExecuteEndpointChain executes an endpoint attack chain by chain ID on specified assets
func ExecuteEndpointAction(ctx context.Context, h *api.HTTPAPI, attackRun models.AttackRunActionsStagers) (models.GetExecutionResponse, error) {
	var response models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/run", EndpointActionsV2URI)
	_, err := h.PostJSON(ctx, endpoint, attackRun, &response)
	if err != nil {
		return models.GetExecutionResponse{}, fmt.Errorf("failed to execute endpoint chain: %w", err)
	}

	return response, nil
}

type ListEndpointActionOpts struct {
	Size             int               `json:"size"`
	Offset           int               `json:"offset"`
	StartReleaseDate time.Time         `json:"start_release_date,omitempty"`
	EndReleaseDate   time.Time         `json:"end_release_date,omitempty"`
	ID               string            `json:"id,omitempty"`
	Name             string            `json:"name,omitempty"`
	Severity         models.Severity   `json:"severity,omitempty"`
	Platforms        []models.Platform `json:"platforms,omitempty"`
	Type             string            `json:"type,omitempty"`
}

func ListEndpointActions(ctx context.Context, h *api.HTTPAPI, opts ListEndpointActionOpts) (models.PaginationResponse[modelActions.ActionForUserState], error) {
	var resp models.PaginationResponse[modelActions.ActionForUserState]

	params := url.Values{
		"size":   []string{strconv.FormatInt(int64(opts.Size), 10)},
		"offset": []string{strconv.FormatInt(int64(opts.Offset), 10)},
	}

	if !opts.StartReleaseDate.IsZero() {
		params.Add("filter[start_release_date]", opts.StartReleaseDate.Format(time.RFC3339))
	}

	if !opts.EndReleaseDate.IsZero() {
		params.Add("filter[end_release_date]", opts.EndReleaseDate.Format(time.RFC3339))
	}

	if opts.ID != "" {
		params.Add("filter[id]", opts.ID)
	}

	if opts.Name != "" {
		params.Add("filter[name]", opts.Name)
	}

	if opts.Severity != "" {
		params.Add("filter[severity]", string(opts.Severity))
	}

	if len(opts.Platforms) > 0 {
		platforms := make([]string, 0, len(opts.Platforms))
		for _, platform := range opts.Platforms {
			platforms = append(platforms, string(platform))
		}
		params["filter[platform]"] = platforms
	}

	if opts.Type != "" {
		params.Add("filter[type]", opts.Type)
	}

	_, err := h.GetJSON(ctx, ListEndpointActionsV2URI, &resp, api.ReqOptions{Params: params})

	return resp, err
}
