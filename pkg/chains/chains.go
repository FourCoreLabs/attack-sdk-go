package chains

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/chains"
)

// ExecuteEndpointChainsV2URI is the base endpoint for the endpoint chains API
const ExecuteEndpointChainsV2URI = "/api/v2/chains"

// ListEndpointChainsV2URI is the base endpoint for the endpoint chains API
const ListEndpointChainsV2URI = "/api/v2/content/chains"

// ExecuteEndpointChain executes an endpoint attack chain by chain ID on specified assets
func ExecuteEndpointChain(ctx context.Context, h *api.HTTPAPI, chainID string, attackRun models.AttackRun) (models.GetExecutionResponse, error) {
	var response models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/%s/run", ExecuteEndpointChainsV2URI, chainID)
	_, err := h.PostJSON(ctx, endpoint, attackRun, &response)
	if err != nil {
		return models.GetExecutionResponse{}, fmt.Errorf("failed to execute endpoint chain: %w", err)
	}

	return response, nil
}

type ListEndpointChainOrderBy string

const (
	ListEndpointChainOrderbyReleaseDate ListEndpointChainOrderBy = "release_date"
	ListEndpointChainOrderbyName        ListEndpointChainOrderBy = "name"
	ListEndpointChainOrderbyID          ListEndpointChainOrderBy = "id"
	ListEndpointChainOrderbyLastRunAt   ListEndpointChainOrderBy = "last_run_at"
)

var ValidListEndpointChainOrder = []ListEndpointChainOrderBy{
	ListEndpointChainOrderbyReleaseDate,
	ListEndpointChainOrderbyName,
	ListEndpointChainOrderbyID,
	ListEndpointChainOrderbyLastRunAt,
}

type ListEndpointChainOpts struct {
	Size             int       `json:"size"`
	Offset           int       `json:"offset"`
	Order            []string  `json:"order"`
	StartReleaseDate time.Time `json:"start_release_date,omitempty"`
	EndReleaseDate   time.Time `json:"end_release_date,omitempty"`
	StartLastRunAt   time.Time `json:"start_last_run_at,omitempty"`
	EndLastRunAt     time.Time `json:"end_last_run_at,omitempty"`
	ID               string    `json:"id,omitempty"`
	Name             string    `json:"name,omitempty"`
	Platform         []string  `json:"platform,omitempty"`
	Elevated         *bool     `json:"elevated,omitempty"`
	ShowDeprecated   *bool     `json:"show_deprecated,omitempty"`
}

func ListEndpointChains(ctx context.Context, h *api.HTTPAPI, opts ListEndpointChainOpts) (models.PaginationResponse[chains.ChainForUserState], error) {
	var resp models.PaginationResponse[chains.ChainForUserState]

	// Prepare parameters map
	params := url.Values{
		"size":   []string{strconv.FormatInt(int64(opts.Size), 10)},
		"offset": []string{strconv.FormatInt(int64(opts.Offset), 10)},
		"order":  opts.Order,
	}

	if !opts.StartReleaseDate.IsZero() {
		params.Add("filter[start_release_date]", opts.StartReleaseDate.Format(time.RFC3339))
	}

	if !opts.EndReleaseDate.IsZero() {
		params.Add("filter[end_release_date]", opts.EndReleaseDate.Format(time.RFC3339))
	}

	if !opts.StartLastRunAt.IsZero() {
		params.Add("filter[start_last_run_at]", opts.StartLastRunAt.Format(time.RFC3339))
	}

	if !opts.EndReleaseDate.IsZero() {
		params.Add("filter[end_last_run_at]", opts.EndLastRunAt.Format(time.RFC3339))
	}

	if opts.ID != "" {
		params.Add("filter[id]", opts.ID)
	}

	if opts.Name != "" {
		params.Add("filter[name]", opts.Name)
	}

	if len(opts.Platform) > 0 {
		params["filter[platform]"] = opts.Platform
	}

	if opts.Elevated != nil {
		v := "false"
		if *opts.Elevated {
			v = "true"
		}
		params.Add("filter[elevated]", v)
	}

	if opts.ShowDeprecated != nil {
		v := "false"
		if *opts.ShowDeprecated {
			v = "true"
		}
		params.Add("filter[show_deprecated]", v)
	}

	// Make the API request
	_, err := h.GetJSON(ctx, ListEndpointChainsV2URI, &resp, api.ReqOptions{
		Params: params,
	})

	return resp, err
}
